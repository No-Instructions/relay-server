//! Document lifecycle ownership.
//!
//! This module owns document identity for the process: `DocRegistry` is
//! the only way a document enters or leaves memory. Each doc id maps to a
//! slot whose async mutex serializes loading and eviction, so a caller
//! either observes a resident doc or waits until the transition that
//! affects it (a racing load, or an eviction's final store flush) has
//! completed.
//!
//! Slot rules (the single-instance invariant):
//! - A doc is installed or removed only while holding the slot mutex, and
//!   only on a slot that is not `defunct`.
//! - A waiter that acquires the mutex and finds `defunct` retries from the
//!   map: the slot was removed while it waited.
//! - Slots are removed at eviction and on failed loads — nothing else
//!   removes them, so the registry holds no per-doc-id residue.

use dashmap::DashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex as AsyncMutex;
use y_sweet_core::doc_sync::DocWithSyncKv;

/// What an evictor decided after inspecting the doc under the slot lock.
pub enum EvictDecision {
    /// Remove the doc from the registry. The evictor has already made the
    /// doc durable (or decided durability is not required).
    Evict,
    /// Keep the doc resident (something attached while eviction was
    /// pending — the "un-evict").
    Refuse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvictOutcome {
    Evicted,
    Refused,
    /// No resident doc under this id (never loaded, already evicted, or
    /// an eviction/failed load raced us).
    Absent,
}

struct SlotState {
    doc: Option<Arc<DocWithSyncKv>>,
    /// Set exactly once, under the slot mutex, when the slot is removed
    /// from the map. Tells mutex waiters their slot is dead.
    defunct: bool,
}

struct Slot {
    mu: AsyncMutex<()>,
    state: RwLock<SlotState>,
}

impl Slot {
    fn new() -> Self {
        Self {
            mu: AsyncMutex::new(()),
            state: RwLock::new(SlotState {
                doc: None,
                defunct: false,
            }),
        }
    }
}

#[derive(Default)]
pub struct DocRegistry {
    slots: DashMap<String, Arc<Slot>>,
}

impl DocRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock-free view of a resident doc. During an eviction the doc is
    /// already withdrawn from the slot, so a peek misses and the caller
    /// serializes through `get_or_load`.
    pub fn peek(&self, doc_id: &str) -> Option<Arc<DocWithSyncKv>> {
        let slot = self.slots.get(doc_id)?;
        let state = slot.state.read().unwrap();
        state.doc.clone()
    }

    pub fn is_resident(&self, doc_id: &str) -> bool {
        self.peek(doc_id).is_some()
    }

    /// Snapshot of every resident doc, for shutdown flush passes. Docs
    /// mid-load or mid-eviction are absent from slot state and therefore
    /// skipped: a loading doc is clean, and an evicting doc's final flush
    /// is already someone else's responsibility.
    pub fn resident_docs(&self) -> Vec<Arc<DocWithSyncKv>> {
        self.slots
            .iter()
            .filter_map(|entry| entry.value().state.read().unwrap().doc.clone())
            .collect()
    }

    /// Number of slots (resident docs plus in-flight loads).
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Return the resident doc for `doc_id`, or run `loader` to create it.
    /// Concurrent callers single-flight: exactly one runs the loader, the
    /// rest wait on the slot mutex and observe the result. A failed load
    /// removes the slot and returns the error to the caller that ran the
    /// loader; waiters retry with their own load rather than inheriting an
    /// error they can't distinguish from their own.
    pub async fn get_or_load<F, Fut>(
        &self,
        doc_id: &str,
        loader: F,
    ) -> anyhow::Result<Arc<DocWithSyncKv>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        loop {
            // Fast path: no slot mutex. An evicting doc is already
            // withdrawn from the slot state, so this cannot observe one.
            if let Some(slot) = self.slots.get(doc_id) {
                let doc = slot.state.read().unwrap().doc.clone();
                if let Some(doc) = doc {
                    return Ok(doc);
                }
            }

            // Take (or create) the slot, dropping the shard guard before
            // awaiting the slot mutex.
            let slot = {
                let entry = self
                    .slots
                    .entry(doc_id.to_string())
                    .or_insert_with(|| Arc::new(Slot::new()));
                Arc::clone(entry.value())
            };
            let _guard = slot.mu.lock().await;

            {
                let state = slot.state.read().unwrap();
                if state.defunct {
                    // The slot was evicted or its load failed while we
                    // waited; start over from the map.
                    continue;
                }
                if let Some(doc) = state.doc.clone() {
                    return Ok(doc);
                }
            }

            match loader().await {
                Ok(doc) => {
                    let doc = Arc::new(doc);
                    slot.state.write().unwrap().doc = Some(Arc::clone(&doc));
                    return Ok(doc);
                }
                Err(err) => {
                    slot.state.write().unwrap().defunct = true;
                    self.slots.remove_if(doc_id, |_, s| Arc::ptr_eq(s, &slot));
                    return Err(err);
                }
            }
        }
    }

    /// Run `evictor` on the resident doc under the slot lock. The doc is
    /// withdrawn from the slot before the evictor runs, so no new caller
    /// can observe it while the final flush is in flight; loads for the
    /// same id queue on the slot mutex until the eviction completes (and
    /// then read the store, which already holds the final flush) or until
    /// a `Refuse` reinstalls the doc.
    pub async fn evict<F, Fut>(&self, doc_id: &str, evictor: F) -> EvictOutcome
    where
        F: FnOnce(Arc<DocWithSyncKv>) -> Fut,
        Fut: Future<Output = EvictDecision>,
    {
        let Some(slot) = self.slots.get(doc_id).map(|s| Arc::clone(s.value())) else {
            return EvictOutcome::Absent;
        };
        let _guard = slot.mu.lock().await;

        let doc = {
            let mut state = slot.state.write().unwrap();
            if state.defunct {
                return EvictOutcome::Absent;
            }
            match state.doc.take() {
                Some(doc) => doc,
                None => return EvictOutcome::Absent,
            }
        };

        match evictor(Arc::clone(&doc)).await {
            EvictDecision::Refuse => {
                slot.state.write().unwrap().doc = Some(doc);
                EvictOutcome::Refused
            }
            EvictDecision::Evict => {
                slot.state.write().unwrap().defunct = true;
                self.slots.remove_if(doc_id, |_, s| Arc::ptr_eq(s, &slot));
                EvictOutcome::Evicted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{content_update, read_content, FailStore, GatedStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use y_sweet_core::store::{memory::MemoryStore, Store};

    async fn load_doc<S: Store + Clone + 'static>(
        store: &S,
        doc_id: &str,
    ) -> anyhow::Result<DocWithSyncKv> {
        DocWithSyncKv::new(
            doc_id,
            Some(Arc::new(Box::new(store.clone()) as Box<dyn Store>)),
            || (),
            None,
        )
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn single_flight_concurrent_loads_share_one_load() {
        let store = GatedStore::new();
        let registry = Arc::new(DocRegistry::new());
        let loads = Arc::new(AtomicUsize::new(0));

        let docs = futures::future::join_all((0..8).map(|_| {
            let registry = registry.clone();
            let store = store.clone();
            let loads = loads.clone();
            async move {
                registry
                    .get_or_load("doc", || {
                        let store = store.clone();
                        let loads = loads.clone();
                        async move {
                            loads.fetch_add(1, Ordering::SeqCst);
                            load_doc(&store, "doc").await
                        }
                    })
                    .await
                    .unwrap()
            }
        }))
        .await;

        assert_eq!(loads.load(Ordering::SeqCst), 1, "loader must run once");
        assert_eq!(
            store.get_count("doc/data.ysweet"),
            1,
            "store must be read once"
        );
        for doc in &docs[1..] {
            assert!(
                Arc::ptr_eq(&docs[0], doc),
                "all callers must share one instance"
            );
        }
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_load_propagates_to_all_waiters_and_clears_slot() {
        // Enough injected failures that every concurrent caller's own
        // load attempt fails (waiters retry with their own load).
        let store = FailStore::new(8);
        let registry = Arc::new(DocRegistry::new());

        let results = futures::future::join_all((0..8).map(|_| {
            let registry = registry.clone();
            let store = store.clone();
            async move {
                registry
                    .get_or_load("doc", || {
                        let store = store.clone();
                        async move { load_doc(&store, "doc").await }
                    })
                    .await
            }
        }))
        .await;

        for result in &results {
            assert!(result.is_err(), "every caller must see its load fail");
        }
        assert_eq!(registry.len(), 0, "failed loads must not leave slots");

        // The failure budget is exhausted; a retry must succeed rather
        // than finding a wedged slot.
        registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .expect("retry after failed load must succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn evict_removes_slot_and_next_load_is_fresh() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new();

        let doc = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        doc.apply_update(&content_update("k", "v")).unwrap();

        let outcome = registry
            .evict("doc", |doc| async move {
                doc.sync_kv().persist().await.unwrap();
                EvictDecision::Evict
            })
            .await;
        assert_eq!(outcome, EvictOutcome::Evicted);
        assert_eq!(registry.len(), 0);
        assert!(!registry.is_resident("doc"));

        let reloaded = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        assert!(
            !Arc::ptr_eq(&doc, &reloaded),
            "a reload after eviction is a fresh instance"
        );
        assert_eq!(
            read_content(&reloaded, "k").as_deref(),
            Some("v"),
            "the fresh instance must carry the final-flushed state"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refused_evict_keeps_doc_resident() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new();

        let doc = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();

        let outcome = registry
            .evict("doc", |_doc| async move { EvictDecision::Refuse })
            .await;
        assert_eq!(outcome, EvictOutcome::Refused);
        assert_eq!(registry.len(), 1);

        let again = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        assert!(
            Arc::ptr_eq(&doc, &again),
            "a refused eviction must keep the same instance"
        );
    }

    /// Race 2 (reload racing the final flush) at registry level: a load
    /// racing an eviction must block until the eviction's final persist is
    /// on the store, and must then observe the flushed bytes.
    #[tokio::test(start_paused = true)]
    async fn evict_holds_slot_against_concurrent_load_until_final_persist() {
        let store = GatedStore::new();
        let registry = Arc::new(DocRegistry::new());

        let doc = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        doc.apply_update(&content_update("k", "v")).unwrap();
        drop(doc);

        store.close_gate();

        let evict_handle = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .evict("doc", |doc| async move {
                        doc.sync_kv().persist().await.unwrap();
                        EvictDecision::Evict
                    })
                    .await
            }
        });
        // Let the eviction reach the gated PUT.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        let load_handle = tokio::spawn({
            let registry = registry.clone();
            let store = store.clone();
            async move {
                registry
                    .get_or_load("doc", move || {
                        let store = store.clone();
                        async move { load_doc(&store, "doc").await }
                    })
                    .await
            }
        });
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(
            !evict_handle.is_finished(),
            "eviction must be parked on the gated final persist"
        );
        assert!(
            !load_handle.is_finished(),
            "a racing load must wait for the final persist, not read a stale snapshot"
        );

        store.release(1);
        assert_eq!(evict_handle.await.unwrap(), EvictOutcome::Evicted);
        let reloaded = load_handle.await.unwrap().unwrap();
        assert_eq!(
            read_content(&reloaded, "k").as_deref(),
            Some("v"),
            "the racing load must observe the final flush"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slot_count_returns_to_zero_after_load_evict_cycles() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new();

        for round in 0..10 {
            registry
                .get_or_load("doc", || {
                    let store = store.clone();
                    async move { load_doc(&store, "doc").await }
                })
                .await
                .unwrap();
            assert_eq!(registry.len(), 1);
            let outcome = registry
                .evict("doc", |_doc| async move { EvictDecision::Evict })
                .await;
            assert_eq!(outcome, EvictOutcome::Evicted);
            assert_eq!(
                registry.len(),
                0,
                "round {round}: eviction must fully reclaim the slot"
            );
        }
    }
}
