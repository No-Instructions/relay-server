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
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    watch, Mutex as AsyncMutex,
};
use y_sweet_core::{
    doc_sync::DocWithSyncKv, metrics::RelayMetrics, sync::awareness::Awareness, sync_kv::SyncKv,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    Socket,
    Http,
    Subdoc,
}

impl AttachKind {
    fn as_str(&self) -> &'static str {
        match self {
            AttachKind::Socket => "socket",
            AttachKind::Http => "http",
            AttachKind::Subdoc => "subdoc",
        }
    }
}

/// The actor-side view of a doc's lifecycle. `Loading` is a registry-slot
/// phase, so the observable states start at the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Active { connections: usize },
    Idle,
}

/// Mailbox messages for a doc's lifecycle actor. In the shadow-accounting
/// phase the actor only maintains explicit connection counts; eviction
/// authority moves here in a later migration step.
pub enum DocMsg {
    Attach {
        kind: AttachKind,
    },
    Detach {
        kind: AttachKind,
    },
    #[allow(dead_code)] // authoritative from the persistence step onward
    Dirty,
}

/// Handle to a doc's lifecycle actor. Cloned into the registry slot and
/// every guard; the actor exits when the last sender is gone.
#[derive(Clone)]
pub struct DocHandle {
    tx: UnboundedSender<DocMsg>,
    state: watch::Receiver<LifecycleState>,
}

impl DocHandle {
    /// Attach to the doc: counts the attachment and returns the RAII
    /// guard carrying the data-plane handles. The guard holds a strong
    /// awareness clone so the (still-authoritative) strong-count liveness
    /// probes see guards exactly as they saw raw awareness refs.
    pub fn attach(&self, kind: AttachKind, doc: &Arc<DocWithSyncKv>) -> AttachGuard {
        // Unbounded send: never blocks; failure means the actor is gone,
        // in which case there is no count left to maintain.
        let _ = self.tx.send(DocMsg::Attach { kind });
        AttachGuard {
            kind,
            awareness: doc.awareness(),
            doc: Arc::clone(doc),
            tx: self.tx.clone(),
        }
    }

    /// Explicit connection count as the actor sees it. Shadow-accounting
    /// accessor: exists so the GC worker can compare counts against the
    /// strong-count probe; deleted when eviction flips to the counts.
    pub fn connections(&self) -> usize {
        match *self.state.borrow() {
            LifecycleState::Active { connections } => connections,
            LifecycleState::Idle => 0,
        }
    }

    pub fn state(&self) -> watch::Receiver<LifecycleState> {
        self.state.clone()
    }
}

/// RAII attachment to a live doc. Dropping it detaches: the send is
/// unbounded and infallible from sync contexts, so accounting cannot be
/// lost by a caller forgetting a teardown path.
pub struct AttachGuard {
    kind: AttachKind,
    doc: Arc<DocWithSyncKv>,
    /// Strong awareness clone, held for the shadow-accounting phase: the
    /// strong-count probes must see one ref per attachment, exactly as
    /// they saw the raw clones this guard replaces.
    awareness: Arc<RwLock<Awareness>>,
    tx: UnboundedSender<DocMsg>,
}

impl AttachGuard {
    pub fn awareness(&self) -> Arc<RwLock<Awareness>> {
        Arc::clone(&self.awareness)
    }

    pub fn sync_kv(&self) -> Arc<SyncKv> {
        self.doc.sync_kv()
    }

    pub fn doc(&self) -> &Arc<DocWithSyncKv> {
        &self.doc
    }
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(DocMsg::Detach { kind: self.kind });
    }
}

/// A resident doc: the instance plus its lifecycle actor's handle.
#[derive(Clone)]
pub(crate) struct Resident {
    pub doc: Arc<DocWithSyncKv>,
    pub handle: DocHandle,
}

/// The per-doc lifecycle actor. In this phase it is a pure connection
/// ledger: it processes Attach/Detach in mailbox order, publishes the
/// resulting state on a watch channel, and emits transition metrics.
struct DocActor {
    doc_id: String,
    mailbox: UnboundedReceiver<DocMsg>,
    state_tx: watch::Sender<LifecycleState>,
    sockets: usize,
    https: usize,
    subdocs: usize,
    metrics: Arc<RelayMetrics>,
}

impl DocActor {
    fn spawn(doc_id: String, metrics: Arc<RelayMetrics>) -> DocHandle {
        let (tx, mailbox) = unbounded_channel();
        let (state_tx, state_rx) = watch::channel(LifecycleState::Idle);
        metrics.record_lifecycle_transition("loading", "idle");
        let actor = DocActor {
            doc_id,
            mailbox,
            state_tx,
            sockets: 0,
            https: 0,
            subdocs: 0,
            metrics,
        };
        tokio::spawn(actor.run());
        DocHandle {
            tx,
            state: state_rx,
        }
    }

    fn connections(&self) -> usize {
        self.sockets + self.https + self.subdocs
    }

    async fn run(mut self) {
        // The slot holds one sender and each guard holds one; the actor
        // ends when the doc is evicted and the last guard is gone.
        while let Some(msg) = self.mailbox.recv().await {
            match msg {
                DocMsg::Attach { kind } => {
                    let was = self.connections();
                    match kind {
                        AttachKind::Socket => self.sockets += 1,
                        AttachKind::Http => self.https += 1,
                        AttachKind::Subdoc => self.subdocs += 1,
                    }
                    if was == 0 {
                        self.metrics.record_lifecycle_transition("idle", "active");
                    }
                    self.publish();
                    tracing::debug!(
                        doc_id = %self.doc_id,
                        kind = kind.as_str(),
                        connections = self.connections(),
                        "attach"
                    );
                }
                DocMsg::Detach { kind } => {
                    let counter = match kind {
                        AttachKind::Socket => &mut self.sockets,
                        AttachKind::Http => &mut self.https,
                        AttachKind::Subdoc => &mut self.subdocs,
                    };
                    debug_assert!(*counter > 0, "detach without matching attach");
                    *counter = counter.saturating_sub(1);
                    if self.connections() == 0 {
                        self.metrics.record_lifecycle_transition("active", "idle");
                    }
                    self.publish();
                    tracing::debug!(
                        doc_id = %self.doc_id,
                        kind = kind.as_str(),
                        connections = self.connections(),
                        "detach"
                    );
                }
                DocMsg::Dirty => {}
            }
        }
    }

    fn publish(&self) {
        let state = match self.connections() {
            0 => LifecycleState::Idle,
            n => LifecycleState::Active { connections: n },
        };
        let _ = self.state_tx.send(state);
    }
}

/// A bare actor handle for harnesses that drive the socket path without
/// a registry (see `server.rs`'s in-memory socket tests).
#[cfg(test)]
pub(crate) fn test_actor_handle(doc_id: &str, metrics: Arc<RelayMetrics>) -> DocHandle {
    DocActor::spawn(doc_id.to_string(), metrics)
}

/// The shadow-accounting comparison: does the explicit connection count
/// agree with the awareness strong-count probe? A single-instant mismatch
/// can be an attach/detach caught mid-flight (the guard's awareness clone
/// and its mailbox message are not atomic), so callers only record a
/// mismatch after it persists across two consecutive checks.
/// Returns whether this check disagreed.
pub(crate) fn shadow_accounting_disagrees(resident: &Resident) -> bool {
    let probe = Arc::downgrade(&resident.doc.awareness());
    let strong_alive = probe.strong_count() > 1;
    let counted_alive = resident.handle.connections() > 0;
    strong_alive != counted_alive
}

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
    doc: Option<Resident>,
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

pub struct DocRegistry {
    slots: DashMap<String, Arc<Slot>>,
    metrics: Arc<RelayMetrics>,
}

impl DocRegistry {
    pub fn new(metrics: Arc<RelayMetrics>) -> Self {
        Self {
            slots: DashMap::new(),
            metrics,
        }
    }

    /// Lock-free view of a resident doc. During an eviction the doc is
    /// already withdrawn from the slot, so a peek misses and the caller
    /// serializes through `get_or_load`.
    pub fn peek(&self, doc_id: &str) -> Option<Arc<DocWithSyncKv>> {
        self.peek_resident(doc_id).map(|r| r.doc)
    }

    pub(crate) fn peek_resident(&self, doc_id: &str) -> Option<Resident> {
        let slot = self.slots.get(doc_id)?;
        let state = slot.state.read().unwrap();
        state.doc.clone()
    }

    /// Load (if needed) and attach in one step: the returned guard is the
    /// unit of explicit connection accounting.
    pub async fn attach<F, Fut>(
        &self,
        doc_id: &str,
        kind: AttachKind,
        loader: F,
    ) -> anyhow::Result<AttachGuard>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        let resident = self.get_or_load_resident(doc_id, loader).await?;
        Ok(resident.handle.attach(kind, &resident.doc))
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
            .map(|resident| resident.doc)
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
        Ok(self.get_or_load_resident(doc_id, loader).await?.doc)
    }

    async fn get_or_load_resident<F, Fut>(
        &self,
        doc_id: &str,
        loader: F,
    ) -> anyhow::Result<Resident>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        loop {
            // Fast path: no slot mutex. An evicting doc is already
            // withdrawn from the slot state, so this cannot observe one.
            if let Some(slot) = self.slots.get(doc_id) {
                let resident = slot.state.read().unwrap().doc.clone();
                if let Some(resident) = resident {
                    return Ok(resident);
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
                if let Some(resident) = state.doc.clone() {
                    return Ok(resident);
                }
            }

            match loader().await {
                Ok(doc) => {
                    let resident = Resident {
                        doc: Arc::new(doc),
                        handle: DocActor::spawn(doc_id.to_string(), self.metrics.clone()),
                    };
                    slot.state.write().unwrap().doc = Some(resident.clone());
                    return Ok(resident);
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

        let resident = {
            let mut state = slot.state.write().unwrap();
            if state.defunct {
                return EvictOutcome::Absent;
            }
            match state.doc.take() {
                Some(resident) => resident,
                None => return EvictOutcome::Absent,
            }
        };

        match evictor(Arc::clone(&resident.doc)).await {
            EvictDecision::Refuse => {
                slot.state.write().unwrap().doc = Some(resident);
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

    fn test_metrics() -> Arc<RelayMetrics> {
        RelayMetrics::new_with_registry(&prometheus::Registry::new()).unwrap()
    }

    /// Let the actor drain its mailbox (single-threaded test runtime).
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

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
        let registry = Arc::new(DocRegistry::new(test_metrics()));
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
        let registry = Arc::new(DocRegistry::new(test_metrics()));

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
        let registry = DocRegistry::new(test_metrics());

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
        let registry = DocRegistry::new(test_metrics());

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
        let registry = Arc::new(DocRegistry::new(test_metrics()));

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
        let registry = DocRegistry::new(test_metrics());

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

    #[tokio::test(start_paused = true)]
    async fn attach_guard_drop_sends_detach_and_count_reaches_zero() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let socket_guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        let http_guard = registry
            .attach("doc", AttachKind::Http, loader)
            .await
            .unwrap();
        settle().await;

        let resident = registry.peek_resident("doc").unwrap();
        assert_eq!(resident.handle.connections(), 2);
        assert_eq!(
            *resident.handle.state().borrow(),
            LifecycleState::Active { connections: 2 }
        );

        drop(socket_guard);
        settle().await;
        assert_eq!(resident.handle.connections(), 1);

        drop(http_guard);
        settle().await;
        assert_eq!(resident.handle.connections(), 0);
        assert_eq!(*resident.handle.state().borrow(), LifecycleState::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn attach_kinds_tracked_independently() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let subdoc_guard = registry
            .attach("doc", AttachKind::Subdoc, loader)
            .await
            .unwrap();

        // Socket attachments come and go; the subdoc pin must keep the
        // doc Active throughout.
        for _ in 0..3 {
            let socket_guard = registry
                .attach("doc", AttachKind::Socket, loader)
                .await
                .unwrap();
            drop(socket_guard);
            settle().await;
            let resident = registry.peek_resident("doc").unwrap();
            assert_eq!(
                *resident.handle.state().borrow(),
                LifecycleState::Active { connections: 1 },
                "the subdoc pin alone must keep the doc active"
            );
        }

        drop(subdoc_guard);
        settle().await;
        let resident = registry.peek_resident("doc").unwrap();
        assert_eq!(*resident.handle.state().borrow(), LifecycleState::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn transition_metrics_emitted() {
        let metrics = test_metrics();
        let store = MemoryStore::new();
        let registry = DocRegistry::new(metrics.clone());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let transitions = |from: &str, to: &str| {
            metrics
                .doc_lifecycle_transitions_total
                .with_label_values(&[from, to])
                .get()
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        settle().await;
        assert_eq!(transitions("loading", "idle"), 1.0, "actor birth");
        assert_eq!(transitions("idle", "active"), 1.0, "first attach");

        drop(guard);
        settle().await;
        assert_eq!(transitions("active", "idle"), 1.0, "last detach");
    }

    /// The step-3 shippability contract: a guard holds exactly one strong
    /// awareness clone, so the strong-count probes (still authoritative
    /// for eviction) see attachments exactly as before the swap.
    #[tokio::test(start_paused = true)]
    async fn guard_holds_awareness_so_strong_count_agrees() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let doc = registry.get_or_load("doc", loader).await.unwrap();
        let probe = Arc::downgrade(&doc.awareness());
        assert_eq!(probe.strong_count(), 1, "baseline: only the doc's own ref");

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        assert_eq!(probe.strong_count(), 2, "a guard is one awareness ref");

        drop(guard);
        assert_eq!(probe.strong_count(), 1, "detach releases the ref");
    }

    /// A scripted attach/detach sequence during which the shadow
    /// comparison (explicit counts vs strong-count probe) must never
    /// disagree once the actor has drained its mailbox. This is the
    /// in-vitro version of the soak the GC worker runs in production.
    #[tokio::test(start_paused = true)]
    async fn shadow_mismatch_metric_zero_across_scripted_sequence() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let check = |step: &str| {
            let resident = registry.peek_resident("doc").unwrap();
            assert!(
                !shadow_accounting_disagrees(&resident),
                "shadow accounting disagreed after: {step}"
            );
        };

        registry.get_or_load("doc", loader).await.unwrap();
        settle().await;
        check("load without attach");

        let socket = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        settle().await;
        check("socket attach");

        let subdoc = registry
            .attach("doc", AttachKind::Subdoc, loader)
            .await
            .unwrap();
        let http = registry
            .attach("doc", AttachKind::Http, loader)
            .await
            .unwrap();
        settle().await;
        check("three concurrent kinds");

        drop(http);
        drop(socket);
        settle().await;
        check("partial detach");

        drop(subdoc);
        settle().await;
        check("fully idle");
    }
}
