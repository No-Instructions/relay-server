//! Shared test fixtures for lifecycle tests: deterministic store wrappers
//! and a server builder. Fixtures only — tests stay inline in the files
//! they cover.

use crate::server::Server;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use y_sweet_core::doc_sync::DocWithSyncKv;
use y_sweet_core::store::{memory::MemoryStore, Result as StoreResult, Store};
use yrs::{Map, Out, ReadTxn, Transact};

/// A `MemoryStore` wrapper that counts reads/writes per key and can hold
/// every `set` on a gate, so tests can freeze a persist mid-flight and
/// order other work around it deterministically (no sleeps).
#[derive(Clone)]
pub(crate) struct GatedStore {
    inner: MemoryStore,
    gated: Arc<AtomicBool>,
    gate: Arc<Semaphore>,
    gets: Arc<DashMap<String, usize>>,
    puts: Arc<DashMap<String, usize>>,
}

impl GatedStore {
    pub fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            gated: Arc::new(AtomicBool::new(false)),
            gate: Arc::new(Semaphore::new(0)),
            gets: Arc::new(DashMap::new()),
            puts: Arc::new(DashMap::new()),
        }
    }

    /// Hold every subsequent `set` until `release` or `open`.
    pub fn close_gate(&self) {
        self.gated.store(true, Ordering::SeqCst);
    }

    /// Let `n` held/future `set`s through.
    pub fn release(&self, n: usize) {
        self.gate.add_permits(n);
    }

    /// Stop gating entirely and unblock everything held.
    pub fn open_gate(&self) {
        self.gated.store(false, Ordering::SeqCst);
        self.gate
            .add_permits(Semaphore::MAX_PERMITS - self.gate.available_permits());
    }

    pub fn get_count(&self, key: &str) -> usize {
        self.gets.get(key).map(|v| *v).unwrap_or(0)
    }

    pub fn put_count(&self, key: &str) -> usize {
        self.puts.get(key).map(|v| *v).unwrap_or(0)
    }

    /// Bytes currently stored for `key` (bypasses the gate).
    pub fn stored(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.get_bytes(key)
    }
}

#[async_trait]
impl Store for GatedStore {
    async fn init(&self) -> StoreResult<()> {
        self.inner.init().await
    }

    async fn get(&self, key: &str) -> StoreResult<Option<Vec<u8>>> {
        *self.gets.entry(key.to_owned()).or_insert(0) += 1;
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> StoreResult<()> {
        if self.gated.load(Ordering::SeqCst) {
            // Waiters queue here until the test releases the gate. The
            // permit is intentionally consumed: one release() == one PUT.
            let permit = self.gate.acquire().await.expect("gate semaphore closed");
            permit.forget();
        }
        *self.puts.entry(key.to_owned()).or_insert(0) += 1;
        self.inner.set(key, value).await
    }

    async fn remove(&self, key: &str) -> StoreResult<()> {
        self.inner.remove(key).await
    }

    async fn exists(&self, key: &str) -> StoreResult<bool> {
        self.inner.exists(key).await
    }
}

/// A `MemoryStore` wrapper that fails the next `n` reads, for exercising
/// load-failure paths.
#[derive(Clone)]
pub(crate) struct FailStore {
    inner: MemoryStore,
    fail_gets: Arc<AtomicUsize>,
}

impl FailStore {
    pub fn new(fail_gets: usize) -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_gets: Arc::new(AtomicUsize::new(fail_gets)),
        }
    }
}

#[async_trait]
impl Store for FailStore {
    async fn init(&self) -> StoreResult<()> {
        self.inner.init().await
    }

    async fn get(&self, key: &str) -> StoreResult<Option<Vec<u8>>> {
        if self
            .fail_gets
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(y_sweet_core::store::StoreError::ConnectionError(format!(
                "injected failure reading {key}"
            )));
        }
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> StoreResult<()> {
        self.inner.set(key, value).await
    }

    async fn remove(&self, key: &str) -> StoreResult<()> {
        self.inner.remove(key).await
    }

    async fn exists(&self, key: &str) -> StoreResult<bool> {
        self.inner.exists(key).await
    }
}

/// A `MemoryStore` that also hands out fixed presigned URLs, for file
/// endpoint tests.
#[derive(Clone)]
pub(crate) struct PresignedStore {
    inner: MemoryStore,
    pub upload_url: &'static str,
    pub download_url: &'static str,
}

impl PresignedStore {
    pub fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            upload_url: "http://mock-upload-url",
            download_url: "http://mock-download-url",
        }
    }
}

#[async_trait]
impl Store for PresignedStore {
    async fn init(&self) -> StoreResult<()> {
        self.inner.init().await
    }

    async fn get(&self, key: &str) -> StoreResult<Option<Vec<u8>>> {
        self.inner.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> StoreResult<()> {
        self.inner.set(key, value).await
    }

    async fn remove(&self, key: &str) -> StoreResult<()> {
        self.inner.remove(key).await
    }

    async fn exists(&self, key: &str) -> StoreResult<bool> {
        self.inner.exists(key).await
    }

    async fn generate_upload_url(
        &self,
        _key: &str,
        _content_type: Option<&str>,
        _content_length: Option<u64>,
    ) -> StoreResult<Option<String>> {
        Ok(Some(self.upload_url.to_string()))
    }

    async fn generate_download_url(&self, _key: &str) -> StoreResult<Option<String>> {
        Ok(Some(self.download_url.to_string()))
    }
}

/// A v1 update inserting `value` under `key` in the "data" map.
pub(crate) fn content_update(key: &str, value: &str) -> Vec<u8> {
    let doc = yrs::Doc::new();
    let map = doc.get_or_insert_map("data");
    {
        let mut txn = doc.transact_mut();
        map.insert(&mut txn, key, value);
    }
    let txn = doc.transact();
    txn.encode_state_as_update_v1(&yrs::StateVector::default())
}

/// Read back a string inserted with [`content_update`].
pub(crate) fn read_content(dwskv: &DocWithSyncKv, key: &str) -> Option<String> {
    let awareness = dwskv.awareness();
    let awareness = awareness.read().unwrap();
    let doc = awareness.doc();
    let txn = doc.transact();
    let map = txn.get_map("data")?;
    match map.get(&txn, key) {
        Some(Out::Any(yrs::Any::String(s))) => Some(s.to_string()),
        _ => None,
    }
}

pub(crate) async fn test_server(
    store: Option<Box<dyn Store>>,
    checkpoint_freq: Duration,
    doc_gc: bool,
    token: CancellationToken,
) -> Server {
    Server::new(
        store,
        checkpoint_freq,
        None,
        None,
        vec![],
        token,
        doc_gc,
        None,
    )
    .await
    .expect("test server construction failed")
}
