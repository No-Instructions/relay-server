//! An in-memory [`Store`] backed by a shared map. Clones share the same
//! underlying data, so a `MemoryStore` can stand in for a durable store
//! shared between multiple servers in tests, or serve as an ephemeral
//! store where durability is not required.
//!
//! The default `get_with_lease`/`set_if_unchanged` implementations give it
//! digest-based compare-and-set semantics, matching the write-lease
//! behavior of stores without native conditional writes.

use super::{Result, Store};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct MemoryStore {
    data: Arc<DashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct (non-trait) read of a stored value, for assertions.
    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.data.get(key).map(|v| v.value().clone())
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.data.get(key).map(|v| v.value().clone()))
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.data.insert(key.to_owned(), value);
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.data.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.data.contains_key(key))
    }
}
