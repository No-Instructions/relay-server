use crate::store::Store;
use anyhow::{Context, Result};
use ciborium;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    ops::Bound,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use yrs_kvstore::{DocOps, KVEntry};

/// Helper function to get current timestamp in milliseconds since epoch
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Extension trait for serializing BTreeMap to CBOR format
trait CborBTreeMapExt {
    fn to_cbor_value(&self) -> ciborium::value::Value;
    fn from_cbor_value(value: ciborium::value::Value) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl CborBTreeMapExt for BTreeMap<Vec<u8>, Vec<u8>> {
    fn to_cbor_value(&self) -> ciborium::value::Value {
        let cbor_map: Vec<(ciborium::value::Value, ciborium::value::Value)> = self
            .iter()
            .map(|(k, v)| {
                (
                    ciborium::value::Value::Bytes(k.clone()),
                    ciborium::value::Value::Bytes(v.clone()),
                )
            })
            .collect();
        ciborium::value::Value::Map(cbor_map)
    }

    fn from_cbor_value(value: ciborium::value::Value) -> anyhow::Result<Self> {
        if let ciborium::value::Value::Map(cbor_map) = value {
            let mut btree = BTreeMap::new();
            for (k, v) in cbor_map {
                if let (ciborium::value::Value::Bytes(key), ciborium::value::Value::Bytes(val)) =
                    (k, v)
                {
                    btree.insert(key, val);
                } else {
                    anyhow::bail!("Invalid CBOR map entry: expected bytes for both key and value");
                }
            }
            Ok(btree)
        } else {
            anyhow::bail!("Expected CBOR map, got different type");
        }
    }
}

/// Metadata container for Y-Sweet data with CBOR serialization
#[derive(Serialize, Deserialize, Debug)]
struct YSweetData {
    /// Format version for future compatibility
    version: u32,

    /// Creation timestamp (milliseconds since epoch)
    created_at: u64,

    /// Last modified timestamp (milliseconds since epoch)
    modified_at: u64,

    /// Optional metadata for future extensions
    metadata: Option<BTreeMap<String, ciborium::value::Value>>,

    /// The actual key-value data as CBOR map
    #[serde(serialize_with = "serialize_btree_as_cbor")]
    #[serde(deserialize_with = "deserialize_btree_from_cbor")]
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Custom serializer for BTreeMap to CBOR Value
fn serialize_btree_as_cbor<S>(
    btree: &BTreeMap<Vec<u8>, Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let cbor_value = btree.to_cbor_value();
    cbor_value.serialize(serializer)
}

/// Custom deserializer for BTreeMap from CBOR Value
fn deserialize_btree_from_cbor<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let cbor_value = ciborium::value::Value::deserialize(deserializer)?;
    BTreeMap::from_cbor_value(cbor_value).map_err(D::Error::custom)
}

pub struct SyncKv {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
    store: Option<Arc<Box<dyn Store>>>,
    key: String,
    dirty: AtomicBool,
    dirty_callback: Box<dyn Fn() + Send + Sync>,
    created_at: Option<u64>,
    metadata: Arc<Mutex<Option<BTreeMap<String, ciborium::value::Value>>>>,
}

impl SyncKv {
    pub async fn new<Callback: Fn() + Send + Sync + 'static>(
        store: Option<Arc<Box<dyn Store>>>,
        key: &str,
        callback: Callback,
    ) -> Result<Self> {
        let key = format!("{}/data.ysweet", key);
        let mut created_at = None;
        let mut metadata = None;

        let data = if let Some(store) = &store {
            if let Some(snapshot) = store.get(&key).await.context("Failed to get from store.")? {
                tracing::info!(size=?snapshot.len(), "Loading snapshot");

                // Try CBOR format first
                match ciborium::de::from_reader::<YSweetData, _>(&snapshot[..]) {
                    Ok(y_data) => {
                        created_at = Some(y_data.created_at);
                        metadata = y_data.metadata;
                        tracing::info!("Loaded CBOR format data (version {})", y_data.version);
                        y_data.data
                    }
                    Err(cbor_err) => {
                        // Fallback to bincode for backward compatibility
                        tracing::info!(
                            "CBOR deserialization failed ({}), trying bincode format",
                            cbor_err
                        );
                        match bincode::deserialize(&snapshot) {
                            Ok(data) => {
                                tracing::info!("Loaded bincode format data, will migrate to CBOR on next persist");
                                data
                            }
                            Err(bincode_err) => {
                                anyhow::bail!("Failed to deserialize data in both CBOR and bincode formats. CBOR: {}, Bincode: {}", cbor_err, bincode_err);
                            }
                        }
                    }
                }
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            store,
            key,
            dirty: AtomicBool::new(false),
            dirty_callback: Box::new(callback),
            created_at,
            metadata: Arc::new(Mutex::new(metadata)),
        })
    }

    fn mark_dirty(&self) {
        if !self.dirty.load(Ordering::Relaxed) {
            self.dirty.store(true, Ordering::Relaxed);
            (self.dirty_callback)();
        }
    }

    pub async fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(store) = &self.store {
            let now = current_timestamp_ms();

            let snapshot = {
                let data = self.data.lock().unwrap();
                let metadata = self.metadata.lock().unwrap();

                let y_data = YSweetData {
                    version: 1,
                    created_at: self.created_at.unwrap_or(now),
                    modified_at: now,
                    metadata: metadata.clone(),
                    data: data.clone(),
                };

                let mut buffer = Vec::new();
                ciborium::ser::into_writer(&y_data, &mut buffer)?;
                buffer
            };

            tracing::info!(size=?snapshot.len(), "Persisting CBOR snapshot");
            store.set(&self.key, snapshot).await?;
        }
        self.dirty.store(false, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(test)]
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let map = self.data.lock().unwrap();
        map.get(key).cloned()
    }

    #[cfg(test)]
    fn set(&self, key: &[u8], value: &[u8]) {
        let mut map = self.data.lock().unwrap();
        map.insert(key.to_vec(), value.to_vec());
        self.mark_dirty();
    }

    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().unwrap().is_empty()
    }

    /// Set metadata for this document
    pub fn set_metadata(&self, metadata: BTreeMap<String, ciborium::value::Value>) {
        let mut meta = self.metadata.lock().unwrap();
        *meta = Some(metadata);
        self.mark_dirty();
    }

    /// Get metadata for this document
    pub fn get_metadata(&self) -> Option<BTreeMap<String, ciborium::value::Value>> {
        self.metadata.lock().unwrap().clone()
    }

    /// Update a specific metadata field
    pub fn update_metadata(&self, key: String, value: ciborium::value::Value) {
        let mut meta = self.metadata.lock().unwrap();
        if let Some(ref mut metadata) = *meta {
            metadata.insert(key, value);
        } else {
            let mut new_metadata = BTreeMap::new();
            new_metadata.insert(key, value);
            *meta = Some(new_metadata);
        }
        self.mark_dirty();
    }
}

impl<'d> DocOps<'d> for SyncKv {}

pub struct SyncKvEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl KVEntry for SyncKvEntry {
    fn key(&self) -> &[u8] {
        &self.key
    }

    fn value(&self) -> &[u8] {
        &self.value
    }
}

pub struct SyncKvCursor {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
    next_key: Bound<Vec<u8>>,
    to: Vec<u8>,
}

impl Iterator for SyncKvCursor {
    type Item = SyncKvEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let map = self.data.lock().unwrap();
        let next = map
            .range((self.next_key.clone(), Bound::Excluded(self.to.clone())))
            .next()?;
        self.next_key = Bound::Excluded(next.0.clone());
        Some(SyncKvEntry {
            key: next.0.clone(),
            value: next.1.clone(),
        })
    }
}

impl<'a> yrs_kvstore::KVStore<'a> for SyncKv {
    type Error = std::convert::Infallible;
    type Cursor = SyncKvCursor;
    type Entry = SyncKvEntry;
    type Return = Vec<u8>;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
        let map = self.data.lock().unwrap();
        Ok(map.get(key).cloned())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        let mut map = self.data.lock().unwrap();
        map.remove(key);
        self.mark_dirty();
        Ok(())
    }

    fn iter_range(&self, from: &[u8], to: &[u8]) -> Result<Self::Cursor, Self::Error> {
        Ok(SyncKvCursor {
            data: self.data.clone(),
            next_key: Bound::Included(from.to_vec()),
            to: to.to_vec(),
        })
    }

    fn peek_back(&self, key: &[u8]) -> Result<Option<Self::Entry>, Self::Error> {
        let map = self.data.lock().unwrap();
        let prev = map.range(..key.to_vec()).next_back();
        Ok(prev.map(|(k, v)| SyncKvEntry {
            key: k.clone(),
            value: v.clone(),
        }))
    }

    fn upsert(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let mut map = self.data.lock().unwrap();
        map.insert(key.to_vec(), value.to_vec());
        self.mark_dirty();
        Ok(())
    }

    fn remove_range(&self, from: &[u8], to: &[u8]) -> Result<(), Self::Error> {
        for entry in self.iter_range(from, to)? {
            let mut map = self.data.lock().unwrap();
            map.remove(&entry.key);
        }
        self.mark_dirty();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::store::Result;
    use async_trait::async_trait;
    use dashmap::DashMap;
    use std::sync::atomic::AtomicUsize;
    use tokio;

    #[derive(Default, Clone)]
    struct MemoryStore {
        data: Arc<DashMap<String, Vec<u8>>>,
    }

    #[cfg_attr(not(feature = "single-threaded"), async_trait)]
    #[cfg_attr(feature = "single-threaded", async_trait(?Send))]
    impl Store for MemoryStore {
        async fn init(&self) -> Result<()> {
            Ok(())
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.data.get(key).map(|v| v.clone()))
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

    #[derive(Default, Clone)]
    struct CallbackCounter {
        data: Arc<AtomicUsize>,
    }

    impl CallbackCounter {
        fn callback(&self) -> Box<dyn Fn() + Send + Sync> {
            let data = self.data.clone();
            Box::new(move || {
                data.fetch_add(1, Ordering::Relaxed);
            })
        }

        fn count(&self) -> usize {
            self.data.load(Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn calls_sync_callback() {
        let store = MemoryStore::default();
        let c = CallbackCounter::default();
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", c.callback())
            .await
            .unwrap();

        assert_eq!(c.count(), 0);
        sync_kv.set(b"foo", b"bar");
        assert_eq!(sync_kv.get(b"foo"), Some(b"bar".to_vec()));

        assert!(store.data.is_empty());

        // We should have received a dirty callback.
        assert_eq!(c.count(), 1);

        sync_kv.set(b"abc", b"def");

        // We should not receive a dirty callback.
        assert_eq!(c.count(), 1);
    }

    #[tokio::test]
    async fn persists_to_store() {
        let store = MemoryStore::default();

        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap();

            sync_kv.set(b"foo", b"bar");
            assert_eq!(sync_kv.get(b"foo"), Some(b"bar".to_vec()));

            assert!(store.data.is_empty());

            sync_kv.persist().await.unwrap();
        }

        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap();

            assert_eq!(sync_kv.get(b"foo"), Some(b"bar".to_vec()));
        }
    }

    #[tokio::test]
    async fn test_cbor_serialization_roundtrip() {
        let store = MemoryStore::default();

        // Create and persist data using CBOR format
        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "cbor_test", || ())
                .await
                .unwrap();

            sync_kv.set(b"key1", b"value1");
            sync_kv.set(b"key2", b"value2");
            sync_kv.set(b"key3", b"value3");

            sync_kv.persist().await.unwrap();
        }

        // Load data back and verify CBOR format was used
        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "cbor_test", || ())
                .await
                .unwrap();

            assert_eq!(sync_kv.get(b"key1"), Some(b"value1".to_vec()));
            assert_eq!(sync_kv.get(b"key2"), Some(b"value2".to_vec()));
            assert_eq!(sync_kv.get(b"key3"), Some(b"value3".to_vec()));

            // Verify created_at timestamp was preserved
            assert!(sync_kv.created_at.is_some());
        }
    }

    #[tokio::test]
    async fn test_bincode_to_cbor_migration() {
        let store = MemoryStore::default();
        let test_key = "migration_test";

        // First, manually create bincode data in the store
        {
            let mut test_data = BTreeMap::new();
            test_data.insert(b"old_key".to_vec(), b"old_value".to_vec());

            let bincode_data = bincode::serialize(&test_data).unwrap();
            let storage_key = format!("{}/data.ysweet", test_key);
            store.set(&storage_key, bincode_data).await.unwrap();
        }

        // Load bincode data, it should be migrated to CBOR on next persist
        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), test_key, || ())
                .await
                .unwrap();

            // Verify old data was loaded correctly
            assert_eq!(sync_kv.get(b"old_key"), Some(b"old_value".to_vec()));

            // Add new data and persist (should save in CBOR format)
            sync_kv.set(b"new_key", b"new_value");
            sync_kv.persist().await.unwrap();
        }

        // Load again and verify both old and new data exist in CBOR format
        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), test_key, || ())
                .await
                .unwrap();

            assert_eq!(sync_kv.get(b"old_key"), Some(b"old_value".to_vec()));
            assert_eq!(sync_kv.get(b"new_key"), Some(b"new_value".to_vec()));

            // Should have created_at timestamp now (from CBOR format)
            assert!(sync_kv.created_at.is_some());
        }
    }

    #[test]
    fn test_cbor_btreemap_extension() {
        use super::CborBTreeMapExt;

        let mut original = BTreeMap::new();
        original.insert(vec![1, 2, 3], vec![4, 5, 6]);
        original.insert(vec![7, 8, 9], vec![10, 11, 12]);
        original.insert(vec![13, 14, 15], vec![16, 17, 18]);

        // Convert to CBOR value
        let cbor_value = original.to_cbor_value();

        // Convert back from CBOR value
        let restored = BTreeMap::from_cbor_value(cbor_value).unwrap();

        // Verify roundtrip
        assert_eq!(original, restored);
    }

    #[test]
    fn test_ysweet_data_serialization() {
        let mut data = BTreeMap::new();
        data.insert(vec![1, 2], vec![3, 4]);
        data.insert(vec![5, 6], vec![7, 8]);

        let y_data = YSweetData {
            version: 1,
            created_at: 1234567890,
            modified_at: 1234567891,
            metadata: None,
            data,
        };

        // Serialize to CBOR
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&y_data, &mut buffer).unwrap();

        // Deserialize from CBOR
        let restored: YSweetData = ciborium::de::from_reader(&buffer[..]).unwrap();

        assert_eq!(restored.version, 1);
        assert_eq!(restored.created_at, 1234567890);
        assert_eq!(restored.modified_at, 1234567891);
        assert_eq!(restored.data.len(), 2);
        assert_eq!(restored.data.get(&vec![1, 2]), Some(&vec![3, 4]));
        assert_eq!(restored.data.get(&vec![5, 6]), Some(&vec![7, 8]));
    }

    #[tokio::test]
    async fn test_metadata_persistence_roundtrip() {
        let store = MemoryStore::default();
        let test_key = "metadata_test";

        // Create initial data with metadata
        let created_timestamp = {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), test_key, || ())
                .await
                .unwrap();

            sync_kv.set(b"data_key", b"data_value");
            sync_kv.persist().await.unwrap();

            // Manually inject metadata into the stored data
            let storage_key = format!("{}/data.ysweet", test_key);
            let stored_data = store.get(&storage_key).await.unwrap().unwrap();

            // Deserialize, add metadata, and re-serialize
            let mut y_data: YSweetData = ciborium::de::from_reader(&stored_data[..]).unwrap();
            let mut metadata = BTreeMap::new();
            metadata.insert(
                "document_type".to_string(),
                ciborium::value::Value::Text("test_document".to_string()),
            );
            metadata.insert(
                "version_info".to_string(),
                ciborium::value::Value::Integer(42.into()),
            );
            metadata.insert(
                "feature_flags".to_string(),
                ciborium::value::Value::Array(vec![
                    ciborium::value::Value::Text("collaborative".to_string()),
                    ciborium::value::Value::Text("auto-save".to_string()),
                ]),
            );
            y_data.metadata = Some(metadata);

            let mut buffer = Vec::new();
            ciborium::ser::into_writer(&y_data, &mut buffer).unwrap();
            store.set(&storage_key, buffer).await.unwrap();

            y_data.created_at
        };

        // Load data from disk and verify metadata persisted
        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), test_key, || ())
                .await
                .unwrap();

            // Verify data is intact
            assert_eq!(sync_kv.get(b"data_key"), Some(b"data_value".to_vec()));

            // Verify timestamp was preserved
            assert_eq!(sync_kv.created_at, Some(created_timestamp));

            // Directly check metadata in stored format
            let storage_key = format!("{}/data.ysweet", test_key);
            let stored_data = store.get(&storage_key).await.unwrap().unwrap();
            let y_data: YSweetData = ciborium::de::from_reader(&stored_data[..]).unwrap();

            assert!(y_data.metadata.is_some());
            let metadata = y_data.metadata.unwrap();

            // Verify document_type
            assert_eq!(
                metadata.get("document_type"),
                Some(&ciborium::value::Value::Text("test_document".to_string()))
            );

            // Verify version_info
            assert_eq!(
                metadata.get("version_info"),
                Some(&ciborium::value::Value::Integer(42.into()))
            );

            // Verify feature_flags array
            if let Some(ciborium::value::Value::Array(flags)) = metadata.get("feature_flags") {
                assert_eq!(flags.len(), 2);
                assert_eq!(
                    flags[0],
                    ciborium::value::Value::Text("collaborative".to_string())
                );
                assert_eq!(
                    flags[1],
                    ciborium::value::Value::Text("auto-save".to_string())
                );
            } else {
                panic!("Expected feature_flags to be an array");
            }

            // Add more data and persist again - metadata should be preserved
            sync_kv.set(b"new_key", b"new_value");
            sync_kv.persist().await.unwrap();
        }

        // Final verification - load again and check everything is still there
        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), test_key, || ())
                .await
                .unwrap();

            // Verify both old and new data
            assert_eq!(sync_kv.get(b"data_key"), Some(b"data_value".to_vec()));
            assert_eq!(sync_kv.get(b"new_key"), Some(b"new_value".to_vec()));

            // Check metadata still exists after persist
            let storage_key = format!("{}/data.ysweet", test_key);
            let stored_data = store.get(&storage_key).await.unwrap().unwrap();
            let y_data: YSweetData = ciborium::de::from_reader(&stored_data[..]).unwrap();

            // Metadata should still be present after persist (now that we preserve it)
            assert!(y_data.metadata.is_some());
            let metadata = y_data.metadata.unwrap();

            // Verify all metadata fields are still there
            assert_eq!(
                metadata.get("document_type"),
                Some(&ciborium::value::Value::Text("test_document".to_string()))
            );
            assert_eq!(
                metadata.get("version_info"),
                Some(&ciborium::value::Value::Integer(42.into()))
            );
        }
    }

    #[tokio::test]
    async fn test_metadata_api() {
        let store = MemoryStore::default();
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "api_test", || ())
            .await
            .unwrap();

        // Initially no metadata
        assert_eq!(sync_kv.get_metadata(), None);

        // Add some metadata using update_metadata
        sync_kv.update_metadata(
            "doc_type".to_string(),
            ciborium::value::Value::Text("collaborative_doc".to_string()),
        );
        sync_kv.update_metadata(
            "max_collaborators".to_string(),
            ciborium::value::Value::Integer(10.into()),
        );

        // Verify metadata exists
        let metadata = sync_kv.get_metadata().unwrap();
        assert_eq!(metadata.len(), 2);
        assert_eq!(
            metadata.get("doc_type"),
            Some(&ciborium::value::Value::Text(
                "collaborative_doc".to_string()
            ))
        );
        assert_eq!(
            metadata.get("max_collaborators"),
            Some(&ciborium::value::Value::Integer(10.into()))
        );

        // Persist and reload
        sync_kv.persist().await.unwrap();
        let sync_kv2 = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "api_test", || ())
            .await
            .unwrap();

        // Verify metadata persisted
        let reloaded_metadata = sync_kv2.get_metadata().unwrap();
        assert_eq!(reloaded_metadata.len(), 2);
        assert_eq!(
            reloaded_metadata.get("doc_type"),
            Some(&ciborium::value::Value::Text(
                "collaborative_doc".to_string()
            ))
        );
        assert_eq!(
            reloaded_metadata.get("max_collaborators"),
            Some(&ciborium::value::Value::Integer(10.into()))
        );

        // Test set_metadata to replace all metadata
        let mut new_metadata = BTreeMap::new();
        new_metadata.insert(
            "version".to_string(),
            ciborium::value::Value::Integer(2.into()),
        );
        sync_kv2.set_metadata(new_metadata);

        let updated_metadata = sync_kv2.get_metadata().unwrap();
        assert_eq!(updated_metadata.len(), 1);
        assert_eq!(
            updated_metadata.get("version"),
            Some(&ciborium::value::Value::Integer(2.into()))
        );
        // Old metadata should be gone
        assert_eq!(updated_metadata.get("doc_type"), None);
    }
}
