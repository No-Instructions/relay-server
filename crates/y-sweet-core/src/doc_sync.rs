use crate::{
    doc_connection::DOC_NAME, event::DocumentUpdatedEvent, permanent_user_data::CompactionResult,
    store::Store, sync::awareness::Awareness, sync_kv::SyncKv, webhook::WebhookCallback,
};
use anyhow::{anyhow, Context, Result};
use std::sync::{Arc, RwLock};
use yrs::{
    updates::decoder::Decode, updates::encoder::Encode, Doc, ReadTxn, StateVector, Subscription,
    Transact, Update,
};
use yrs_kvstore::DocOps;

pub struct DocWithSyncKv {
    awareness: Arc<RwLock<Awareness>>,
    sync_kv: Arc<SyncKv>,
    #[allow(unused)] // acts as RAII guard
    subscription: Subscription,
}

impl DocWithSyncKv {
    pub fn awareness(&self) -> Arc<RwLock<Awareness>> {
        self.awareness.clone()
    }

    pub fn sync_kv(&self) -> Arc<SyncKv> {
        self.sync_kv.clone()
    }

    pub async fn new<F>(
        key: &str,
        store: Option<Arc<Box<dyn Store>>>,
        dirty_callback: F,
        webhook_callback: Option<WebhookCallback>,
    ) -> Result<Self>
    where
        F: Fn() + Send + Sync + 'static,
    {
        let sync_kv = SyncKv::new(store, key, dirty_callback)
            .await
            .context("Failed to create SyncKv")?;

        let sync_kv = Arc::new(sync_kv);
        let doc = Doc::new();

        {
            let mut txn = doc.transact_mut();
            sync_kv
                .load_doc(DOC_NAME, &mut txn)
                .map_err(|_| anyhow!("Failed to load doc"))?;
        }

        let subscription = {
            let sync_kv = sync_kv.clone();
            let webhook_callback = webhook_callback.clone();
            let doc_key = key.to_string();
            doc.observe_update_v1(move |txn, event| {
                sync_kv.push_update(DOC_NAME, &event.update).unwrap();
                sync_kv
                    .flush_doc_with(DOC_NAME, Default::default())
                    .unwrap();

                // Trigger webhook if callback is configured
                if let Some(ref callback) = webhook_callback {
                    // Extract state vector from the transaction (post-update)
                    let sv = txn.state_vector().encode_v1();

                    // Create the event payload with business data, metadata, update, and state vector
                    let event = DocumentUpdatedEvent::new(doc_key.clone())
                        .with_metadata(&sync_kv)
                        .with_update(event.update.to_vec())
                        .with_state_vector(sv);

                    // Callback handles envelope creation and dispatch
                    callback(event);
                }
            })
            .map_err(|_| anyhow!("Failed to subscribe to updates"))?
        };

        let awareness = Arc::new(RwLock::new(Awareness::new(doc)));
        Ok(Self {
            awareness,
            sync_kv,
            subscription,
        })
    }

    pub fn as_update(&self) -> Vec<u8> {
        let awareness_guard = self.awareness.read().unwrap();
        let doc = &awareness_guard.doc;

        let txn = doc.transact();

        txn.encode_state_as_update_v1(&StateVector::default())
    }

    pub fn apply_update(&self, update: &[u8]) -> Result<()> {
        let awareness_guard = self.awareness.write().unwrap();
        let doc = &awareness_guard.doc;

        let update: Update =
            Update::decode_v1(update).map_err(|_| anyhow!("Failed to decode update"))?;

        let mut txn = doc.transact_mut();
        txn.apply_update(update);

        Ok(())
    }

    /// Set the channel for this document in metadata
    pub fn set_channel(&self, channel: &str) {
        self.sync_kv.update_metadata(
            "channel".to_string(),
            ciborium::value::Value::Text(channel.to_string()),
        );
    }

    /// Get the channel for this document from metadata
    pub fn get_channel(&self) -> Option<String> {
        self.sync_kv.get_metadata()?.get("channel").and_then(|v| {
            if let ciborium::value::Value::Text(channel) = v {
                Some(channel.clone())
            } else {
                None
            }
        })
    }

    /// Compact the "users" PermanentUserData map: deduplicate ids, clear ds.
    ///
    /// The mutations trigger the update observer, which marks SyncKv dirty so
    /// the compacted state will be persisted on the next flush.
    pub fn compact_user_data(&self) -> CompactionResult {
        let awareness_guard = self.awareness.read().unwrap();
        let doc = &awareness_guard.doc;
        crate::permanent_user_data::compact_user_data(doc)
    }

    /// Update the state vector for a subdocument in this document's metadata index.
    /// Also seeds the last-seen timestamp so new entries aren't immediately eligible for GC.
    pub fn update_subdoc_state_vector(&self, subdoc_id: &str, encoded_sv: Vec<u8>) {
        let mut metadata = self.sync_kv.get_metadata().unwrap_or_default();

        let subdocs = metadata
            .entry("subdocs".to_string())
            .or_insert_with(|| ciborium::value::Value::Map(Vec::new()));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let entry_value = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("state_vector".to_string()),
                ciborium::value::Value::Bytes(encoded_sv),
            ),
            (
                ciborium::value::Value::Text("last_seen".to_string()),
                ciborium::value::Value::Integer(now.into()),
            ),
        ]);

        if let ciborium::value::Value::Map(ref mut entries) = subdocs {
            let key = ciborium::value::Value::Text(subdoc_id.to_string());
            if let Some(entry) = entries.iter_mut().find(|(k, _)| *k == key) {
                entry.1 = entry_value;
            } else {
                entries.push((key, entry_value));
            }
        }

        self.sync_kv.set_metadata(metadata);
    }

    /// Get the subdocument state vector index from metadata.
    pub fn get_subdoc_state_vectors(&self) -> Option<Vec<(String, Vec<u8>)>> {
        let metadata = self.sync_kv.get_metadata()?;
        let subdocs = metadata.get("subdocs")?;

        if let ciborium::value::Value::Map(entries) = subdocs {
            let mut result = Vec::new();
            for (k, v) in entries {
                if let ciborium::value::Value::Text(doc_id) = k {
                    if let ciborium::value::Value::Map(fields) = v {
                        for (fk, fv) in fields {
                            if let (
                                ciborium::value::Value::Text(fname),
                                ciborium::value::Value::Bytes(sv_bytes),
                            ) = (fk, fv)
                            {
                                if fname == "state_vector" {
                                    result.push((doc_id.clone(), sv_bytes.clone()));
                                }
                            }
                        }
                    }
                }
            }
            Some(result)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use async_trait::async_trait;
    use dashmap::DashMap;

    #[derive(Default, Clone)]
    struct MemoryStore {
        data: Arc<DashMap<String, Vec<u8>>>,
    }

    #[cfg_attr(not(feature = "single-threaded"), async_trait)]
    #[cfg_attr(feature = "single-threaded", async_trait(?Send))]
    impl Store for MemoryStore {
        async fn init(&self) -> crate::store::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> crate::store::Result<Option<Vec<u8>>> {
            Ok(self.data.get(key).map(|v| v.clone()))
        }
        async fn set(&self, key: &str, value: Vec<u8>) -> crate::store::Result<()> {
            self.data.insert(key.to_owned(), value);
            Ok(())
        }
        async fn remove(&self, key: &str) -> crate::store::Result<()> {
            self.data.remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> crate::store::Result<bool> {
            Ok(self.data.contains_key(key))
        }
    }

    #[tokio::test]
    async fn test_subdoc_state_vector_roundtrip() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("parent_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        // Initially no subdoc state vectors
        assert!(dwskv.get_subdoc_state_vectors().is_none());

        // Add a subdoc state vector
        dwskv.update_subdoc_state_vector("subdoc-abc", vec![1, 2, 3, 4]);

        let svs = dwskv.get_subdoc_state_vectors().unwrap();
        assert_eq!(svs.len(), 1);
        assert_eq!(svs[0], ("subdoc-abc".to_string(), vec![1, 2, 3, 4]));

        // Add another subdoc
        dwskv.update_subdoc_state_vector("subdoc-def", vec![5, 6, 7, 8]);

        let svs = dwskv.get_subdoc_state_vectors().unwrap();
        assert_eq!(svs.len(), 2);

        // Update existing subdoc — should replace, not duplicate
        dwskv.update_subdoc_state_vector("subdoc-abc", vec![10, 20, 30]);

        let svs = dwskv.get_subdoc_state_vectors().unwrap();
        assert_eq!(svs.len(), 2);
        let abc = svs.iter().find(|(id, _)| id == "subdoc-abc").unwrap();
        assert_eq!(abc.1, vec![10, 20, 30]);
    }

    #[tokio::test]
    async fn test_subdoc_state_vectors_persist() {
        let store = MemoryStore::default();

        // Create parent, add subdoc state vectors, persist
        {
            let dwskv = DocWithSyncKv::new(
                "parent_doc",
                Some(Arc::new(Box::new(store.clone()))),
                || (),
                None,
            )
            .await
            .unwrap();

            dwskv.update_subdoc_state_vector("subdoc-1", vec![1, 2, 3]);
            dwskv.update_subdoc_state_vector("subdoc-2", vec![4, 5, 6]);
            dwskv.sync_kv().persist().await.unwrap();
        }

        // Reload and verify state vectors survived
        {
            let dwskv = DocWithSyncKv::new(
                "parent_doc",
                Some(Arc::new(Box::new(store.clone()))),
                || (),
                None,
            )
            .await
            .unwrap();

            let svs = dwskv.get_subdoc_state_vectors().unwrap();
            assert_eq!(svs.len(), 2);

            let s1 = svs.iter().find(|(id, _)| id == "subdoc-1").unwrap();
            assert_eq!(s1.1, vec![1, 2, 3]);

            let s2 = svs.iter().find(|(id, _)| id == "subdoc-2").unwrap();
            assert_eq!(s2.1, vec![4, 5, 6]);
        }
    }

    #[tokio::test]
    async fn test_subdoc_last_seen_seeded_on_update() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("parent_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        dwskv.update_subdoc_state_vector("subdoc-abc", vec![1, 2, 3]);

        let metadata = dwskv.sync_kv().get_metadata().unwrap();
        let subdocs = metadata.get("subdocs").unwrap();
        if let ciborium::value::Value::Map(entries) = subdocs {
            assert_eq!(entries.len(), 1);
            let (k, v) = &entries[0];
            assert_eq!(*k, ciborium::value::Value::Text("subdoc-abc".to_string()));
            if let ciborium::value::Value::Map(fields) = v {
                // Check state_vector
                let sv = fields
                    .iter()
                    .find(|(k, _)| *k == ciborium::value::Value::Text("state_vector".to_string()))
                    .unwrap();
                assert_eq!(sv.1, ciborium::value::Value::Bytes(vec![1, 2, 3]));
                // Check last_seen
                let ls = fields
                    .iter()
                    .find(|(k, _)| *k == ciborium::value::Value::Text("last_seen".to_string()))
                    .unwrap();
                if let ciborium::value::Value::Integer(ts) = &ls.1 {
                    let ts: u64 = (*ts).try_into().unwrap();
                    assert!(ts >= before);
                } else {
                    panic!("Expected Integer timestamp");
                }
            } else {
                panic!("Expected Map for subdoc entry");
            }
        } else {
            panic!("Expected Map for subdocs");
        }

        // Second update should refresh the timestamp, not duplicate the entry
        std::thread::sleep(std::time::Duration::from_millis(2));
        dwskv.update_subdoc_state_vector("subdoc-abc", vec![4, 5, 6]);

        let metadata = dwskv.sync_kv().get_metadata().unwrap();
        let subdocs = metadata.get("subdocs").unwrap();
        if let ciborium::value::Value::Map(entries) = subdocs {
            assert_eq!(entries.len(), 1);
            if let ciborium::value::Value::Map(fields) = &entries[0].1 {
                let sv = fields
                    .iter()
                    .find(|(k, _)| *k == ciborium::value::Value::Text("state_vector".to_string()))
                    .unwrap();
                assert_eq!(sv.1, ciborium::value::Value::Bytes(vec![4, 5, 6]));
            }
        } else {
            panic!("Expected Map");
        }
    }
}
