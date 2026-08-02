use crate::{
    doc_connection::DOC_NAME, event::DocumentUpdatedEvent, permanent_user_data::CompactionResult,
    store::Store, sync::awareness::Awareness, sync_kv::SyncKv, webhook::WebhookCallback,
};
use anyhow::{anyhow, Context, Result};
use std::sync::{Arc, RwLock};
use yrs::{
    updates::decoder::Decode, updates::encoder::Encode, Array, Doc, Map, Out, ReadTxn, StateVector,
    Subscription, Transact, Update,
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
                    // Extract the full snapshot from the transaction (post-update).
                    let snapshot = txn.snapshot().encode_v1();

                    // Create the event payload with business data, metadata, update, and snapshot
                    let event = DocumentUpdatedEvent::new(doc_key.clone())
                        .with_metadata(&sync_kv)
                        .with_update(event.update.to_vec())
                        .with_snapshot(snapshot);

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
        txn.apply_update(update)
            .map_err(|err| anyhow!("Failed to apply update: {}", err))?;
        crate::sync::block_filemeta_path_traversal(&mut txn);

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

    /// Register a client_id under the given user in the "users" PermanentUserData map.
    /// This is a no-op if the client_id is already registered for that user.
    /// Returns true if a new registration was written.
    pub fn register_client_id(&self, user_id: &str, client_id: u64) -> bool {
        let awareness_guard = self.awareness.read().unwrap();
        let doc = &awareness_guard.doc;

        // get_or_insert_map takes a write txn internally, call before any read txn.
        let users_map = doc.get_or_insert_map("users");

        // Check if already registered under a read txn.
        {
            let txn = doc.transact();
            if let Some(Out::YMap(user_map)) = users_map.get(&txn, user_id) {
                if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                    for item in ids_arr.iter(&txn) {
                        let existing_id = match &item {
                            Out::Any(yrs::Any::Number(n)) => Some(*n as u64),
                            Out::Any(yrs::Any::BigInt(n)) => Some(*n as u64),
                            _ => None,
                        };
                        if existing_id == Some(client_id) {
                            return false;
                        }
                    }
                }
            }
        }
        // Read txn dropped before taking a write txn.

        let mut txn = doc.transact_mut();

        // Get or create the user entry.
        let user_map = match users_map.get(&txn, user_id) {
            Some(Out::YMap(m)) => m,
            _ => users_map.insert(&mut txn, user_id, yrs::MapPrelim::default()),
        };

        // Get or create the ids array.
        let ids_arr = match user_map.get(&txn, "ids") {
            Some(Out::YArray(a)) => a,
            _ => user_map.insert(&mut txn, "ids", yrs::ArrayPrelim::default()),
        };

        // Ensure `ds` exists as an empty YArray so canonical Yjs PUD readers don't crash.
        if !matches!(user_map.get(&txn, "ds"), Some(Out::YArray(_))) {
            user_map.insert(&mut txn, "ds", yrs::ArrayPrelim::default());
        }

        ids_arr.push_back(&mut txn, yrs::Any::Number(client_id as f64));
        tracing::info!(
            user_id,
            client_id,
            "Registered client_id for user via server-driven PUD"
        );
        true
    }

    /// Update the snapshot for a subdocument in this document's metadata index.
    /// Also records when the subdocument was last edited.
    pub fn update_subdoc_snapshot(&self, subdoc_id: &str, encoded_snapshot: Vec<u8>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.update_subdoc_snapshot_at(subdoc_id, encoded_snapshot, now);
    }

    /// Same as [`Self::update_subdoc_snapshot`] but uses an explicit
    /// `last_edit_ms` (Unix epoch milliseconds) instead of the current wall
    /// clock. Intended for offline backfills where the historical edit time
    /// is known (e.g. an S3 object's `last_modified`).
    pub fn update_subdoc_snapshot_at(
        &self,
        subdoc_id: &str,
        encoded_snapshot: Vec<u8>,
        last_edit_ms: u64,
    ) {
        let snapshot_value = ciborium::value::Value::Bytes(encoded_snapshot);
        let last_edit_value = ciborium::value::Value::Integer(last_edit_ms.into());

        // Mutate under the metadata lock: subdoc update callbacks and index
        // queries touch this map concurrently, and an unlocked
        // read-modify-write here loses entries written between the read and
        // the write.
        self.sync_kv.with_metadata(|metadata| {
            let subdocs = metadata
                .entry("subdocs".to_string())
                .or_insert_with(|| ciborium::value::Value::Map(Vec::new()));

            if let ciborium::value::Value::Map(ref mut entries) = subdocs {
                let key = ciborium::value::Value::Text(subdoc_id.to_string());
                if let Some((_, entry_value)) = entries.iter_mut().find(|(k, _)| *k == key) {
                    if let ciborium::value::Value::Map(fields) = entry_value {
                        fields.retain(|(k, _)| {
                            *k != ciborium::value::Value::Text("last_seen".to_string())
                                && *k != ciborium::value::Value::Text("state_vector".to_string())
                        });
                        upsert_cbor_field(fields, "snapshot", snapshot_value);
                        upsert_cbor_field(fields, "last_edit", last_edit_value);
                    } else {
                        *entry_value = ciborium::value::Value::Map(vec![
                            (
                                ciborium::value::Value::Text("snapshot".to_string()),
                                snapshot_value,
                            ),
                            (
                                ciborium::value::Value::Text("last_edit".to_string()),
                                last_edit_value,
                            ),
                        ]);
                    }
                } else {
                    entries.push((
                        key,
                        ciborium::value::Value::Map(vec![
                            (
                                ciborium::value::Value::Text("snapshot".to_string()),
                                snapshot_value,
                            ),
                            (
                                ciborium::value::Value::Text("last_edit".to_string()),
                                last_edit_value,
                            ),
                        ]),
                    ));
                }
            }
        });
    }

    /// Get the subdocument snapshot index from metadata.
    pub fn get_subdoc_snapshots(&self) -> Option<Vec<(String, Vec<u8>)>> {
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
                                ciborium::value::Value::Bytes(snapshot_bytes),
                            ) = (fk, fv)
                            {
                                if fname == "snapshot" {
                                    result.push((doc_id.clone(), snapshot_bytes.clone()));
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

fn upsert_cbor_field(
    fields: &mut Vec<(ciborium::value::Value, ciborium::value::Value)>,
    key: &str,
    value: ciborium::value::Value,
) {
    let key = ciborium::value::Value::Text(key.to_string());
    if let Some((_, existing)) = fields.iter_mut().find(|(k, _)| *k == key) {
        *existing = value;
    } else {
        fields.push((key, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use async_trait::async_trait;
    use dashmap::DashMap;
    use std::collections::BTreeMap;
    use yrs::Text;

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
    async fn out_of_order_filemeta_delete_does_not_resurrect_after_reload() {
        let source = Doc::with_client_id(1);
        let updates = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscription = {
            let updates = updates.clone();
            source
                .observe_update_v1(move |_, event| {
                    updates.lock().unwrap().push(event.update.clone());
                })
                .unwrap()
        };
        let map = source.get_or_insert_map("filemeta_v0");

        map.insert(&mut source.transact_mut(), "k4", "v2");
        map.insert(&mut source.transact_mut(), "k4", "v10");
        map.insert(&mut source.transact_mut(), "k0", "v4");
        map.insert(&mut source.transact_mut(), "k4", "v16");
        map.insert(&mut source.transact_mut(), "k5", "v12");
        map.insert(&mut source.transact_mut(), "k0", "v2");
        map.insert(&mut source.transact_mut(), "k3", "v13");
        map.remove(&mut source.transact_mut(), "k4");
        drop(subscription);

        assert!(map.get(&source.transact(), "k4").is_none());
        let updates = Arc::into_inner(updates).unwrap().into_inner().unwrap();
        assert_eq!(updates.len(), 8);

        let store = MemoryStore::default();
        {
            let doc = DocWithSyncKv::new(
                "filemeta",
                Some(Arc::new(Box::new(store.clone()))),
                || (),
                None,
            )
            .await
            .unwrap();

            // Simulate valid updates from one peer arriving out of causal order.
            for index in [5, 4, 3, 0, 7, 6, 1, 2] {
                doc.apply_update(&updates[index]).unwrap();
            }
            doc.sync_kv().persist().await.unwrap();
        }

        let reloaded = DocWithSyncKv::new("filemeta", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();
        let awareness = reloaded.awareness();
        let guard = awareness.read().unwrap();
        let map = guard.doc().get_or_insert_map("filemeta_v0");
        let txn = guard.doc().transact();

        assert!(map.get(&txn, "k3").is_some());
        assert!(
            map.get(&txn, "k4").is_none(),
            "an out-of-order pending delete must not resurrect a removed filemeta entry"
        );
    }

    #[tokio::test]
    async fn direct_update_blocks_filemeta_path_traversal() {
        let source = Doc::with_client_id(1);
        let filemeta = source.get_or_insert_map("filemeta_v0");
        {
            let mut txn = source.transact_mut();
            filemeta.insert(&mut txn, "folder/note.md", "safe");
            filemeta.insert(&mut txn, "folder/../secret.md", "blocked");
        }
        let update = source
            .transact()
            .encode_state_as_update_v1(&StateVector::default());

        let target = DocWithSyncKv::new("filemeta", None, || (), None)
            .await
            .unwrap();
        target.apply_update(&update).unwrap();

        let awareness = target.awareness();
        let guard = awareness.read().unwrap();
        let txn = guard.doc().transact();
        let filemeta = txn.get_map("filemeta_v0").unwrap();
        assert!(filemeta.get(&txn, "folder/note.md").is_some());
        assert!(filemeta.get(&txn, "folder/../secret.md").is_none());
    }

    #[tokio::test]
    async fn test_subdoc_snapshot_roundtrip() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("parent_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        // Initially no subdoc snapshots
        assert!(dwskv.get_subdoc_snapshots().is_none());

        // Add a subdoc snapshot
        dwskv.update_subdoc_snapshot("subdoc-abc", vec![1, 2, 3, 4]);

        let snapshots = dwskv.get_subdoc_snapshots().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0], ("subdoc-abc".to_string(), vec![1, 2, 3, 4]));

        // Add another subdoc
        dwskv.update_subdoc_snapshot("subdoc-def", vec![5, 6, 7, 8]);

        let snapshots = dwskv.get_subdoc_snapshots().unwrap();
        assert_eq!(snapshots.len(), 2);

        // Update existing subdoc — should replace, not duplicate
        dwskv.update_subdoc_snapshot("subdoc-abc", vec![10, 20, 30]);

        let snapshots = dwskv.get_subdoc_snapshots().unwrap();
        assert_eq!(snapshots.len(), 2);
        let abc = snapshots.iter().find(|(id, _)| id == "subdoc-abc").unwrap();
        assert_eq!(abc.1, vec![10, 20, 30]);
    }

    #[tokio::test]
    async fn test_subdoc_snapshots_persist() {
        let store = MemoryStore::default();

        // Create parent, add subdoc snapshots, persist
        {
            let dwskv = DocWithSyncKv::new(
                "parent_doc",
                Some(Arc::new(Box::new(store.clone()))),
                || (),
                None,
            )
            .await
            .unwrap();

            dwskv.update_subdoc_snapshot("subdoc-1", vec![1, 2, 3]);
            dwskv.update_subdoc_snapshot("subdoc-2", vec![4, 5, 6]);
            dwskv.sync_kv().persist().await.unwrap();
        }

        // Reload and verify snapshots survived
        {
            let dwskv = DocWithSyncKv::new(
                "parent_doc",
                Some(Arc::new(Box::new(store.clone()))),
                || (),
                None,
            )
            .await
            .unwrap();

            let snapshots = dwskv.get_subdoc_snapshots().unwrap();
            assert_eq!(snapshots.len(), 2);

            let s1 = snapshots.iter().find(|(id, _)| id == "subdoc-1").unwrap();
            assert_eq!(s1.1, vec![1, 2, 3]);

            let s2 = snapshots.iter().find(|(id, _)| id == "subdoc-2").unwrap();
            assert_eq!(s2.1, vec![4, 5, 6]);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_subdoc_snapshot_updates_keep_all_entries() {
        let store = MemoryStore::default();
        let dwskv = Arc::new(
            DocWithSyncKv::new("parent_doc", Some(Arc::new(Box::new(store))), || (), None)
                .await
                .unwrap(),
        );

        // Writers update distinct subdocs while a query-style writer stamps
        // every entry, mirroring subdoc update callbacks racing
        // MSG_QUERY_SUBDOCS handling on the same parent. Every writer's last
        // update must survive: losing one means a reader was able to write
        // back a stale copy of the whole map.
        const WRITERS: usize = 8;
        const UPDATES_PER_WRITER: usize = 200;

        let mut handles = Vec::new();
        for w in 0..WRITERS {
            let dwskv = dwskv.clone();
            handles.push(std::thread::spawn(move || {
                let subdoc_id = format!("subdoc-{w}");
                for i in 0..UPDATES_PER_WRITER {
                    dwskv.update_subdoc_snapshot(&subdoc_id, vec![w as u8, i as u8]);
                }
            }));
        }
        {
            let dwskv = dwskv.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..UPDATES_PER_WRITER {
                    dwskv.sync_kv().with_metadata(|metadata| {
                        if let Some(ciborium::value::Value::Map(entries)) =
                            metadata.get_mut("subdocs")
                        {
                            for (_, entry_val) in entries {
                                if let ciborium::value::Value::Map(fields) = entry_val {
                                    upsert_cbor_field(
                                        fields,
                                        "last_query",
                                        ciborium::value::Value::Integer((i as u64).into()),
                                    );
                                }
                            }
                        }
                    });
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let snapshots = dwskv.get_subdoc_snapshots().unwrap();
        assert_eq!(snapshots.len(), WRITERS);
        for w in 0..WRITERS {
            let subdoc_id = format!("subdoc-{w}");
            let entry = snapshots.iter().find(|(id, _)| *id == subdoc_id).unwrap();
            assert_eq!(entry.1, vec![w as u8, (UPDATES_PER_WRITER - 1) as u8]);
        }
    }

    #[tokio::test]
    async fn test_update_event_snapshot_includes_delete_set() {
        let store = MemoryStore::default();
        let snapshots = Arc::new(std::sync::Mutex::new(Vec::new()));
        let snapshots_for_callback = snapshots.clone();
        let callback: WebhookCallback = Arc::new(move |event| {
            if let Some(snapshot) = event.snapshot {
                snapshots_for_callback.lock().unwrap().push(snapshot);
            }
        });

        let dwskv = DocWithSyncKv::new(
            "subdoc",
            Some(Arc::new(Box::new(store))),
            || (),
            Some(callback),
        )
        .await
        .unwrap();

        let awareness = dwskv.awareness();
        {
            let guard = awareness.read().unwrap();
            let text = guard.doc().get_or_insert_text("body");
            let mut txn = guard.doc().transact_mut();
            text.insert(&mut txn, 0, "abc");
        }
        {
            let guard = awareness.read().unwrap();
            let text = guard.doc().get_or_insert_text("body");
            let mut txn = guard.doc().transact_mut();
            text.remove_range(&mut txn, 1, 1);
        }

        let encoded_snapshot = snapshots.lock().unwrap().last().cloned().unwrap();
        let snapshot = yrs::Snapshot::decode_v1(&encoded_snapshot).unwrap();
        assert!(!snapshot.delete_set.is_empty());
    }

    #[tokio::test]
    async fn test_subdoc_last_edit_seeded_on_update() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("parent_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        dwskv.update_subdoc_snapshot("subdoc-abc", vec![1, 2, 3]);

        let metadata = dwskv.sync_kv().get_metadata().unwrap();
        let subdocs = metadata.get("subdocs").unwrap();
        if let ciborium::value::Value::Map(entries) = subdocs {
            assert_eq!(entries.len(), 1);
            let (k, v) = &entries[0];
            assert_eq!(*k, ciborium::value::Value::Text("subdoc-abc".to_string()));
            if let ciborium::value::Value::Map(fields) = v {
                // Check snapshot
                let snapshot = fields
                    .iter()
                    .find(|(k, _)| *k == ciborium::value::Value::Text("snapshot".to_string()))
                    .unwrap();
                assert_eq!(snapshot.1, ciborium::value::Value::Bytes(vec![1, 2, 3]));
                // Check last_edit
                let le = fields
                    .iter()
                    .find(|(k, _)| *k == ciborium::value::Value::Text("last_edit".to_string()))
                    .unwrap();
                if let ciborium::value::Value::Integer(ts) = &le.1 {
                    let ts: u64 = (*ts).try_into().unwrap();
                    assert!(ts >= before);
                } else {
                    panic!("Expected Integer timestamp");
                }
                assert!(fields.iter().all(|(k, _)| {
                    *k != ciborium::value::Value::Text("last_seen".to_string())
                        && *k != ciborium::value::Value::Text("last_query".to_string())
                }));
            } else {
                panic!("Expected Map for subdoc entry");
            }
        } else {
            panic!("Expected Map for subdocs");
        }

        // Second update should refresh the timestamp, not duplicate the entry
        std::thread::sleep(std::time::Duration::from_millis(2));
        dwskv.update_subdoc_snapshot("subdoc-abc", vec![4, 5, 6]);

        let metadata = dwskv.sync_kv().get_metadata().unwrap();
        let subdocs = metadata.get("subdocs").unwrap();
        if let ciborium::value::Value::Map(entries) = subdocs {
            assert_eq!(entries.len(), 1);
            if let ciborium::value::Value::Map(fields) = &entries[0].1 {
                let snapshot = fields
                    .iter()
                    .find(|(k, _)| *k == ciborium::value::Value::Text("snapshot".to_string()))
                    .unwrap();
                assert_eq!(snapshot.1, ciborium::value::Value::Bytes(vec![4, 5, 6]));
            }
        } else {
            panic!("Expected Map");
        }
    }

    #[tokio::test]
    async fn test_subdoc_snapshot_update_drops_legacy_state_vector() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("parent_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "subdocs".to_string(),
            ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("subdoc-abc".to_string()),
                ciborium::value::Value::Map(vec![
                    (
                        ciborium::value::Value::Text("state_vector".to_string()),
                        ciborium::value::Value::Bytes(vec![1, 2, 3]),
                    ),
                    (
                        ciborium::value::Value::Text("snapshot".to_string()),
                        ciborium::value::Value::Bytes(vec![4, 5, 6]),
                    ),
                    (
                        ciborium::value::Value::Text("last_seen".to_string()),
                        ciborium::value::Value::Integer(123.into()),
                    ),
                    (
                        ciborium::value::Value::Text("last_query".to_string()),
                        ciborium::value::Value::Integer(456.into()),
                    ),
                ]),
            )]),
        );
        dwskv.sync_kv().set_metadata(metadata);

        dwskv.update_subdoc_snapshot("subdoc-abc", vec![7, 8, 9]);

        let metadata = dwskv.sync_kv().get_metadata().unwrap();
        let subdocs = metadata.get("subdocs").unwrap();
        if let ciborium::value::Value::Map(entries) = subdocs {
            if let ciborium::value::Value::Map(fields) = &entries[0].1 {
                assert_eq!(
                    fields
                        .iter()
                        .find(|(k, _)| {
                            *k == ciborium::value::Value::Text("snapshot".to_string())
                        })
                        .unwrap()
                        .1,
                    ciborium::value::Value::Bytes(vec![7, 8, 9])
                );
                assert!(fields
                    .iter()
                    .any(|(k, _)| *k == ciborium::value::Value::Text("last_edit".to_string())));
                assert!(fields
                    .iter()
                    .any(|(k, _)| *k == ciborium::value::Value::Text("last_query".to_string())));
                assert!(fields.iter().all(|(k, _)| {
                    *k != ciborium::value::Value::Text("state_vector".to_string())
                        && *k != ciborium::value::Value::Text("last_seen".to_string())
                }));
            } else {
                panic!("Expected subdoc metadata map");
            }
        } else {
            panic!("Expected subdocs map");
        }
    }

    #[tokio::test]
    async fn test_register_client_id_basic() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("test_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        // First registration should return true.
        assert!(dwskv.register_client_id("alice", 12345));

        // Duplicate registration should return false.
        assert!(!dwskv.register_client_id("alice", 12345));

        // Different client_id for same user should return true.
        assert!(dwskv.register_client_id("alice", 67890));

        // Verify the "users" map structure via a read txn.
        let awareness = dwskv.awareness();
        let awareness_guard = awareness.read().unwrap();
        let doc = &awareness_guard.doc;
        let users_map = doc.get_or_insert_map("users");
        let txn = doc.transact();

        let alice = users_map.get(&txn, "alice").unwrap();
        if let Out::YMap(user_map) = alice {
            let ids = user_map.get(&txn, "ids").unwrap();
            if let Out::YArray(ids_arr) = ids {
                let items: Vec<i64> = ids_arr
                    .iter(&txn)
                    .filter_map(|item| match item {
                        Out::Any(yrs::Any::Number(n)) => Some(n as i64),
                        Out::Any(yrs::Any::BigInt(n)) => Some(n),
                        _ => None,
                    })
                    .collect();
                assert_eq!(items, vec![12345i64, 67890i64]);
            } else {
                panic!("Expected YArray for ids");
            }
        } else {
            panic!("Expected YMap for user entry");
        }
    }

    #[tokio::test]
    async fn test_register_client_id_multiple_users() {
        let store = MemoryStore::default();
        let dwskv = DocWithSyncKv::new("test_doc", Some(Arc::new(Box::new(store))), || (), None)
            .await
            .unwrap();

        assert!(dwskv.register_client_id("alice", 111));
        assert!(dwskv.register_client_id("bob", 222));
        assert!(dwskv.register_client_id("alice", 333));

        let awareness = dwskv.awareness();
        let awareness_guard = awareness.read().unwrap();
        let doc = &awareness_guard.doc;
        let users_map = doc.get_or_insert_map("users");
        let txn = doc.transact();

        // Alice should have 2 client_ids.
        if let Some(Out::YMap(alice_map)) = users_map.get(&txn, "alice") {
            if let Some(Out::YArray(ids)) = alice_map.get(&txn, "ids") {
                assert_eq!(ids.len(&txn), 2);
            } else {
                panic!("Expected ids array for alice");
            }
        } else {
            panic!("Expected user map for alice");
        }

        // Bob should have 1 client_id.
        if let Some(Out::YMap(bob_map)) = users_map.get(&txn, "bob") {
            if let Some(Out::YArray(ids)) = bob_map.get(&txn, "ids") {
                assert_eq!(ids.len(&txn), 1);
            } else {
                panic!("Expected ids array for bob");
            }
        } else {
            panic!("Expected user map for bob");
        }
    }
}
