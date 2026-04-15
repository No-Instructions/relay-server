use std::collections::HashSet;
use yrs::{Array, ArrayRef, Doc, Map, Out, Transact};

/// Compact the "users" Y-Map in a document by deduplicating `ids` arrays and
/// clearing `ds` arrays.
///
/// The "users" map stores PermanentUserData: for each user identity, a sub-map
/// with an `ids` YArray (mapping client IDs to this user) and a `ds` YArray
/// (serialized DeleteSet buffers recording which items this user deleted).
///
/// Two bugs in the upstream Yjs PermanentUserData implementation cause bloat:
///   1. Each session re-appends ALL known client IDs to `ids` (quadratic growth)
///   2. Each session re-appends delete set buffers to `ds` (unbounded growth)
///
/// This function:
///   - Deduplicates `ids` arrays (keeps unique values, preserves order)
///   - Clears `ds` arrays (delete sets are irrelevant after GC bakes deletions
///     into the document state)
///
/// Returns a `CompactionResult` describing what was changed.
pub fn compact_user_data(doc: &Doc) -> CompactionResult {
    // get_or_insert_map requires internal mut — call it before any transaction.
    let users_map = doc.get_or_insert_map("users");

    let mut result = CompactionResult::default();

    // Phase 1: read all user data under an immutable borrow of the transaction.
    // We collect the info we need so we can drop the iterator borrow before mutating.
    // Dedup work for a single ids array.
    struct IdsWork {
        arr: ArrayRef,
        original_len: u32,
        unique_ids: Vec<i64>,
    }

    // Clear work for a single ds array.
    struct DsWork {
        arr: ArrayRef,
        len: u32,
    }

    let mut ids_work: Vec<IdsWork> = Vec::new();
    let mut ds_work: Vec<DsWork> = Vec::new();

    // Phase 1: read under an immutable transaction.
    {
        let txn = doc.transact();
        for (_user_name, user_val) in users_map.iter(&txn) {
            let user_map = match &user_val {
                Out::YMap(m) => m,
                _ => continue,
            };

            if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                let original_len = ids_arr.len(&txn);
                let mut seen = HashSet::new();
                let mut unique_ids: Vec<i64> = Vec::new();

                for item in ids_arr.iter(&txn) {
                    let client_id = match &item {
                        Out::Any(yrs::Any::Number(n)) => Some(*n as i64),
                        Out::Any(yrs::Any::BigInt(n)) => Some(*n),
                        _ => None,
                    };
                    if let Some(cid) = client_id {
                        if seen.insert(cid) {
                            unique_ids.push(cid);
                        }
                    }
                }

                if (unique_ids.len() as u32) < original_len {
                    ids_work.push(IdsWork {
                        arr: ids_arr,
                        original_len,
                        unique_ids,
                    });
                }
            }

            if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                let len = ds_arr.len(&txn);
                if len > 0 {
                    ds_work.push(DsWork { arr: ds_arr, len });
                }
            }
        }
    } // txn dropped here

    if ids_work.is_empty() && ds_work.is_empty() {
        return result;
    }

    // Phase 2: apply mutations.
    let mut txn = doc.transact_mut();

    for iw in ids_work {
        result.ids_removed += (iw.original_len - iw.unique_ids.len() as u32) as usize;
        iw.arr.remove_range(&mut txn, 0, iw.original_len);
        for cid in iw.unique_ids {
            iw.arr.push_back(&mut txn, yrs::Any::Number(cid as f64));
        }
    }

    for dw in ds_work {
        result.ds_removed += dw.len as usize;
        dw.arr.remove_range(&mut txn, 0, dw.len);
    }

    result
}

#[derive(Debug, Default, Clone)]
pub struct CompactionResult {
    /// Number of duplicate client ID entries removed across all users.
    pub ids_removed: usize,
    /// Number of delete set entries removed across all users.
    pub ds_removed: usize,
}

impl CompactionResult {
    pub fn is_empty(&self) -> bool {
        self.ids_removed == 0 && self.ds_removed == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{Array, Doc, Map, Out, Transact};

    /// Helper: build a doc with a "users" map containing the given user entries.
    /// Each user gets an `ids` array (from the provided list) and a `ds` array
    /// (with the provided number of dummy buffer entries).
    fn make_doc_with_users(users: &[(&str, &[i64], usize)]) -> Doc {
        let doc = Doc::new();
        let users_map = doc.get_or_insert_map("users");

        let mut txn = doc.transact_mut();
        for (user_name, ids, ds_count) in users {
            let user_map =
                users_map.insert(&mut txn, user_name.to_string(), yrs::MapPrelim::default());
            let ids_arr = user_map.insert(&mut txn, "ids", yrs::ArrayPrelim::default());
            for &cid in *ids {
                ids_arr.push_back(&mut txn, cid);
            }
            let ds_arr = user_map.insert(&mut txn, "ds", yrs::ArrayPrelim::default());
            for _ in 0..*ds_count {
                // Push a dummy buffer (real PUD stores encoded DeleteSet bytes).
                ds_arr.push_back(&mut txn, vec![0u8; 4]);
            }
        }
        drop(txn);
        doc
    }

    /// Read back the ids array for a user as a Vec<i64>.
    fn read_ids(doc: &Doc, user_name: &str) -> Vec<i64> {
        let users_map = doc.get_or_insert_map("users");
        let txn = doc.transact();
        let mut result = Vec::new();
        if let Some(Out::YMap(user_map)) = users_map.get(&txn, user_name) {
            if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                for item in ids_arr.iter(&txn) {
                    match &item {
                        Out::Any(yrs::Any::Number(n)) => result.push(*n as i64),
                        Out::Any(yrs::Any::BigInt(n)) => result.push(*n),
                        _ => {}
                    }
                }
            }
        }
        result
    }

    /// Read back the length of the ds array for a user.
    fn read_ds_len(doc: &Doc, user_name: &str) -> u32 {
        let users_map = doc.get_or_insert_map("users");
        let txn = doc.transact();
        if let Some(Out::YMap(user_map)) = users_map.get(&txn, user_name) {
            if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                return ds_arr.len(&txn);
            }
        }
        0
    }

    #[test]
    fn test_deduplicates_ids() {
        let doc = make_doc_with_users(&[("alice", &[1, 2, 1, 3, 2, 1], 0)]);

        let result = compact_user_data(&doc);
        assert_eq!(result.ids_removed, 3);
        assert_eq!(read_ids(&doc, "alice"), vec![1, 2, 3]);
    }

    #[test]
    fn test_clears_ds() {
        let doc = make_doc_with_users(&[("alice", &[1, 2], 5)]);

        assert_eq!(read_ds_len(&doc, "alice"), 5);
        let result = compact_user_data(&doc);
        assert_eq!(result.ds_removed, 5);
        assert_eq!(read_ds_len(&doc, "alice"), 0);
        // ids should be unchanged (no duplicates).
        assert_eq!(read_ids(&doc, "alice"), vec![1, 2]);
    }

    #[test]
    fn test_noop_without_users_map() {
        let doc = Doc::new();
        let result = compact_user_data(&doc);
        assert!(result.is_empty());
    }

    #[test]
    fn test_handles_empty_arrays() {
        let doc = make_doc_with_users(&[("alice", &[], 0)]);

        let result = compact_user_data(&doc);
        assert!(result.is_empty());
        assert_eq!(read_ids(&doc, "alice"), Vec::<i64>::new());
        assert_eq!(read_ds_len(&doc, "alice"), 0);
    }

    #[test]
    fn test_multiple_users() {
        let doc = make_doc_with_users(&[("alice", &[1, 2, 1, 3], 3), ("bob", &[4, 5, 4], 2)]);

        let result = compact_user_data(&doc);
        assert_eq!(result.ids_removed, 2); // 1 from alice, 1 from bob
        assert_eq!(result.ds_removed, 5); // 3 from alice, 2 from bob
        assert_eq!(read_ids(&doc, "alice"), vec![1, 2, 3]);
        assert_eq!(read_ids(&doc, "bob"), vec![4, 5]);
    }

    #[test]
    fn test_no_duplicates_is_noop() {
        let doc = make_doc_with_users(&[("alice", &[1, 2, 3], 0)]);

        let result = compact_user_data(&doc);
        assert!(result.is_empty());
        assert_eq!(read_ids(&doc, "alice"), vec![1, 2, 3]);
    }

    #[test]
    fn test_idempotent() {
        let doc = make_doc_with_users(&[("alice", &[1, 2, 1, 3, 2], 4)]);

        let r1 = compact_user_data(&doc);
        assert_eq!(r1.ids_removed, 2);
        assert_eq!(r1.ds_removed, 4);

        // Second compaction should be a no-op.
        let r2 = compact_user_data(&doc);
        assert!(r2.is_empty());
        assert_eq!(read_ids(&doc, "alice"), vec![1, 2, 3]);
    }
}
