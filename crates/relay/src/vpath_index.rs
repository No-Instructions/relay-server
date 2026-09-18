//! Resolve a document GUID to the vault-relative path its shared folder knows
//! it by.
//!
//! Every log line the server emits carries a doc GUID and no path, which makes
//! an edit log readable only to someone who can already map GUIDs to notes.
//! The mapping exists server-side: a shared folder's `filemeta_v0` map is keyed
//! by vpath, and each value carries the child's GUID under `id`. This module
//! inverts that map and caches the result per folder.
//!
//! The cache is invalidated by the folder doc's update count rather than by
//! time, so a lookup after a rename resolves to the new path on the first
//! update that follows it.
//!
//! Both entry points run from update callbacks, which fire inside
//! `apply_update` while the edited doc's awareness lock is held as a writer.
//! A blocking read of that lock deadlocks the doc. `resolve` therefore reads
//! the *parent* folder under `try_read` and gives up rather than block, and
//! the membership diff, whose folder is the edited doc itself, reads the
//! post-update snapshot the event already carries instead of the live doc.

use std::collections::HashMap;
use std::sync::RwLock;
use y_sweet_core::doc_sync::DocWithSyncKv;
use yrs::updates::decoder::Decode;
use yrs::{Map, Out, ReadTxn, Transact};

const FILEMETA_ROOT: &str = "filemeta_v0";

/// One entry per shared folder that has seen an edit. A server hosts far fewer
/// folders than this, so the bound only matters as a backstop against folder
/// ids accumulating across evictions and reloads.
const MAX_CACHED_FOLDERS: usize = 256;

/// A folder's GUID -> vpath mapping, plus the marker identifying the folder
/// state it was built from.
struct CachedIndex {
    by_guid: HashMap<String, String>,
    built_from: FolderMarker,
}

/// Cheap stand-in for "has this folder's membership changed". The state vector
/// would be exact but costs an encode per lookup; entry count plus the folder's
/// own clock moves on any add, remove, or rename.
#[derive(PartialEq, Clone, Copy)]
struct FolderMarker {
    entries: usize,
    clock: u64,
}

pub struct VPathIndex {
    by_folder: RwLock<HashMap<String, CachedIndex>>,
    /// Last membership reported per folder, deliberately separate from
    /// `by_folder`. Adding a file writes two updates - the child doc and the
    /// folder doc - and the child arrives first, calling `resolve`, which
    /// refreshes `by_folder`. Sharing one map let that refresh overwrite the
    /// baseline the diff reads as "before", so every add reported no change.
    membership: RwLock<HashMap<String, HashMap<String, String>>>,
}

impl Default for VPathIndex {
    fn default() -> Self {
        Self {
            by_folder: RwLock::new(HashMap::new()),
            membership: RwLock::new(HashMap::new()),
        }
    }
}

fn folder_marker(folder: &DocWithSyncKv) -> Option<FolderMarker> {
    let aw = folder.awareness();
    let aw = aw.try_read().ok()?;
    let txn = aw.doc.transact();
    if !txn.root_refs().any(|(name, _)| name == FILEMETA_ROOT) {
        return None;
    }

    Some(FolderMarker {
        entries: txn
            .get_map(FILEMETA_ROOT)
            .map_or(0, |m| m.len(&txn) as usize),
        clock: txn
            .state_vector()
            .iter()
            .map(|(_, clock)| u64::from(*clock))
            .sum(),
    })
}

fn build_index(folder: &DocWithSyncKv) -> HashMap<String, String> {
    let Some(aw) = folder.awareness().try_read().ok().map(|aw| aw.doc.clone()) else {
        return HashMap::new();
    };

    let txn = aw.transact();
    index_from_txn(&txn)
}

fn index_from_txn<T: ReadTxn>(txn: &T) -> HashMap<String, String> {
    let Some(filemeta) = txn.get_map(FILEMETA_ROOT) else {
        return HashMap::new();
    };

    filemeta
        .iter(txn)
        .filter_map(|(path, value)| match value {
            Out::Any(yrs::Any::Map(fields)) => match fields.get("id") {
                Some(yrs::Any::String(guid)) => Some((guid.to_string(), path.to_string())),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Doc ids on the wire are `<relay_id>-<guid>`, but `filemeta_v0` keys its
/// entries on the bare guid. The folder's own id carries the same relay
/// prefix, so it identifies the part to drop.
///
/// Returns `doc_id` unchanged when the two share no prefix, which covers
/// single-segment ids in tests and any future unprefixed scheme.
fn strip_relay_prefix<'a>(doc_id: &'a str, folder_id: &str) -> &'a str {
    // A UUID is five dash-separated groups, so a prefixed id has ten and the
    // relay portion ends just before the sixth.
    let Some(relay_prefix) = folder_id
        .match_indices('-')
        .nth(4)
        .map(|(i, _)| &folder_id[..i])
    else {
        return doc_id;
    };

    doc_id
        .strip_prefix(relay_prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .unwrap_or(doc_id)
}

/// How a shared folder's membership changed between two observations.
#[derive(Debug, Default, PartialEq)]
pub struct MembershipDelta {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// `(from, to)`. A GUID present on both sides under different paths is a
    /// move, never a remove plus an add.
    pub moved: Vec<(String, String)>,
}

impl MembershipDelta {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.moved.is_empty()
    }
}

fn diff_membership(
    before: &HashMap<String, String>,
    after: &HashMap<String, String>,
) -> MembershipDelta {
    let mut delta = MembershipDelta::default();

    for (guid, path) in after {
        match before.get(guid) {
            None => delta.added.push(path.clone()),
            Some(prior) if prior != path => delta.moved.push((prior.clone(), path.clone())),
            Some(_) => {}
        }
    }
    for (guid, path) in before {
        if !after.contains_key(guid) {
            delta.removed.push(path.clone());
        }
    }

    // Folder walks are unordered, so sort to keep a line stable across runs.
    delta.added.sort();
    delta.removed.sort();
    delta.moved.sort();
    delta
}

impl VPathIndex {
    /// The vpath `folder` knows `doc_id` by, or None when the folder has no
    /// `filemeta_v0` yet or does not list this child.
    ///
    /// Rebuilds the folder's index when its membership marker has moved, so a
    /// caller on the update path pays a full map walk only after a change.
    pub fn resolve(&self, folder_id: &str, folder: &DocWithSyncKv, doc_id: &str) -> Option<String> {
        let doc_id = strip_relay_prefix(doc_id, folder_id);
        let marker = folder_marker(folder)?;

        if let Ok(cache) = self.by_folder.read() {
            if let Some(cached) = cache.get(folder_id) {
                if cached.built_from == marker {
                    return cached.by_guid.get(doc_id).cloned();
                }
            }
        }

        let by_guid = build_index(folder);
        let resolved = by_guid.get(doc_id).cloned();
        if let Ok(mut cache) = self.by_folder.write() {
            if cache.len() >= MAX_CACHED_FOLDERS && !cache.contains_key(folder_id) {
                cache.clear();
            }
            cache.insert(
                folder_id.to_string(),
                CachedIndex {
                    by_guid,
                    built_from: marker,
                },
            );
        }

        resolved
    }

    /// Refresh `folder_id`'s mapping and report how membership changed since
    /// the last call.
    ///
    /// Returns None the first time a folder is seen: with no prior mapping,
    /// every entry would look like an add, and reporting a folder's whole
    /// contents as new on load is worse than staying quiet.
    ///
    /// Reads the folder state from the post-update snapshot the event already
    /// carries, rather than from the live doc: this runs from an update
    /// observer, where the folder's awareness lock is held as a writer and
    /// re-reading it would deadlock.
    pub fn sync_membership_from_snapshot(
        &self,
        folder_id: &str,
        snapshot: &[u8],
    ) -> Option<MembershipDelta> {
        let doc = yrs::Doc::new();
        {
            let mut txn = doc.transact_mut();
            txn.apply_update(yrs::Update::decode_v1(snapshot).ok()?)
                .ok()?;
        }
        let txn = doc.transact();

        let marker = FolderMarker {
            entries: txn
                .get_map(FILEMETA_ROOT)
                .map_or(0, |m| m.len(&txn) as usize),
            clock: txn
                .state_vector()
                .iter()
                .map(|(_, clock)| u64::from(*clock))
                .sum(),
        };
        let by_guid = index_from_txn(&txn);

        // Diff against the membership baseline, which only this method writes.
        let mut baseline = self.membership.write().ok()?;
        let delta = baseline
            .get(folder_id)
            .map(|before| diff_membership(before, &by_guid));

        if baseline.len() >= MAX_CACHED_FOLDERS && !baseline.contains_key(folder_id) {
            baseline.clear();
        }
        baseline.insert(folder_id.to_string(), by_guid.clone());

        // Refresh the resolver cache too: this snapshot is newer than whatever
        // it holds, and a child edit that follows should see the new entry.
        if let Ok(mut cache) = self.by_folder.write() {
            if cache.len() >= MAX_CACHED_FOLDERS && !cache.contains_key(folder_id) {
                cache.clear();
            }
            cache.insert(
                folder_id.to_string(),
                CachedIndex {
                    by_guid,
                    built_from: marker,
                },
            );
        }

        delta.filter(|d| !d.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::Any;

    async fn folder_with(entries: &[(&str, &str)]) -> DocWithSyncKv {
        let folder = DocWithSyncKv::new("folder", None, || (), None)
            .await
            .unwrap();
        write_entries(&folder, entries);
        folder
    }

    fn write_entries(folder: &DocWithSyncKv, entries: &[(&str, &str)]) {
        let aw = folder.awareness();
        let aw = aw.read().unwrap();
        let map = aw.doc().get_or_insert_map(FILEMETA_ROOT);
        let mut txn = aw.doc().transact_mut();
        for (path, guid) in entries {
            map.insert(
                &mut txn,
                *path,
                Any::from(std::collections::HashMap::from([(
                    "id".to_string(),
                    Any::String((*guid).into()),
                )])),
            );
        }
    }

    /// The encoded post-update state, matching what the update observer hands
    /// the callback as `event.snapshot`.
    fn snapshot_of(folder: &DocWithSyncKv) -> Vec<u8> {
        let aw = folder.awareness();
        let aw = aw.read().unwrap();
        let txn = aw.doc().transact();
        txn.encode_state_as_update_v1(&yrs::StateVector::default())
    }

    fn remove_entry(folder: &DocWithSyncKv, path: &str) {
        let aw = folder.awareness();
        let aw = aw.read().unwrap();
        let map = aw.doc().get_or_insert_map(FILEMETA_ROOT);
        let mut txn = aw.doc().transact_mut();
        map.remove(&mut txn, path);
    }

    #[tokio::test]
    async fn resolves_a_guid_to_the_path_its_folder_lists_it_under() {
        let folder = folder_with(&[("notes/today.md", "guid-a"), ("refs/spec.md", "guid-b")]).await;

        assert_eq!(
            VPathIndex::default().resolve("folder", &folder, "guid-b"),
            Some("refs/spec.md".to_string())
        );
    }

    /// Production ids are `<relay_id>-<guid>` while filemeta_v0 is keyed on
    /// the bare guid. Resolving the wire id against that map is the real
    /// case; tests that use the same string for both never exercise it.
    #[tokio::test]
    async fn resolves_a_relay_prefixed_doc_id() {
        const RELAY: &str = "26120033-7a40-4583-809d-a1b151dddc5d";
        let guid = "d1c3dc2b-ac71-4f5c-a19b-a87ec06b6665";
        let folder = folder_with(&[("notes/prefixed.md", guid)]).await;

        assert_eq!(
            VPathIndex::default().resolve(
                &format!("{RELAY}-f8c9593b-f62b-41dc-911b-8b73cf1372c2"),
                &folder,
                &format!("{RELAY}-{guid}"),
            ),
            Some("notes/prefixed.md".to_string())
        );
    }

    #[test]
    fn strip_relay_prefix_leaves_unprefixed_ids_alone() {
        assert_eq!(strip_relay_prefix("child-doc", "parent-doc"), "child-doc");
        assert_eq!(
            strip_relay_prefix("26120033-7a40-4583-809d-a1b151dddc5d-abc", "short-id"),
            "26120033-7a40-4583-809d-a1b151dddc5d-abc",
            "a folder id with no relay prefix cannot identify one to strip"
        );
    }

    #[tokio::test]
    async fn unknown_guid_resolves_to_none() {
        let folder = folder_with(&[("notes/today.md", "guid-a")]).await;

        assert_eq!(
            VPathIndex::default().resolve("folder", &folder, "guid-missing"),
            None
        );
    }

    #[tokio::test]
    async fn folder_without_filemeta_resolves_to_none() {
        let folder = DocWithSyncKv::new("folder", None, || (), None)
            .await
            .unwrap();

        assert_eq!(
            VPathIndex::default().resolve("folder", &folder, "guid-a"),
            None
        );
    }

    #[tokio::test]
    async fn a_rename_is_picked_up_on_the_next_lookup() {
        let folder = folder_with(&[("notes/old-name.md", "guid-a")]).await;
        let index = VPathIndex::default();
        assert_eq!(
            index.resolve("folder", &folder, "guid-a"),
            Some("notes/old-name.md".to_string())
        );

        remove_entry(&folder, "notes/old-name.md");
        write_entries(&folder, &[("notes/new-name.md", "guid-a")]);

        assert_eq!(
            index.resolve("folder", &folder, "guid-a"),
            Some("notes/new-name.md".to_string()),
            "a cached index must not outlive the rename that invalidated it"
        );
    }

    #[tokio::test]
    async fn membership_reads_do_not_touch_the_live_doc_lock() {
        // Update callbacks run with the doc's awareness lock held as a writer.
        // Holding it here reproduces that: anything that reads the live doc
        // instead of the snapshot hangs the test rather than failing it.
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;
        let index = VPathIndex::default();
        let before = snapshot_of(&folder);
        index.sync_membership_from_snapshot("folder", &before);

        write_entries(&folder, &[("notes/b.md", "guid-b")]);
        let after = snapshot_of(&folder);

        let aw = folder.awareness();
        let _writer = aw.write().unwrap();

        assert_eq!(
            index.sync_membership_from_snapshot("folder", &after),
            Some(MembershipDelta {
                added: vec!["notes/b.md".to_string()],
                ..Default::default()
            })
        );
    }

    #[tokio::test]
    async fn first_sight_of_a_folder_reports_no_delta() {
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;

        assert_eq!(
            VPathIndex::default().sync_membership_from_snapshot("folder", &snapshot_of(&folder)),
            None
        );
    }

    #[tokio::test]
    async fn an_unchanged_folder_reports_no_delta() {
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;
        let index = VPathIndex::default();
        index.sync_membership_from_snapshot("folder", &snapshot_of(&folder));

        assert_eq!(
            index.sync_membership_from_snapshot("folder", &snapshot_of(&folder)),
            None
        );
    }

    #[tokio::test]
    async fn a_new_file_is_reported_as_an_add() {
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;
        let index = VPathIndex::default();
        index.sync_membership_from_snapshot("folder", &snapshot_of(&folder));

        write_entries(&folder, &[("notes/b.md", "guid-b")]);

        assert_eq!(
            index.sync_membership_from_snapshot("folder", &snapshot_of(&folder)),
            Some(MembershipDelta {
                added: vec!["notes/b.md".to_string()],
                ..Default::default()
            })
        );
    }

    #[tokio::test]
    async fn a_deleted_file_is_reported_as_a_remove() {
        let folder = folder_with(&[("notes/a.md", "guid-a"), ("notes/b.md", "guid-b")]).await;
        let index = VPathIndex::default();
        index.sync_membership_from_snapshot("folder", &snapshot_of(&folder));

        remove_entry(&folder, "notes/b.md");

        assert_eq!(
            index.sync_membership_from_snapshot("folder", &snapshot_of(&folder)),
            Some(MembershipDelta {
                removed: vec!["notes/b.md".to_string()],
                ..Default::default()
            })
        );
    }

    #[tokio::test]
    async fn a_move_is_not_reported_as_a_delete_plus_an_add() {
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;
        let index = VPathIndex::default();
        index.sync_membership_from_snapshot("folder", &snapshot_of(&folder));

        remove_entry(&folder, "notes/a.md");
        write_entries(&folder, &[("archive/a.md", "guid-a")]);

        assert_eq!(
            index.sync_membership_from_snapshot("folder", &snapshot_of(&folder)),
            Some(MembershipDelta {
                moved: vec![("notes/a.md".to_string(), "archive/a.md".to_string())],
                ..Default::default()
            })
        );
    }

    #[tokio::test]
    async fn an_added_sibling_invalidates_the_cache() {
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;
        let index = VPathIndex::default();
        assert_eq!(index.resolve("folder", &folder, "guid-b"), None);

        write_entries(&folder, &[("notes/b.md", "guid-b")]);

        assert_eq!(
            index.resolve("folder", &folder, "guid-b"),
            Some("notes/b.md".to_string())
        );
    }

    /// The production interleaving: a child edit calls resolve() between two
    /// folder edits. resolve() refreshes the same cache the membership diff
    /// reads as its "before", so an add can be erased before it is ever
    /// reported.
    #[tokio::test]
    async fn a_resolve_between_folder_edits_must_not_swallow_the_add() {
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;
        let index = VPathIndex::default();
        index.sync_membership_from_snapshot("folder", &snapshot_of(&folder));

        // A file appears: the folder gains an entry, and the new child doc
        // gets edited too - which is what calls resolve().
        write_entries(&folder, &[("notes/b.md", "guid-b")]);
        index.resolve("folder", &folder, "guid-b");

        assert_eq!(
            index.sync_membership_from_snapshot("folder", &snapshot_of(&folder)),
            Some(MembershipDelta {
                added: vec!["notes/b.md".to_string()],
                ..Default::default()
            }),
            "resolve() must not consume the baseline the membership diff needs"
        );
    }

    /// `event.snapshot` is `txn.snapshot().encode_v1()` - a yrs Snapshot
    /// (state vector + delete set), not a document update. Decoding it as an
    /// update yields an empty doc, so the membership diff has been reading an
    /// empty filemeta map the whole time.
    #[tokio::test]
    async fn a_yrs_snapshot_is_not_a_document_update() {
        use yrs::updates::encoder::Encode;
        let folder = folder_with(&[("notes/a.md", "guid-a")]).await;

        let (as_snapshot, as_update) = {
            let aw = folder.awareness();
            let aw = aw.read().unwrap();
            let txn = aw.doc().transact();
            (
                txn.snapshot().encode_v1(),
                txn.encode_state_as_update_v1(&yrs::StateVector::default()),
            )
        };

        let index = VPathIndex::default();
        index.sync_membership_from_snapshot("folder", &as_update);
        assert_eq!(
            index
                .membership
                .read()
                .unwrap()
                .get("folder")
                .map(|m| m.len()),
            Some(1),
            "a real update carries the filemeta entries"
        );

        let from_snapshot = VPathIndex::default();
        from_snapshot.sync_membership_from_snapshot("folder", &as_snapshot);
        // Decoding a Snapshot as an update fails outright, so the method
        // returns early and never records a baseline at all.
        assert_eq!(
            from_snapshot
                .membership
                .read()
                .unwrap()
                .get("folder")
                .map(|m| m.len()),
            None,
            "a yrs Snapshot is not decodable as an update, which is what production passes"
        );
    }
}
