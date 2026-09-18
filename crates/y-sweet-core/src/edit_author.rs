//! Identify who produced an update.
//!
//! The event callback's captured user describes whichever connection first
//! loaded the doc, not the edit in hand, so it reads `-` forever on any doc
//! first opened without a user token. The doc itself holds the truth:
//! `register_new_client_ids` records client_id -> user in the PermanentUserData
//! `users` map from each connection's authenticated identity, and an update
//! names the clients it came from.
//!
//! Three traps in reading those client ids:
//!
//! 1. Use `Update::state_vector_lower`, never `state_vector`. The latter is an
//!    upper bound over blocks contiguous from clock 0, so it drops any client
//!    whose first block in the update has a nonzero clock - which is every
//!    update after a client's first. It looks correct against a freshly-created
//!    test doc and returns empty for most real traffic.
//! 2. Insertions and deletions live in different places. A deletion creates no
//!    blocks, so a delete-only update has an empty state vector by any measure;
//!    its delete set is the only client information it carries.
//! 3. Delete-set client ids name the owners of the *deleted* blocks - whoever
//!    wrote what was removed - never the client doing the removing. A pure
//!    deletion carries no authorship at all, so the deleting client is
//!    unknowable from the update. Attributing the delete-set owner as the actor
//!    misattributes every removal of someone else's entry: one person's 16-file
//!    cleanup sweep was logged as three different users, each the entry's last
//!    writer (observed 2026-08-14).
//!
//! Trap 3 is why actors and deleted-entry owners are separate lookups here:
//! `user_for_update` names the actor and reports none for pure deletions,
//! while `deleted_entries_user` names whose entries were removed.

use std::collections::{HashMap, HashSet};
use yrs::updates::decoder::Decode;
use yrs::{ReadTxn, Transact, Update};

/// Reverse the PUD "users" map (user -> {ids: [client_id]}) into client -> user.
fn _user_by_client<T: ReadTxn>(txn: &T) -> HashMap<u64, String> {
    crate::permanent_user_data::user_by_client(txn)
}

/// Clients that wrote new blocks in `update`: the actors behind it.
fn _insert_clients(update: &Update) -> HashSet<u64> {
    update
        .state_vector_lower()
        .iter()
        .map(|(client_id, _)| client_id.get())
        .collect()
}

/// Owners of the blocks `update` deletes. NOT the deleting client (trap 3).
fn _deleted_block_clients(update: &Update) -> HashSet<u64> {
    update
        .delete_set()
        .iter()
        .map(|(client_id, _)| client_id.get())
        .collect()
}

/// The single user behind `clients`, or None.
///
/// None covers clients with no registered identity (server-authored updates,
/// connections that predate their PUD registration) and multiple distinct
/// users, which means a merged update that no single person authored - report
/// none rather than picking one arbitrarily.
fn _single_user<T: ReadTxn>(txn: &T, clients: &HashSet<u64>) -> Option<String> {
    let by_client = _user_by_client(txn);

    let users: HashSet<&String> = clients
        .iter()
        .filter_map(|client_id| by_client.get(client_id))
        .collect();

    match users.len() {
        1 => users.into_iter().next().cloned(),
        _ => None,
    }
}

/// The user whose client authored `update`, resolved through the doc's PUD map.
///
/// Only new blocks name their author, so a pure deletion resolves to None:
/// the update genuinely does not say who deleted (trap 3). A move (remove +
/// insert in one transaction) still attributes, through its inserted block.
pub fn user_for_update<T: ReadTxn>(txn: &T, update: &[u8]) -> Option<String> {
    _single_user(txn, &_insert_clients(&Update::decode_v1(update).ok()?))
}

/// The user whose entries/content `update` deletes - the owner of what was
/// removed, not the remover.
pub fn deleted_entries_user<T: ReadTxn>(txn: &T, update: &[u8]) -> Option<String> {
    _single_user(
        txn,
        &_deleted_block_clients(&Update::decode_v1(update).ok()?),
    )
}

/// The yjs client ids that authored `update`'s new blocks, ascending.
pub fn clients_in_update(update: &[u8]) -> Vec<u64> {
    let Ok(decoded) = Update::decode_v1(update) else {
        return Vec::new();
    };

    let mut ids: Vec<u64> = _insert_clients(&decoded).into_iter().collect();
    ids.sort_unstable();
    ids
}

/// True when every client named by the update - block authors and deleted-block
/// owners alike - is server-authored (53-bit yrs id, >= 2^32). PUD registration
/// writes are the main case: the server mutates the doc's `users` map under its
/// own client id, which fires `observe_update_v1` and would otherwise produce a
/// webhook for internal bookkeeping that no human produced.
pub fn is_server_only_update(update: &[u8]) -> bool {
    let Ok(decoded) = Update::decode_v1(update) else {
        return false;
    };

    let ids: HashSet<u64> = _insert_clients(&decoded)
        .into_iter()
        .chain(_deleted_block_clients(&decoded))
        .collect();
    !ids.is_empty() && ids.iter().all(|id| *id >= (1u64 << 32))
}

/// `clients_in_update`, comma-separated, or "-" when the update names none.
pub fn clients_for_update(update: &[u8]) -> String {
    _render_clients(clients_in_update(update))
}

/// The owners of `update`'s deleted blocks, comma-separated, or "-" when it
/// deletes nothing. Also the honest signal that an actorless update was a
/// deletion rather than server bookkeeping.
pub fn deleted_clients_for_update(update: &[u8]) -> String {
    let Ok(decoded) = Update::decode_v1(update) else {
        return "-".to_string();
    };

    let mut ids: Vec<u64> = _deleted_block_clients(&decoded).into_iter().collect();
    ids.sort_unstable();
    _render_clients(ids)
}

/// True when `update` removes anything.
///
/// An update that deletes carries no recoverable actor (trap 3), which is what
/// makes a captured-identity fallback unsafe there rather than merely
/// imprecise: it would name the wrong person for every removal.
pub fn update_deletes(update: &[u8]) -> bool {
    Update::decode_v1(update)
        .map(|decoded| !_deleted_block_clients(&decoded).is_empty())
        .unwrap_or(false)
}

fn _render_clients(ids: Vec<u64>) -> String {
    if ids.is_empty() {
        return "-".to_string();
    }

    ids.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
}

/// Same lookup, reading the PUD map out of the post-update snapshot the event
/// carries. Update callbacks fire while the edited doc's awareness lock is held
/// as a writer, so the live doc is not readable from there.
pub fn user_from_snapshot(snapshot: &[u8], update: &[u8]) -> Option<String> {
    let doc = _doc_from(snapshot)?;
    let txn = doc.transact();
    user_for_update(&txn, update)
}

/// `deleted_entries_user`, resolved from the event's snapshot like
/// `user_from_snapshot`.
pub fn deleted_user_from_snapshot(snapshot: &[u8], update: &[u8]) -> Option<String> {
    let doc = _doc_from(snapshot)?;
    let txn = doc.transact();
    deleted_entries_user(&txn, update)
}

fn _doc_from(snapshot: &[u8]) -> Option<yrs::Doc> {
    let doc = yrs::Doc::new();
    {
        let mut txn = doc.transact_mut();
        txn.apply_update(Update::decode_v1(snapshot).ok()?).ok()?;
    }
    Some(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{Array, Map, Text, Transact};

    fn register(doc: &yrs::Doc, user_id: &str, client_ids: &[u64]) {
        let users = doc.get_or_insert_map("users");
        let mut txn = doc.transact_mut();
        let entry = users.insert(&mut txn, user_id, yrs::MapPrelim::default());
        let ids = entry.insert(&mut txn, "ids", yrs::ArrayPrelim::default());
        for cid in client_ids {
            ids.push_back(&mut txn, *cid as f64);
        }
    }

    fn update_from(doc: &yrs::Doc, text: &str) -> Vec<u8> {
        let body = doc.get_or_insert_text("body");
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            body.push(&mut txn, text);
        }
        doc.transact().encode_state_as_update_v1(&before)
    }

    /// A second doc holding the same state as `a`, with its own client id.
    fn peer_of(a: &yrs::Doc) -> yrs::Doc {
        let full = a
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());
        let b = yrs::Doc::with_client_id(a.client_id().get() + 100);
        {
            let mut txn = b.transact_mut();
            txn.apply_update(Update::decode_v1(&full).unwrap()).unwrap();
        }
        b
    }

    #[test]
    fn resolves_the_user_whose_client_authored_the_update() {
        let doc = yrs::Doc::new();
        let update = update_from(&doc, "hello");
        register(&doc, "user-a", &[doc.client_id().get()]);

        assert_eq!(
            user_for_update(&doc.transact(), &update),
            Some("user-a".to_string())
        );
    }

    #[test]
    fn an_unregistered_client_resolves_to_none() {
        let doc = yrs::Doc::new();
        let update = update_from(&doc, "hello");
        register(&doc, "user-a", &[doc.client_id().get() + 1]);

        assert_eq!(user_for_update(&doc.transact(), &update), None);
    }

    #[test]
    fn a_doc_with_no_users_map_resolves_to_none() {
        let doc = yrs::Doc::new();
        let update = update_from(&doc, "hello");

        assert_eq!(user_for_update(&doc.transact(), &update), None);
    }

    #[test]
    fn an_update_merging_two_authors_reports_neither() {
        let a = yrs::Doc::new();
        let b = yrs::Doc::with_client_id(a.client_id().get() + 100);
        let from_a = update_from(&a, "aaa");
        let from_b = update_from(&b, "bbb");

        let merged = yrs::Doc::new();
        {
            let mut txn = merged.transact_mut();
            txn.apply_update(Update::decode_v1(&from_a).unwrap())
                .unwrap();
            txn.apply_update(Update::decode_v1(&from_b).unwrap())
                .unwrap();
        }
        let combined = merged
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());

        register(&merged, "user-a", &[a.client_id().get()]);
        register(&merged, "user-b", &[b.client_id().get()]);

        assert_eq!(user_for_update(&merged.transact(), &combined), None);
    }

    #[test]
    fn clients_in_update_names_the_author() {
        let a = yrs::Doc::new();
        let update = update_from(&a, "hello");

        assert_eq!(clients_in_update(&update), vec![a.client_id().get()]);
        assert_eq!(clients_in_update(b"not an update"), Vec::<u64>::new());
    }

    #[test]
    fn a_map_insert_still_names_its_client() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/x.md", "guid-x");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);

        assert_eq!(clients_in_update(&update), vec![doc.client_id().get()]);
    }

    /// A membership removal has no actor: deleting creates no blocks, and the
    /// delete set names the entry's author. Even when deleter == author, the
    /// update cannot say so, and reporting the author as actor is what logged
    /// one person's cleanup sweep as three other users (2026-08-14).
    #[test]
    fn a_removal_has_no_actor_and_names_the_entry_author_as_deleted() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/x.md", "guid-x");
        }
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.remove(&mut txn, "notes/x.md");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);
        register(&doc, "user-a", &[doc.client_id().get()]);

        assert_eq!(clients_in_update(&update), Vec::<u64>::new());
        assert_eq!(user_for_update(&doc.transact(), &update), None);
        assert_eq!(
            deleted_clients_for_update(&update),
            doc.client_id().get().to_string()
        );
        assert_eq!(
            deleted_entries_user(&doc.transact(), &update),
            Some("user-a".to_string())
        );
    }

    /// The production shape behind this module's trap 3: B sweeps an entry A
    /// created (a zombie cleanup). The update's only client id is A's, so an
    /// actor reading of the delete set would blame A for B's deletion.
    #[test]
    fn removing_anothers_entry_names_them_as_deleted_user_not_actor() {
        let a = yrs::Doc::new();
        let map_a = a.get_or_insert_map("filemeta_v0");
        {
            let mut txn = a.transact_mut();
            map_a.insert(&mut txn, "notes/zombie.md", "guid-z");
        }
        let b = peer_of(&a);

        let map_b = b.get_or_insert_map("filemeta_v0");
        let before = b.transact().state_vector();
        {
            let mut txn = b.transact_mut();
            map_b.remove(&mut txn, "notes/zombie.md");
        }
        let update = b.transact().encode_state_as_update_v1(&before);
        register(&b, "user-a", &[a.client_id().get()]);
        register(&b, "user-b", &[b.client_id().get()]);

        assert_eq!(user_for_update(&b.transact(), &update), None);
        assert_eq!(
            deleted_entries_user(&b.transact(), &update),
            Some("user-a".to_string()),
            "the delete set names the entry's author, which is exactly why it \
             must not be reported as the deleter"
        );
        assert_eq!(
            deleted_clients_for_update(&update),
            a.client_id().get().to_string()
        );
    }

    /// A move is remove + insert in one transaction. The inserted block names
    /// the mover, so moving someone else's entry attributes correctly - it must
    /// not be swallowed by the two-users-means-none guard.
    #[test]
    fn moving_anothers_entry_attributes_the_mover() {
        let a = yrs::Doc::new();
        let map_a = a.get_or_insert_map("filemeta_v0");
        {
            let mut txn = a.transact_mut();
            map_a.insert(&mut txn, "notes/old.md", "guid-m");
        }
        let b = peer_of(&a);

        let map_b = b.get_or_insert_map("filemeta_v0");
        let before = b.transact().state_vector();
        {
            let mut txn = b.transact_mut();
            map_b.remove(&mut txn, "notes/old.md");
            map_b.insert(&mut txn, "notes/new.md", "guid-m");
        }
        let update = b.transact().encode_state_as_update_v1(&before);
        register(&b, "user-a", &[a.client_id().get()]);
        register(&b, "user-b", &[b.client_id().get()]);

        assert_eq!(
            user_for_update(&b.transact(), &update),
            Some("user-b".to_string())
        );
        assert_eq!(
            deleted_entries_user(&b.transact(), &update),
            Some("user-a".to_string())
        );
    }

    #[test]
    fn a_later_update_still_names_its_client() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/first.md", "guid-1");
        }
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/second.md", "guid-2");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);

        assert!(
            Update::decode_v1(&update)
                .unwrap()
                .state_vector()
                .is_empty(),
            "guards the reason for state_vector_lower"
        );
        assert_eq!(clients_in_update(&update), vec![doc.client_id().get()]);

        register(&doc, "user-a", &[doc.client_id().get()]);
        assert_eq!(
            user_for_update(&doc.transact(), &update),
            Some("user-a".to_string())
        );
    }

    #[test]
    fn is_server_only_detects_53_bit_ids() {
        let server_doc = yrs::Doc::with_client_id((1u64 << 32) + 42);
        let update = update_from(&server_doc, "pud write");
        assert!(is_server_only_update(&update));

        let user_doc = yrs::Doc::with_client_id(42);
        let user_update = update_from(&user_doc, "human edit");
        assert!(!is_server_only_update(&user_update));
    }

    /// A server-side deletion of a user's blocks still involves that user's
    /// ids through the delete set, so it must not be suppressed as server-only.
    #[test]
    fn a_server_deletion_of_user_content_is_not_server_only() {
        let user = yrs::Doc::with_client_id(42);
        let map_u = user.get_or_insert_map("filemeta_v0");
        {
            let mut txn = user.transact_mut();
            map_u.insert(&mut txn, "notes/x.md", "guid-x");
        }
        let full = user
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());
        let server = yrs::Doc::with_client_id((1u64 << 32) + 1);
        {
            let mut txn = server.transact_mut();
            txn.apply_update(Update::decode_v1(&full).unwrap()).unwrap();
        }
        let map_s = server.get_or_insert_map("filemeta_v0");
        let before = server.transact().state_vector();
        {
            let mut txn = server.transact_mut();
            map_s.remove(&mut txn, "notes/x.md");
        }
        let update = server.transact().encode_state_as_update_v1(&before);

        assert!(!is_server_only_update(&update));
    }

    #[test]
    fn mixed_server_and_user_ids_is_not_server_only() {
        let user = yrs::Doc::with_client_id(42);
        let server = yrs::Doc::with_client_id((1u64 << 32) + 1);
        let from_user = update_from(&user, "user");
        let from_server = update_from(&server, "server");

        let merged = yrs::Doc::new();
        {
            let mut txn = merged.transact_mut();
            txn.apply_update(Update::decode_v1(&from_user).unwrap())
                .unwrap();
            txn.apply_update(Update::decode_v1(&from_server).unwrap())
                .unwrap();
        }
        let combined = merged
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());

        assert!(!is_server_only_update(&combined));
    }

    #[test]
    fn clients_for_update_formats_as_comma_separated() {
        let a = yrs::Doc::new();
        let update = update_from(&a, "hello");

        assert_eq!(clients_for_update(&update), a.client_id().get().to_string());
        assert_eq!(clients_for_update(b"not an update"), "-");
    }
}
