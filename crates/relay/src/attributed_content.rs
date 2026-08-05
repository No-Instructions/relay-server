//! Per-span authorship of a doc's current text content.
//!
//! Every yjs item structurally carries the client ID that created it, and the
//! server-driven PUD "users" map records which user each client ID belongs to.
//! Combining the two attributes every surviving character of a text root to a
//! user - the basis for per-author git commits downstream (git-sync).

use std::collections::HashMap;

use serde::Serialize;
use yrs::types::text::YChange;
use yrs::updates::decoder::Decode;
use yrs::{Array, GetString, Map, Out, ReadTxn, Snapshot, StateVector, Text, Transact, Update};

#[derive(Serialize, Debug, PartialEq)]
pub struct AttributedSpan {
    pub text: String,
    /// None only in the fallback case where attribution could not be computed.
    pub client_id: Option<u64>,
    pub user: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct AttributedContent {
    pub root: String,
    pub spans: Vec<AttributedSpan>,
}

/// Reverse the PUD "users" map (user -> {ids: [client_id]}) into client -> user.
fn user_by_client<T: ReadTxn>(txn: &T) -> HashMap<u64, String> {
    let mut result = HashMap::new();
    let Some(users_map) = txn.get_map("users") else {
        return result;
    };

    for (user_id, user_val) in users_map.iter(txn) {
        let Out::YMap(user_map) = user_val else {
            continue;
        };
        let Some(Out::YArray(ids_arr)) = user_map.get(txn, "ids") else {
            continue;
        };
        for item in ids_arr.iter(txn) {
            let client_id = match item {
                Out::Any(yrs::Any::Number(n)) => Some(n as u64),
                Out::Any(yrs::Any::BigInt(n)) => Some(n as u64),
                _ => None,
            };
            if let Some(cid) = client_id {
                result.insert(cid, user_id.to_string());
            }
        }
    }
    result
}

fn attributed_spans(
    doc: &yrs::Doc,
    root: &str,
    users: &HashMap<u64, String>,
) -> Vec<AttributedSpan> {
    let mut txn = doc.transact_mut();
    let text = txn.get_text(root).expect("checked by caller");

    // With hi = the current snapshot and lo = an empty one, every visible item
    // is "added" between the snapshots, so each chunk carries its item's ID.
    let current = txn.snapshot();
    let chunks = text.diff_range(
        &mut txn,
        Some(&current),
        Some(&Snapshot::default()),
        YChange::identity,
    );

    let mut spans: Vec<AttributedSpan> = Vec::new();
    for chunk in chunks {
        let piece = match &chunk.insert {
            Out::Any(yrs::Any::String(s)) => s.to_string(),
            // Embeds and nested types have no text representation here; they
            // are rare-to-absent in markdown docs.
            _ => continue,
        };
        let client_id = match &chunk.ychange {
            Some(change) => change.id.client.get(),
            None => continue,
        };
        match spans.last_mut() {
            Some(last) if last.client_id == Some(client_id) => last.text.push_str(&piece),
            _ => spans.push(AttributedSpan {
                text: piece,
                client_id: Some(client_id),
                user: users.get(&client_id).cloned(),
            }),
        }
    }
    spans
}

/// The current visible content of the named text root, split into spans by
/// authoring client, with clients resolved to users via the PUD "users" map.
/// Returns None if the doc has no such text root.
///
/// The walk runs on a throwaway clone of the doc: diff_range splits blocks in
/// place (so the live doc must not be touched), and yrs 0.26 panics with a
/// divide-by-zero in find_pivot when splitting at the current snapshot while
/// any client's stream is a single one-unit block. On that panic the clone is
/// discarded and the whole content is returned as one unattributed span.
pub fn attributed_content(doc: &yrs::Doc, root: &str) -> Option<AttributedContent> {
    let full_state = doc
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    let clone = yrs::Doc::new();
    clone
        .transact_mut()
        .apply_update(Update::decode_v1(&full_state).ok()?)
        .ok()?;

    let full_text = {
        let txn = clone.transact();
        txn.get_text(root)?.get_string(&txn)
    };
    let users = user_by_client(&clone.transact());

    let spans = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attributed_spans(&clone, root, &users)
    })) {
        Ok(spans) => spans,
        Err(_) => {
            tracing::warn!(
                root,
                "attribution walk panicked; returning unattributed content"
            );
            vec![AttributedSpan {
                text: full_text,
                client_id: None,
                user: None,
            }]
        }
    };

    Some(AttributedContent {
        root: root.to_string(),
        spans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::Doc;

    fn sync(from: &Doc, to: &Doc) {
        let sv = to.transact().state_vector();
        let update = from.transact().encode_state_as_update_v1(&sv);
        to.transact_mut()
            .apply_update(Update::decode_v1(&update).unwrap())
            .unwrap();
    }

    fn register_user(doc: &Doc, user: &str, client_id: u64) {
        let users_map = doc.get_or_insert_map("users");
        let mut txn = doc.transact_mut();
        let user_map = users_map.insert(&mut txn, user, yrs::MapPrelim::default());
        let ids = user_map.insert(&mut txn, "ids", yrs::ArrayPrelim::default());
        ids.push_back(&mut txn, yrs::Any::Number(client_id as f64));
    }

    #[test]
    fn test_two_authors_attributed_and_merged() {
        let alice = Doc::new();
        let bob = Doc::new();
        alice.get_or_insert_text("contents");
        bob.get_or_insert_text("contents");

        {
            let text = alice.get_or_insert_text("contents");
            let mut txn = alice.transact_mut();
            text.insert(&mut txn, 0, "hello world");
        }
        sync(&alice, &bob);
        {
            let text = bob.get_or_insert_text("contents");
            let mut txn = bob.transact_mut();
            text.insert(&mut txn, 5, " there,");
        }
        sync(&bob, &alice);
        register_user(&alice, "alice-user", alice.client_id().get());
        register_user(&alice, "bob-user", bob.client_id().get());

        let content = attributed_content(&alice, "contents").unwrap();
        let full: String = content.spans.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(full, "hello there, world");
        assert_eq!(content.spans.len(), 3);
        assert_eq!(content.spans[0].user.as_deref(), Some("alice-user"));
        assert_eq!(content.spans[0].text, "hello");
        assert_eq!(content.spans[1].user.as_deref(), Some("bob-user"));
        assert_eq!(content.spans[1].text, " there,");
        assert_eq!(content.spans[2].user.as_deref(), Some("alice-user"));
        assert_eq!(content.spans[2].text, " world");
    }

    #[test]
    fn test_deletion_leaves_survivors_attributed() {
        let doc = Doc::new();
        let text = doc.get_or_insert_text("contents");
        {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, "abcdef");
            text.remove_range(&mut txn, 1, 3);
        }

        let content = attributed_content(&doc, "contents").unwrap();
        let full: String = content.spans.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(full, "aef");
        assert!(content
            .spans
            .iter()
            .all(|s| s.client_id == Some(doc.client_id().get()) && s.user.is_none()));
    }

    #[test]
    fn test_missing_root_returns_none() {
        let doc = Doc::new();
        assert!(attributed_content(&doc, "contents").is_none());
    }

    #[test]
    fn test_unmapped_client_has_null_user() {
        let doc = Doc::new();
        let text = doc.get_or_insert_text("contents");
        {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, "xy");
        }
        let content = attributed_content(&doc, "contents").unwrap();
        assert_eq!(content.spans[0].user, None);
        assert_eq!(content.spans[0].client_id, Some(doc.client_id().get()));
    }

    /// yrs 0.26 panics splitting at the current snapshot when a client's whole
    /// stream is one single-unit block; the fallback returns the content
    /// unattributed instead of failing.
    #[test]
    fn test_single_unit_stream_falls_back_unattributed() {
        let doc = Doc::new();
        let text = doc.get_or_insert_text("contents");
        {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, "x");
        }
        let content = attributed_content(&doc, "contents").unwrap();
        assert_eq!(content.spans.len(), 1);
        assert_eq!(content.spans[0].text, "x");
        assert_eq!(content.spans[0].client_id, None);
    }
}
