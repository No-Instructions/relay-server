//! Read-only triage of persisted documents, before yrs can discard broken items.
//!
//! v1 stores string clock lengths implicitly as UTF-16 content lengths. A saved
//! state vector provides an independent aggregate clock check, but per-item
//! pre-serialization lengths cannot be recovered. GC blocks have no parent;
//! GC alongside a root text is a candidate for review, not proof of corruption
//! (deleted nested types can legitimately produce GC in the same document).

use crate::doc_inspect::{decode_v1_item_parents, parse_ysweet_bytes, DecodedItemMeta};
use anyhow::{anyhow, Result};
use std::collections::{BTreeMap, HashMap};
use yrs::{updates::decoder::Decode, StateVector};

#[derive(Debug, Default)]
pub struct DamageReport {
    pub self_anchored: bool,
    pub clock_mismatch: bool,
    pub gc_with_root_text: bool,
}

impl DamageReport {
    pub fn is_candidate(&self) -> bool {
        self.self_anchored || self.clock_mismatch || self.gc_with_root_text
    }
}

/// Inspect raw v1 structs without applying, repairing or re-encoding them.
/// No document text is included in results or errors.
pub fn scan_update(bytes: &[u8]) -> Result<DamageReport> {
    let items = decode_v1_item_parents(bytes).map_err(|_| anyhow!("invalid v1 update"))?;
    Ok(inspect_items(&items))
}

fn inspect_items(items: &[DecodedItemMeta]) -> DamageReport {
    let mut result = DamageReport::default();
    for item in items {
        for (client, clock) in [item.origin, item.right_origin].into_iter().flatten() {
            if client == item.client && clock >= item.clock && clock - item.clock < item.len {
                result.self_anchored = true;
            }
        }
    }
    // An explicit root string proves a text sequence exists. Other strings may
    // inherit that root via origins; follow those without loading a broken Doc.
    let mut roots: Vec<bool> = items
        .iter()
        .map(|i| i.parent_named.is_some() && i.parent_sub.is_none())
        .collect();
    // Range lookup avoids expanding long strings into one entry per clock.
    let mut ranges = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        ranges.entry((item.client, item.clock)).or_insert(index);
    }
    let mut dependents = vec![Vec::new(); items.len()];
    for (index, item) in items.iter().enumerate() {
        if item.parent_id.is_some() || item.parent_sub.is_some() {
            continue;
        }
        for (client, clock) in [item.origin, item.right_origin].into_iter().flatten() {
            if let Some((_, &parent)) = ranges.range(..=(client, clock)).next_back() {
                let other = &items[parent];
                if other.client == client && clock >= other.clock && clock - other.clock < other.len
                {
                    dependents[parent].push(index);
                }
            }
        }
    }
    let mut queue: Vec<_> = roots
        .iter()
        .enumerate()
        .filter_map(|(i, root)| root.then_some(i))
        .collect();
    while let Some(parent) = queue.pop() {
        for &child in &dependents[parent] {
            if !roots[child] {
                roots[child] = true;
                queue.push(child);
            }
        }
    }
    result.gc_with_root_text = items.iter().any(|i| i.content_ref == 0)
        && items
            .iter()
            .zip(roots)
            .any(|(i, root)| root && i.content_ref == 4);
    result
}

pub fn scan_ysweet(bytes: &[u8]) -> Result<DamageReport> {
    let map = parse_ysweet_bytes(bytes).map_err(|_| anyhow!("invalid ysweet envelope"))?;
    scan_map(&map)
}

fn scan_map(map: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<DamageReport> {
    let mut report = DamageReport::default();
    let mut documents: HashMap<&[u8], Vec<DecodedItemMeta>> = HashMap::new();
    for (key, bytes) in map {
        if key.len() < 7 || key[..2] != [0, 1] || !matches!(key[6], 0 | 2) {
            continue;
        }
        let items =
            decode_v1_item_parents(bytes).map_err(|_| anyhow!("invalid stored v1 update"))?;
        if key[6] == 0 {
            let mut sv_key = key.clone();
            sv_key[6] = 1;
            if let Some(sv_bytes) = map.get(&sv_key) {
                let sv = StateVector::decode_v1(sv_bytes)
                    .map_err(|_| anyhow!("invalid stored state vector"))?;
                let mut ends = HashMap::<u64, u32>::new();
                for item in &items {
                    ends.entry(item.client)
                        .and_modify(|end| *end = (*end).max(item.clock + item.len))
                        .or_insert(item.clock + item.len);
                }
                // Full-state encoding includes pending structs that are absent
                // from the integrated state vector. Extra encoded clocks are
                // therefore valid; only a vector claiming missing clocks is a
                // provable inconsistency in the persisted aggregate lengths.
                report.clock_mismatch |= sv
                    .iter()
                    .any(|(client, &end)| ends.get(&client.get()).copied().unwrap_or(0) < end);
            }
        }
        documents.entry(&key[..6]).or_default().extend(items);
    }
    if documents.is_empty() {
        return Err(anyhow!("no document updates in envelope"));
    }
    for items in documents.values() {
        let found = inspect_items(items);
        report.self_anchored |= found.self_anchored;
        report.gc_with_root_text |= found.gc_with_root_text;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{Doc, ReadTxn, Text, Transact};

    fn text_state() -> Vec<u8> {
        let doc = Doc::with_client_id(5);
        doc.get_or_insert_text("contents")
            .insert(&mut doc.transact_mut(), 0, "a🚀b");
        let state = doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        state
    }

    #[test]
    fn valid_unicode_uses_utf16_clocks() {
        let state = text_state();
        assert!(!scan_update(&state).unwrap().is_candidate());
        let mut sv = StateVector::default();
        sv.set_max(yrs::block::ClientID::new(5), 4);
        use yrs::updates::encoder::Encode;
        let mut map = BTreeMap::from([
            (vec![0, 1, 0, 0, 0, 1, 0], state),
            (vec![0, 1, 0, 0, 0, 1, 1], sv.encode_v1()),
        ]);
        assert!(!scan_map(&map).unwrap().is_candidate());
        sv.set_max(yrs::block::ClientID::new(5), 5);
        map.insert(vec![0, 1, 0, 0, 0, 1, 1], sv.encode_v1());
        assert!(scan_map(&map).unwrap().clock_mismatch);
        let bytes = bincode::serialize(&map).unwrap();
        assert!(scan_ysweet(&bytes).unwrap().clock_mismatch);
    }

    #[test]
    fn reads_cbor_envelopes_without_loading_a_doc() {
        use ciborium::value::Value::{Bytes, Integer, Map, Null, Text};
        let envelope = Map(vec![
            (Text("version".into()), Integer(1.into())),
            (Text("created_at".into()), Integer(0.into())),
            (Text("modified_at".into()), Integer(0.into())),
            (Text("metadata".into()), Null),
            (
                Text("data".into()),
                Map(vec![(
                    Bytes(vec![0, 1, 0, 0, 0, 1, 0]),
                    Bytes(text_state()),
                )]),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&envelope, &mut bytes).unwrap();
        assert!(!scan_ysweet(&bytes).unwrap().is_candidate());
    }

    #[test]
    fn pending_updates_do_not_look_like_clock_damage() {
        use yrs::updates::encoder::Encode;
        let pending = vec![1, 1, 5, 1, 132, 5, 0, 1, b'b', 0];
        let map = BTreeMap::from([
            (vec![0, 1, 0, 0, 0, 1, 0], pending),
            (
                vec![0, 1, 0, 0, 0, 1, 1],
                StateVector::default().encode_v1(),
            ),
        ]);
        assert!(!scan_map(&map).unwrap().is_candidate());
    }

    #[test]
    fn self_anchor_and_gc_are_seen_before_integration() {
        // One item at client 5 clock 0 whose origin is itself.
        let update = [1, 1, 5, 0, 132, 5, 0, 1, b'x', 0];
        assert!(scan_update(&update).unwrap().self_anchored);
        let mut state = text_state();
        state[1] = 2; // append a GC block to the client's struct sequence
        state.pop(); // delete-set count
        state.extend_from_slice(&[0, 1, 0]); // GC length 1; empty delete set
        assert!(scan_update(&state).unwrap().gc_with_root_text);
        assert!(
            !scan_update(&[1, 1, 5, 0, 0, 1, 0])
                .unwrap()
                .gc_with_root_text
        );
    }

    #[test]
    fn supports_full_width_client_ids_and_rejects_bad_input() {
        let doc = Doc::with_client_id(1_u64 << 40);
        doc.get_or_insert_text("contents")
            .insert(&mut doc.transact_mut(), 0, "🚀");
        let state = doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        assert!(!scan_update(&state).unwrap().is_candidate());
        assert!(scan_update(&[1]).is_err());
        assert!(scan_ysweet(b"invalid").is_err());
    }
}
