use anyhow::Result;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};

// -- Public bytes-based entry points --
//
// All three modes operate on already-loaded `.ysweet` bytes. The `label`
// is what we display to the user (a file path, an S3 key, etc.). Use
// these from any caller — store-backed or file-backed — without
// coupling the inspection logic to a filesystem.

pub fn run_info(label: &str, bytes: &[u8], show_keys: bool) -> Result<()> {
    dump_ysweet_bytes(label, bytes, show_keys)
}

pub fn run_users(label: &str, bytes: &[u8]) -> Result<()> {
    dump_users_bytes(label, bytes)
}

pub fn run_history(label: &str, bytes: &[u8]) -> Result<()> {
    dump_history_bytes(label, bytes)
}

// -- Shared data structures --

/// Mirror of y_sweet_core::sync_kv::YSweetData, kept local to avoid making the original public.
#[derive(serde::Deserialize, serde::Serialize, Debug)]
struct YSweetDataDump {
    version: u32,
    created_at: u64,
    modified_at: u64,
    metadata: Option<BTreeMap<String, ciborium::value::Value>>,
    #[serde(
        deserialize_with = "deserialize_btree_dump",
        serialize_with = "serialize_btree_dump"
    )]
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn deserialize_btree_dump<'de, D>(deserializer: D) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde::Deserialize;
    let cbor_value = ciborium::value::Value::deserialize(deserializer)?;
    if let ciborium::value::Value::Map(entries) = cbor_value {
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            if let (ciborium::value::Value::Bytes(key), ciborium::value::Value::Bytes(val)) = (k, v)
            {
                map.insert(key, val);
            } else {
                return Err(D::Error::custom("expected bytes for key and value"));
            }
        }
        Ok(map)
    } else {
        Err(D::Error::custom("expected CBOR map"))
    }
}

fn serialize_btree_dump<S>(
    map: &BTreeMap<Vec<u8>, Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let cbor_entries: Vec<(ciborium::value::Value, ciborium::value::Value)> = map
        .iter()
        .map(|(k, v)| {
            (
                ciborium::value::Value::Bytes(k.clone()),
                ciborium::value::Value::Bytes(v.clone()),
            )
        })
        .collect();
    let cbor_map = ciborium::value::Value::Map(cbor_entries);
    serde::Serialize::serialize(&cbor_map, serializer)
}

// -- Shared helpers --

/// Parse `.ysweet` bytes into the KV map (tries CBOR then bincode).
pub(crate) fn parse_ysweet_bytes(bytes: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    match ciborium::de::from_reader::<YSweetDataDump, _>(bytes) {
        Ok(doc) => Ok(doc.data),
        Err(cbor_err) => match bincode::deserialize::<BTreeMap<Vec<u8>, Vec<u8>>>(bytes) {
            Ok(map) => Ok(map),
            Err(bincode_err) => {
                anyhow::bail!(
                    "Failed to parse as CBOR ({}) or bincode ({})",
                    cbor_err,
                    bincode_err
                );
            }
        },
    }
}

/// Reconstruct a yrs Doc from KV entries (doc state + pending updates).
fn load_yrs_doc(map: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<yrs::Doc> {
    use yrs::updates::decoder::Decode;
    use yrs::{Doc, Transact, Update};

    let doc_state = map
        .iter()
        .find(|(k, _)| k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0);

    let Some((_, doc_state_bytes)) = doc_state else {
        anyhow::bail!("No doc state entry found in KV data");
    };

    let doc = Doc::new();

    let update = Update::decode_v1(doc_state_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode doc state: {}", e))?;
    {
        let mut txn = doc.transact_mut();
        let _ = txn.apply_update(update);
    }

    // Apply pending updates
    for (k, v) in map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 2 {
            if let Ok(update) = Update::decode_v1(v) {
                let mut txn = doc.transact_mut();
                let _ = txn.apply_update(update);
            }
        }
    }

    Ok(doc)
}

/// Build a map from client_id -> user_id by reading the "users" YMap.
fn build_client_user_map(doc: &yrs::Doc) -> HashMap<u64, String> {
    use yrs::{Array, Map, Out, Transact};

    let users_map = doc.get_or_insert_map("users");
    let txn = doc.transact();
    let mut result = HashMap::new();

    for (user_id, user_val) in users_map.iter(&txn) {
        if let Out::YMap(user_map) = &user_val {
            if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                for item in ids_arr.iter(&txn) {
                    let client_id = match &item {
                        Out::Any(yrs::Any::Number(n)) => Some(*n as u64),
                        Out::Any(yrs::Any::BigInt(n)) => Some(*n as u64),
                        _ => None,
                    };
                    if let Some(cid) = client_id {
                        result.insert(cid, user_id.to_string());
                    }
                }
            }
        }
    }

    result
}

/// Convert a yrs Out value to a serde_json::Value.
fn out_to_json(out: &yrs::Out, txn: &yrs::Transaction) -> serde_json::Value {
    use yrs::{GetString, Map, Out};

    match out {
        Out::Any(any) => any_to_json(any),
        Out::YText(t) => json!(t.get_string(txn)),
        Out::YMap(m) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in m.iter(txn) {
                obj.insert(k.to_string(), out_to_json(&v, txn));
            }
            serde_json::Value::Object(obj)
        }
        Out::YArray(a) => {
            use yrs::Array;
            let arr: Vec<serde_json::Value> = a.iter(txn).map(|v| out_to_json(&v, txn)).collect();
            serde_json::Value::Array(arr)
        }
        _ => json!(format!("{:?}", out)),
    }
}

/// Convert a yrs::Any to serde_json::Value.
fn any_to_json(any: &yrs::Any) -> serde_json::Value {
    match any {
        yrs::Any::Null | yrs::Any::Undefined => serde_json::Value::Null,
        yrs::Any::Bool(b) => json!(b),
        yrs::Any::Number(n) => json!(n),
        yrs::Any::BigInt(n) => json!(n),
        yrs::Any::String(s) => json!(s.as_ref()),
        yrs::Any::Buffer(buf) => json!(format!("<buffer {} bytes>", buf.len())),
        yrs::Any::Array(arr) => {
            let items: Vec<serde_json::Value> = arr.iter().map(any_to_json).collect();
            serde_json::Value::Array(items)
        }
        yrs::Any::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map.iter() {
                obj.insert(k.to_string(), any_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
    }
}

// -- dump-doc users --

/// Data collected from PUD under a single transaction.
struct PudUserData {
    user_id: String,
    ids_total: u32,
    ids_unique: usize,
    ds_entries: u32,
    ds_decoded: u32,
    ds_total_ops: u64,
}

fn dump_users_bytes(_label: &str, bytes: &[u8]) -> Result<()> {
    use yrs::updates::decoder::Decode;
    use yrs::{Array, Doc, Map, Out, ReadTxn, StateVector, Transact, Update};

    let kv = parse_ysweet_bytes(bytes)?;
    let doc = load_yrs_doc(&kv)?;
    let client_user_map = build_client_user_map(&doc);

    // -- Phase 1: collect everything under read transactions --

    // get_or_insert_map needs a mut transaction internally, do it before the read txn
    let users_map = doc.get_or_insert_map("users");

    let txn = doc.transact();
    let sv = txn.state_vector();

    // Group client_ids by user
    let mut user_clients: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut unmapped_clients: Vec<u64> = Vec::new();

    for (&client_id, _) in sv.iter() {
        let client_id = client_id.get();
        match client_user_map.get(&client_id) {
            Some(user_id) => {
                user_clients
                    .entry(user_id.clone())
                    .or_default()
                    .push(client_id);
            }
            None => {
                unmapped_clients.push(client_id);
            }
        }
    }

    // Per-client delete set stats
    let snapshot = txn.snapshot();
    let ds = &snapshot.delete_set;
    let mut client_deleted: HashMap<u64, u64> = HashMap::new();
    for (&cid, ranges) in ds.iter() {
        let mut total = 0u64;
        for r in ranges.iter() {
            total += (r.end - r.start) as u64;
        }
        client_deleted.insert(cid.get(), total);
    }

    let full_update = txn.encode_state_as_update_v1(&StateVector::default());
    let full_size = full_update.len();

    // Collect PUD array stats under one transaction
    let mut pud_data: Vec<PudUserData> = Vec::new();
    let user_ids: Vec<String> = users_map.keys(&txn).map(|k| k.to_string()).collect();

    for user_id in &user_ids {
        if let Some(Out::YMap(user_map)) = users_map.get(&txn, user_id) {
            let mut data = PudUserData {
                user_id: user_id.clone(),
                ids_total: 0,
                ids_unique: 0,
                ds_entries: 0,
                ds_decoded: 0,
                ds_total_ops: 0,
            };

            if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                data.ids_total = ids_arr.len(&txn);
                let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
                for item in ids_arr.iter(&txn) {
                    match &item {
                        Out::Any(yrs::Any::Number(n)) => {
                            seen.insert(*n as u64);
                        }
                        Out::Any(yrs::Any::BigInt(n)) => {
                            seen.insert(*n as u64);
                        }
                        _ => {}
                    }
                }
                data.ids_unique = seen.len();
            }

            if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                data.ds_entries = ds_arr.len(&txn);
                for item in ds_arr.iter(&txn) {
                    if let Out::Any(yrs::Any::Buffer(buf)) = &item {
                        use yrs::encoding::read::Cursor;
                        use yrs::updates::decoder::DecoderV1;
                        let cursor = Cursor::new(buf.as_ref());
                        let mut decoder = DecoderV1::new(cursor);
                        if let Ok(decoded_ds) = yrs::IdSet::decode(&mut decoder) {
                            data.ds_decoded += 1;
                            for (_, ranges) in decoded_ds.iter() {
                                for r in ranges.iter() {
                                    data.ds_total_ops += (r.end - r.start) as u64;
                                }
                            }
                        }
                    }
                }
            }

            pud_data.push(data);
        }
    }
    drop(txn);

    // -- Phase 2: compute diffs and content per user (no held transaction) --

    let content_snapshot = doc_content_snapshot_filtered(&doc, &["users"]);
    let content_bytes = json_byte_size(&content_snapshot);
    let users_snapshot = doc_content_snapshot_filtered(&doc, &[]);
    let users_root_bytes = if let serde_json::Value::Object(ref map) = users_snapshot {
        map.get("users").map(json_byte_size).unwrap_or(0)
    } else {
        0
    };

    let mut users_json = Vec::new();

    for pud in &pud_data {
        let client_ids_for_user = user_clients.get(&pud.user_id).cloned().unwrap_or_default();

        // Ops stats
        let mut total_user_ops = 0u32;
        let mut total_user_deleted = 0u64;
        {
            let txn = doc.transact();
            let sv = txn.state_vector();
            for &cid in &client_ids_for_user {
                let clk = sv
                    .iter()
                    .find(|(&c, _)| c.get() == cid)
                    .map(|(_, &clk)| clk)
                    .unwrap_or(0);
                total_user_ops += clk;
                if let Some(&del) = client_deleted.get(&cid) {
                    total_user_deleted += del;
                }
            }
        }

        // Content contribution (diff excluding metadata)
        let txn = doc.transact();
        let sv = txn.state_vector();
        let mut sv_without = StateVector::default();
        for (&c, &clk) in sv.iter() {
            if !client_ids_for_user.contains(&c.get()) {
                sv_without.set_max(c, clk);
            }
        }
        let diff = txn.encode_diff_v1(&sv_without);
        let diff_bytes = diff.len();
        drop(txn);

        let user_doc = Doc::new();
        if let Ok(update) = Update::decode_v1(&diff) {
            let mut utxn = user_doc.transact_mut();
            let _ = utxn.apply_update(update);
        }
        let user_content = doc_content_snapshot_filtered(&user_doc, &["users"]);
        let user_content_bytes = json_byte_size(&user_content);

        let mut user_entry = serde_json::Map::new();
        user_entry.insert("user_id".to_string(), json!(&pud.user_id));
        user_entry.insert("sessions".to_string(), json!(client_ids_for_user.len()));
        user_entry.insert("operations".to_string(), json!(total_user_ops));
        user_entry.insert("deleted_operations".to_string(), json!(total_user_deleted));
        user_entry.insert("bytes_in_file".to_string(), json!(diff_bytes));
        user_entry.insert("content_bytes".to_string(), json!(user_content_bytes));

        // How much internal bookkeeping is stored for this user
        user_entry.insert(
            "bookkeeping".to_string(),
            json!({
                "session_records": pud.ids_total,
                "unique_sessions": pud.ids_unique,
                "deletion_records": pud.ds_entries,
            }),
        );

        if user_content_bytes > 2 {
            user_entry.insert("content".to_string(), user_content);
        }

        users_json.push(serde_json::Value::Object(user_entry));
    }

    unmapped_clients.sort();

    let output = json!({
        "file_bytes": full_size,
        "content_bytes": content_bytes,
        "bookkeeping_bytes": users_root_bytes,
        "users": users_json,
        "unmapped_sessions": unmapped_clients.len(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Snapshot document content, excluding the named roots.
fn doc_content_snapshot_filtered(doc: &yrs::Doc, exclude_roots: &[&str]) -> serde_json::Value {
    use yrs::{Array, GetString, Map, ReadTxn, Transact};

    let txn = doc.transact();
    let mut result = serde_json::Map::new();

    let root_names: Vec<String> = txn
        .root_refs()
        .map(|(name, _)| name.to_string())
        .filter(|name| !exclude_roots.contains(&name.as_str()))
        .collect();
    drop(txn);

    for name in &root_names {
        let map_ref = doc.get_or_insert_map(name.as_str());
        let txn = doc.transact();
        let len = map_ref.len(&txn);
        if len > 0 {
            let mut obj = serde_json::Map::new();
            for (k, v) in map_ref.iter(&txn) {
                obj.insert(k.to_string(), out_to_json(&v, &txn));
            }
            result.insert(name.clone(), serde_json::Value::Object(obj));
            drop(txn);
            continue;
        }
        drop(txn);

        let text_ref = doc.get_or_insert_text(name.as_str());
        let txn = doc.transact();
        let s = text_ref.get_string(&txn);
        if !s.is_empty() {
            result.insert(name.clone(), json!(s));
            drop(txn);
            continue;
        }
        drop(txn);

        let arr_ref = doc.get_or_insert_array(name.as_str());
        let txn = doc.transact();
        let arr_len = arr_ref.len(&txn);
        if arr_len > 0 {
            let items: Vec<serde_json::Value> =
                arr_ref.iter(&txn).map(|v| out_to_json(&v, &txn)).collect();
            result.insert(name.clone(), serde_json::Value::Array(items));
            drop(txn);
            continue;
        }
        drop(txn);
    }

    serde_json::Value::Object(result)
}

/// Approximate byte size of a JSON value (compact serialization).
fn json_byte_size(v: &serde_json::Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
}

// -- dump-doc history --

fn dump_history_bytes(_label: &str, bytes: &[u8]) -> Result<()> {
    use yrs::updates::decoder::Decode;
    use yrs::{Doc, Transact, Update};

    let kv = parse_ysweet_bytes(bytes)?;

    // Find the base doc state
    let doc_state = kv
        .iter()
        .find(|(k, _)| k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0);

    let Some((_, doc_state_bytes)) = doc_state else {
        anyhow::bail!("No doc state entry found in KV data");
    };

    // Collect pending updates sorted by clock
    let mut updates: Vec<(u32, &[u8])> = Vec::new();
    for (k, v) in &kv {
        if k.len() >= 11 && k[0] == 0 && k[1] == 1 && k[6] == 2 {
            let clock = u32::from_be_bytes([k[7], k[8], k[9], k[10]]);
            updates.push((clock, v.as_slice()));
        }
    }
    updates.sort_by_key(|(clock, _)| *clock);

    // Load base doc state
    let doc = Doc::new();
    let update = Update::decode_v1(doc_state_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode doc state: {}", e))?;
    {
        let mut txn = doc.transact_mut();
        let _ = txn.apply_update(update);
    }

    let client_user_map = build_client_user_map(&doc);

    let mut prev_snapshot = doc_content_snapshot_filtered(&doc, &["users"]);
    let mut entries = Vec::new();

    if updates.is_empty() {
        // Fully compacted — no individual updates to replay, just show final content
        entries.push(json!({
            "note": "fully compacted, no individual updates to replay",
            "content": prev_snapshot,
        }));
    } else {
        // Show the base state before any pending updates
        if prev_snapshot != json!({}) {
            entries.push(json!({
                "step": "base",
                "content": prev_snapshot,
            }));
        }

        // Replay each pending update and show what changed
        for (_clock, update_bytes) in &updates {
            let client_id = decode_v1_item_parents(update_bytes)
                .ok()
                .and_then(|items| items.first().map(|i| i.client));

            if let Ok(update) = Update::decode_v1(update_bytes) {
                {
                    let mut txn = doc.transact_mut();
                    let _ = txn.apply_update(update);
                }

                let new_snapshot = doc_content_snapshot_filtered(&doc, &["users"]);
                let diff = json_diff(&prev_snapshot, &new_snapshot);

                if !diff.is_null() {
                    let mut entry = serde_json::Map::new();
                    if let Some(cid) = client_id {
                        if let Some(user) = client_user_map.get(&cid) {
                            entry.insert("user".to_string(), json!(user));
                        }
                        entry.insert("session".to_string(), json!(cid));
                    }
                    entry.insert("changes".to_string(), diff);
                    entries.push(serde_json::Value::Object(entry));
                }

                prev_snapshot = new_snapshot;
            }
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Array(entries))?
    );
    Ok(())
}

/// Compute a recursive JSON diff: added/changed keys show new values, removed keys show null.
/// Returns null if no differences.
fn json_diff(old: &serde_json::Value, new: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;

    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            let mut diff = serde_json::Map::new();
            for (k, new_v) in new_map {
                match old_map.get(k) {
                    None => {
                        diff.insert(k.clone(), new_v.clone());
                    }
                    Some(old_v) if old_v != new_v => {
                        let nested = json_diff(old_v, new_v);
                        if !nested.is_null() {
                            diff.insert(k.clone(), nested);
                        }
                    }
                    _ => {}
                }
            }
            for k in old_map.keys() {
                if !new_map.contains_key(k) {
                    diff.insert(k.clone(), Value::Null);
                }
            }
            if diff.is_empty() {
                Value::Null
            } else {
                Value::Object(diff)
            }
        }
        _ if old == new => Value::Null,
        _ => new.clone(),
    }
}

// -- dump-doc info (existing text dump) --

fn dump_ysweet_bytes(label: &str, data: &[u8], show_keys: bool) -> Result<()> {
    println!("Source: {}", label);
    println!("Size: {} bytes", data.len());
    println!();

    match ciborium::de::from_reader::<YSweetDataDump, _>(data) {
        Ok(doc) => {
            println!("Format:      CBOR");
            println!("Version:     {}", doc.version);
            println!("Created at:  {}", format_timestamp_ms(doc.created_at));
            println!("Modified at: {}", format_timestamp_ms(doc.modified_at));

            if let Some(ref meta) = doc.metadata {
                println!("Metadata:    {} entries", meta.len());
                for (k, v) in meta {
                    println!("  {}: {:?}", k, v);
                }
            } else {
                println!("Metadata:    none");
            }

            println!();
            dump_kv_entries(&doc.data, show_keys);
        }
        Err(cbor_err) => match bincode::deserialize::<BTreeMap<Vec<u8>, Vec<u8>>>(data) {
            Ok(map) => {
                println!("Format:      bincode (legacy)");
                println!("(No version/timestamp/metadata in legacy format)");
                println!();
                dump_kv_entries(&map, show_keys);
            }
            Err(bincode_err) => {
                anyhow::bail!(
                    "Failed to parse as CBOR ({}) or bincode ({})",
                    cbor_err,
                    bincode_err
                );
            }
        },
    }

    Ok(())
}

fn format_timestamp_ms(ms: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = UNIX_EPOCH + Duration::from_millis(ms);
    match d.duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs();
            let naive = chrono::DateTime::from_timestamp(secs as i64, 0);
            match naive {
                Some(dt) => format!("{} ({})", dt.to_rfc3339(), ms),
                None => format!("{} ms", ms),
            }
        }
        Err(_) => format!("{} ms", ms),
    }
}

fn describe_kv_key(k: &[u8]) -> String {
    if k.len() < 2 {
        return format!("unknown ({})", hex::encode(k));
    }
    let version = k[0];
    let keyspace = k[1];
    match (version, keyspace) {
        (0, 0) => {
            if k.len() >= 3 && k[k.len() - 1] == 0 {
                let name = &k[2..k.len() - 1];
                let name_str = String::from_utf8_lossy(name);
                format!("OID mapping: \"{}\"", name_str)
            } else {
                format!("OID key (malformed): {}", hex::encode(k))
            }
        }
        (0, 1) => {
            if k.len() < 7 {
                return format!("doc key (short): {}", hex::encode(k));
            }
            let oid = u32::from_be_bytes([k[2], k[3], k[4], k[5]]);
            let sub = k[6];
            match sub {
                0 => format!("doc state (oid={})", oid),
                1 => format!("state vector (oid={})", oid),
                2 => {
                    if k.len() >= 11 {
                        let clock = u32::from_be_bytes([k[7], k[8], k[9], k[10]]);
                        format!("update (oid={}, clock={})", oid, clock)
                    } else {
                        format!("update (oid={}, malformed)", oid)
                    }
                }
                3 => {
                    let meta_name = &k[7..k.len().saturating_sub(1)];
                    let name_str = String::from_utf8_lossy(meta_name);
                    format!("metadata (oid={}, key=\"{}\")", oid, name_str)
                }
                _ => format!("doc key (oid={}, sub={}): {}", oid, sub, hex::encode(k)),
            }
        }
        _ => format!(
            "unknown (v={}, ks={}): {}",
            version,
            keyspace,
            hex::encode(k)
        ),
    }
}

fn dump_kv_entries(map: &BTreeMap<Vec<u8>, Vec<u8>>, show_keys: bool) {
    let total_key_bytes: usize = map.keys().map(|k| k.len()).sum();
    let total_val_bytes: usize = map.values().map(|v| v.len()).sum();

    let mut doc_state_size: usize = 0;
    let mut sv_size: usize = 0;
    let mut update_count: usize = 0;
    let mut update_size: usize = 0;

    for (k, v) in map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 {
            match k[6] {
                0 => doc_state_size += v.len(),
                1 => sv_size += v.len(),
                2 => {
                    update_count += 1;
                    update_size += v.len();
                }
                _ => {}
            }
        }
    }

    println!("KV entries:      {}", map.len());
    println!("Total key bytes: {}", total_key_bytes);
    println!("Total val bytes: {}", total_val_bytes);
    println!();
    println!("  Doc state:     {} bytes", doc_state_size);
    println!("  State vector:  {} bytes", sv_size);
    if update_count > 0 {
        println!("  Updates:       {} ({} bytes)", update_count, update_size);
    } else {
        println!("  Updates:       0 (fully flushed)");
    }

    if show_keys {
        println!();
        println!("All keys:");
        for (k, v) in map {
            println!(
                "  [{}] {} => {} bytes",
                hex::encode(k),
                describe_kv_key(k),
                v.len()
            );
        }
    }

    println!();
    dump_yrs_doc(map);
}

fn dump_yrs_doc(map: &BTreeMap<Vec<u8>, Vec<u8>>) {
    use yrs::updates::decoder::Decode;
    use yrs::updates::encoder::Encode;
    use yrs::{Array, Doc, GetString, Map, Out, ReadTxn, StateVector, Transact, Update};

    let doc_state = map
        .iter()
        .find(|(k, _)| k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0);

    let Some((_, doc_state_bytes)) = doc_state else {
        println!("(No doc state entry found, cannot inspect Yrs document)");
        return;
    };

    let doc = Doc::new();
    let mut loaded = false;

    match Update::decode_v1(doc_state_bytes) {
        Ok(update) => {
            let mut txn = doc.transact_mut();
            let _ = txn.apply_update(update);
            loaded = true;
        }
        Err(e) => {
            println!("(Failed to decode doc state as Yrs v1 update: {})", e);
        }
    }

    let mut updates_applied = 0;
    for (k, v) in map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 2 {
            match Update::decode_v1(v) {
                Ok(update) => {
                    let mut txn = doc.transact_mut();
                    let _ = txn.apply_update(update);
                    updates_applied += 1;
                }
                Err(e) => {
                    println!("(Failed to decode update: {})", e);
                }
            }
        }
    }

    if !loaded {
        return;
    }

    let txn = doc.transact();

    let full_update = txn.encode_state_as_update_v1(&StateVector::default());

    // Skip filemeta clock map for large docs (decode + origin resolution is O(n^2) on items)
    let filemeta_clock_map = if full_update.len() > 2_000_000 {
        println!(
            "  (skipping filemeta clock map: update is {} bytes, too large for item-level decode)",
            full_update.len()
        );
        None
    } else {
        match build_filemeta_clock_map(&full_update) {
            Ok(map) => {
                let unique_filenames: std::collections::HashSet<&str> =
                    map.values().map(|s| s.as_str()).collect();
                println!(
                    "  (decoded {} item→filename mappings across {} unique filenames)",
                    map.len(),
                    unique_filenames.len()
                );
                Some(map)
            }
            Err(e) => {
                println!(
                    "  (failed to decode update items for filename mapping: {})",
                    e
                );
                None
            }
        }
    };

    println!("Yrs document:");
    println!("  Full update size: {} bytes", full_update.len());
    if updates_applied > 0 {
        println!("  (includes {} pending updates)", updates_applied);
    }

    let sv = txn.state_vector();
    let sv_encoded = sv.encode_v1();
    let total_ops: u32 = sv.iter().map(|(_, &clock)| clock).sum();
    println!("  State vector:     {} bytes encoded", sv_encoded.len());
    println!("  Client IDs:       {}", sv.len());
    println!("  Total ops:        {}", total_ops);

    let snapshot = txn.snapshot();
    let ds = &snapshot.delete_set;
    let mut total_deleted: u64 = 0;
    let mut clients_with_deletes: usize = 0;
    for (_client, range) in ds.iter() {
        let mut client_deleted: u64 = 0;
        for r in range.iter() {
            client_deleted += (r.end - r.start) as u64;
        }
        if client_deleted > 0 {
            total_deleted += client_deleted;
            clients_with_deletes += 1;
        }
    }
    let mut doc_ds_ranges: std::collections::HashMap<u64, Vec<(u32, u32)>> =
        std::collections::HashMap::new();
    for (&client_id, ranges) in ds.iter() {
        let mut sorted: Vec<(u32, u32)> = ranges.iter().map(|r| (r.start, r.end)).collect();
        sorted.sort();
        doc_ds_ranges.insert(client_id.get(), sorted);
    }

    println!(
        "  Deleted ops:      {} (across {} clients)",
        total_deleted, clients_with_deletes
    );
    println!(
        "  Live ops:         {} ({:.1}% of total)",
        total_ops as u64 - total_deleted.min(total_ops as u64),
        if total_ops > 0 {
            ((total_ops as u64 - total_deleted.min(total_ops as u64)) as f64 / total_ops as f64)
                * 100.0
        } else {
            100.0
        }
    );

    let mut client_stats: Vec<(u64, u32)> =
        sv.iter().map(|(&id, &clock)| (id.get(), clock)).collect();
    client_stats.sort_by(|a, b| b.1.cmp(&a.1));
    println!();
    println!("  Top clients by ops:");
    for (i, (client_id, clock)) in client_stats.iter().take(10).enumerate() {
        let mut sv_all_but_one = StateVector::default();
        for (&c, &clk) in sv.iter() {
            if c.get() != *client_id {
                sv_all_but_one.set_max(c, clk);
            }
        }
        let diff = txn.encode_diff_v1(&sv_all_but_one);
        println!(
            "    {:>2}. client {:>20}: {:>7} ops, {:>9} bytes in diff",
            i + 1,
            client_id,
            clock,
            diff.len()
        );
    }
    if client_stats.len() > 10 {
        let remaining_ops: u32 = client_stats[10..].iter().map(|(_, c)| c).sum();
        println!(
            "        ... and {} more clients ({} ops)",
            client_stats.len() - 10,
            remaining_ops
        );
    }

    println!();
    println!("  Per-client diffs:");
    for (i, (client_id, clock)) in client_stats.iter().enumerate() {
        let mut sv_without = StateVector::default();
        for (&c, &clk) in sv.iter() {
            if c.get() != *client_id {
                sv_without.set_max(c, clk);
            }
        }
        let diff = txn.encode_diff_v1(&sv_without);

        let diff_doc = Doc::new();
        if let Ok(update) = Update::decode_v1(&diff) {
            let mut diff_txn = diff_doc.transact_mut();
            let _ = diff_txn.apply_update(update);
            drop(diff_txn);

            let diff_txn = diff_doc.transact();
            let diff_roots: Vec<_> = diff_txn.root_refs().map(|(n, _)| n.to_string()).collect();
            drop(diff_txn);

            let mut root_summaries: Vec<String> = Vec::new();
            for root_name in &diff_roots {
                let map_ref = diff_doc.get_or_insert_map(root_name.as_str());
                let diff_txn = diff_doc.transact();
                let keys: Vec<String> = map_ref.keys(&diff_txn).map(|k| k.to_string()).collect();
                drop(diff_txn);

                if root_name == "filemeta_v0" || root_name == "docs" {
                    if keys.is_empty() {
                        root_summaries.push(format!("{}: (all overwritten)", root_name));
                    } else {
                        root_summaries.push(format!("{}: {} keys", root_name, keys.len()));
                        for k in &keys {
                            let diff_txn = diff_doc.transact();
                            if let Some(val) = map_ref.get(&diff_txn, k) {
                                let val_desc = match &val {
                                    Out::YMap(m) => {
                                        let inner: Vec<String> = m
                                            .iter(&diff_txn)
                                            .map(|(ik, iv)| {
                                                format!(
                                                    "{}: {:?}",
                                                    ik,
                                                    match &iv {
                                                        Out::Any(a) => format!("{:?}", a),
                                                        Out::YText(t) => t.get_string(&diff_txn),
                                                        other => format!("{:?}", other),
                                                    }
                                                )
                                            })
                                            .collect();
                                        format!("{{{}}}", inner.join(", "))
                                    }
                                    Out::Any(any) => format!("{:?}", any),
                                    other => format!("{:?}", other),
                                };
                                root_summaries.push(format!("  {} = {}", k, val_desc));
                            }
                            drop(diff_txn);
                        }
                    }
                } else {
                    root_summaries.push(format!("{}: {} keys", root_name, keys.len()));
                }
            }

            if !root_summaries.is_empty() {
                println!(
                    "    {:>2}. client {} ({} ops, {} bytes)",
                    i + 1,
                    client_id,
                    clock,
                    diff.len()
                );
                for s in &root_summaries {
                    println!("        {}", s);
                }
            }
        }
    }
    println!();
    println!("  Delete set breakdown (top 15 by tombstone count):");
    let mut ds_by_client: Vec<(u64, u64, usize)> = Vec::new();
    for (&client_id, ranges) in ds.iter() {
        let mut client_deleted: u64 = 0;
        let mut num_ranges: usize = 0;
        for r in ranges.iter() {
            client_deleted += (r.end - r.start) as u64;
            num_ranges += 1;
        }
        ds_by_client.push((client_id.get(), client_deleted, num_ranges));
    }
    ds_by_client.sort_by(|a, b| b.1.cmp(&a.1));
    for (i, (client_id, deleted, num_ranges)) in ds_by_client.iter().take(15).enumerate() {
        let ops_for_client = sv
            .iter()
            .find(|(&c, _)| c.get() == *client_id)
            .map(|(_, &clk)| clk)
            .unwrap_or(0);
        let pct = if ops_for_client > 0 {
            (*deleted as f64 / ops_for_client as f64) * 100.0
        } else {
            0.0
        };
        println!(
            "    {:>2}. client {:>20}: {:>7} deleted of {:>7} total ({:.1}%), {} ranges",
            i + 1,
            client_id,
            deleted,
            ops_for_client,
            pct,
            num_ranges
        );
    }

    println!();
    println!("  Per-root size estimation:");
    drop(txn);
    let txn = doc.transact();
    let root_names_for_size: Vec<String> =
        txn.root_refs().map(|(name, _)| name.to_string()).collect();
    drop(txn);

    let txn = doc.transact();
    let full_update = txn.encode_state_as_update_v1(&StateVector::default());
    let _full_size = full_update.len();
    drop(txn);

    for root_name in &root_names_for_size {
        let partial_doc = Doc::new();
        {
            let txn = doc.transact();
            let full_update_bytes = txn.encode_state_as_update_v1(&StateVector::default());
            drop(txn);

            if let Ok(update) = Update::decode_v1(&full_update_bytes) {
                let mut txn = partial_doc.transact_mut();
                let _ = txn.apply_update(update);
            }
        }

        let map_ref = doc.get_or_insert_map(root_name.as_str());
        let txn = doc.transact();
        let len = map_ref.len(&txn);

        let mut total_value_bytes = 0usize;
        for (_, v) in map_ref.iter(&txn) {
            match &v {
                Out::YText(t) => total_value_bytes += t.get_string(&txn).len(),
                Out::YMap(m) => {
                    for (_, iv) in m.iter(&txn) {
                        match &iv {
                            Out::Any(a) => total_value_bytes += format!("{:?}", a).len(),
                            Out::YText(t) => total_value_bytes += t.get_string(&txn).len(),
                            Out::YArray(a) => total_value_bytes += a.len(&txn) as usize * 8,
                            _ => total_value_bytes += 16,
                        }
                    }
                }
                Out::YArray(a) => total_value_bytes += a.len(&txn) as usize * 8,
                Out::Any(a) => total_value_bytes += format!("{:?}", a).len(),
                _ => total_value_bytes += 16,
            }
        }
        println!(
            "    \"{}\": {} entries, ~{} bytes live data",
            root_name, len, total_value_bytes
        );
        drop(txn);
    }

    println!();
    println!("  PermanentUserData ds array analysis:");
    let users_map = doc.get_or_insert_map("users");
    let txn = doc.transact();
    let mut total_ds_elements = 0u32;
    let mut total_ds_decoded_ops = 0u64;
    for (user_id, user_val) in users_map.iter(&txn) {
        if let Out::YMap(user_map) = &user_val {
            let ids_info = if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                let mut client_ids = Vec::new();
                for item in ids_arr.iter(&txn) {
                    if let Out::Any(yrs::Any::Number(n)) = &item {
                        client_ids.push(*n as u64);
                    } else if let Out::Any(yrs::Any::BigInt(n)) = &item {
                        client_ids.push(*n as u64);
                    } else {
                        client_ids.push(0);
                    }
                }
                client_ids
            } else {
                Vec::new()
            };

            if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                let ds_len = ds_arr.len(&txn);
                total_ds_elements += ds_len;

                let mut decoded_count = 0u32;
                let mut decoded_total_deleted = 0u64;
                let mut decoded_client_ids: std::collections::HashSet<u64> =
                    std::collections::HashSet::new();
                let mut element_types: BTreeMap<String, u32> = BTreeMap::new();

                let mut per_client_deletions: BTreeMap<u64, (u64, Vec<(u32, u32)>)> =
                    BTreeMap::new();

                for item in ds_arr.iter(&txn) {
                    let type_name = match &item {
                        Out::Any(yrs::Any::Buffer(buf)) => {
                            use yrs::encoding::read::Cursor;
                            use yrs::updates::decoder::DecoderV1;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            match yrs::IdSet::decode(&mut decoder) {
                                Ok(decoded_ds) => {
                                    decoded_count += 1;
                                    for (&cid, ranges) in decoded_ds.iter() {
                                        let cid = cid.get();
                                        decoded_client_ids.insert(cid);
                                        let entry = per_client_deletions
                                            .entry(cid)
                                            .or_insert_with(|| (0, Vec::new()));
                                        for r in ranges.iter() {
                                            let len = (r.end - r.start) as u64;
                                            decoded_total_deleted += len;
                                            entry.0 += len;
                                            entry.1.push((r.start, r.end));
                                        }
                                    }
                                    "DeleteSet".to_string()
                                }
                                Err(_) => {
                                    format!("Buffer({} bytes)", buf.len())
                                }
                            }
                        }
                        Out::Any(yrs::Any::String(s)) => {
                            format!("String(\"{}\")", s)
                        }
                        Out::Any(a) => format!("Any({:?})", a),
                        Out::YMap(_) => "YMap".to_string(),
                        Out::YArray(_) => "YArray".to_string(),
                        Out::YText(_) => "YText".to_string(),
                        other => format!("{:?}", other),
                    };

                    *element_types.entry(type_name.clone()).or_default() += 1;
                }

                println!(
                    "    user \"{}\": ids={:?}, ds.len={}, element types: {:?}",
                    user_id, ids_info, ds_len, element_types
                );
                println!("      first {} ds entries (of {}):", ds_len.min(30), ds_len);
                for (idx, item) in ds_arr.iter(&txn).enumerate() {
                    if idx >= 30 {
                        break;
                    }
                    if let Out::Any(yrs::Any::Buffer(buf)) = &item {
                        use yrs::encoding::read::Cursor;
                        use yrs::updates::decoder::DecoderV1;
                        let cursor = Cursor::new(buf.as_ref());
                        let mut decoder = DecoderV1::new(cursor);
                        if let Ok(decoded_ds) = yrs::IdSet::decode(&mut decoder) {
                            let mut parts = Vec::new();
                            for (&cid, ranges) in decoded_ds.iter() {
                                let cid = cid.get();
                                for r in ranges.iter() {
                                    parts.push(format!(
                                        "{}:{}..{} ({})",
                                        cid,
                                        r.start,
                                        r.end,
                                        r.end - r.start
                                    ));
                                }
                            }
                            if parts.is_empty() {
                                println!("        ds[{:>4}]: (empty)", idx);
                            } else {
                                println!("        ds[{:>4}]: {}", idx, parts.join(", "));
                            }
                        }
                    }
                }
                if ds_len > 30 {
                    println!("        ... ({} more entries)", ds_len - 30);
                    println!("      last 10 ds entries:");
                    let entries: Vec<_> = ds_arr.iter(&txn).collect();
                    let start_idx = entries.len().saturating_sub(10);
                    for (i, item) in entries[start_idx..].iter().enumerate() {
                        let idx = start_idx + i;
                        if let Out::Any(yrs::Any::Buffer(buf)) = item {
                            use yrs::encoding::read::Cursor;
                            use yrs::updates::decoder::DecoderV1;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            if let Ok(decoded_ds) = yrs::IdSet::decode(&mut decoder) {
                                let mut parts = Vec::new();
                                for (&cid, ranges) in decoded_ds.iter() {
                                    let cid = cid.get();
                                    for r in ranges.iter() {
                                        parts.push(format!(
                                            "{}:{}..{} ({})",
                                            cid,
                                            r.start,
                                            r.end,
                                            r.end - r.start
                                        ));
                                    }
                                }
                                if !parts.is_empty() {
                                    println!("        ds[{:>4}]: {}", idx, parts.join(", "));
                                }
                            }
                        }
                    }
                }

                if decoded_count > 0 {
                    println!(
                        "      decoded {} DeleteSets: {} total deleted ops across {} unique client IDs",
                        decoded_count, decoded_total_deleted, decoded_client_ids.len()
                    );
                    total_ds_decoded_ops += decoded_total_deleted;

                    println!("      per-client deletion breakdown:");
                    for (&cid, (total, ranges)) in &per_client_deletions {
                        let mut merged: Vec<(u32, u32)> = Vec::new();
                        let mut sorted_ranges = ranges.clone();
                        sorted_ranges.sort();
                        for (start, end) in &sorted_ranges {
                            if let Some(last) = merged.last_mut() {
                                if *start <= last.1 {
                                    last.1 = last.1.max(*end);
                                    continue;
                                }
                            }
                            merged.push((*start, *end));
                        }
                        let merged_total: u64 = merged.iter().map(|(s, e)| (*e - *s) as u64).sum();
                        println!(
                            "        client {:>12}: {} deleted ops ({} after merging), {} unique ranges",
                            cid, total, merged_total, merged.len()
                        );
                        if merged.len() <= 10 {
                            for (s, e) in &merged {
                                println!("          clock {}..{} ({} ops)", s, e, e - s);
                            }
                        } else {
                            for (s, e) in &merged[..5] {
                                println!("          clock {}..{} ({} ops)", s, e, e - s);
                            }
                            println!("          ... {} more ranges ...", merged.len() - 10);
                            for (s, e) in &merged[merged.len() - 5..] {
                                println!("          clock {}..{} ({} ops)", s, e, e - s);
                            }
                        }

                        if let Some(ref fm_map) = filemeta_clock_map {
                            let mut filename_counts: BTreeMap<&str, u64> = BTreeMap::new();
                            let mut unresolved = 0u64;
                            for (start, end) in &merged {
                                for clock in *start..*end {
                                    if let Some(filename) = fm_map.get(&(cid, clock)) {
                                        *filename_counts.entry(filename.as_str()).or_default() += 1;
                                    } else {
                                        unresolved += 1;
                                    }
                                }
                            }
                            if !filename_counts.is_empty() {
                                let mut by_count: Vec<(&&str, &u64)> =
                                    filename_counts.iter().collect();
                                by_count.sort_by(|a, b| b.1.cmp(a.1));
                                println!(
                                    "          filenames ({} resolved, {} unresolved):",
                                    merged_total - unresolved,
                                    unresolved
                                );
                                for (name, count) in &by_count {
                                    println!("            {:>5} ops  {}", count, name);
                                }
                            } else if merged_total > 0 {
                                println!(
                                    "          (no filemeta_v0 filenames resolved for {} deleted ops)",
                                    merged_total
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "    Total ds elements across all users: {}",
        total_ds_elements
    );
    if total_ds_decoded_ops > 0 {
        println!(
            "    Total deleted ops referenced in ds: {}",
            total_ds_decoded_ops
        );
    }
    drop(txn);

    println!();
    println!("  PermanentUserData ds vs document GC analysis:");
    {
        let txn = doc.transact();

        let count_overlap = |client_id: u64, start: u32, end: u32| -> u64 {
            let Some(doc_ranges) = doc_ds_ranges.get(&client_id) else {
                return 0;
            };
            let mut overlap = 0u64;
            for &(ds_start, ds_end) in doc_ranges {
                if ds_end <= start {
                    continue;
                }
                if ds_start >= end {
                    break;
                }
                let o_start = start.max(ds_start);
                let o_end = end.min(ds_end);
                if o_end > o_start {
                    overlap += (o_end - o_start) as u64;
                }
            }
            overlap
        };

        let mut grand_total_pud_ops = 0u64;
        let mut grand_total_still_live = 0u64;

        for (user_id, user_val) in users_map.iter(&txn) {
            if let Out::YMap(user_map) = &user_val {
                if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                    let mut user_total_ops = 0u64;
                    let mut user_live_ops = 0u64;

                    for item in ds_arr.iter(&txn) {
                        if let Out::Any(yrs::Any::Buffer(buf)) = &item {
                            use yrs::encoding::read::Cursor;
                            use yrs::updates::decoder::DecoderV1;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            if let Ok(decoded_ds) = yrs::IdSet::decode(&mut decoder) {
                                for (&cid, ranges) in decoded_ds.iter() {
                                    let cid = cid.get();
                                    for r in ranges.iter() {
                                        let len = (r.end - r.start) as u64;
                                        user_total_ops += len;
                                        user_live_ops += count_overlap(cid, r.start, r.end);
                                    }
                                }
                            }
                        }
                    }

                    let gc_ops = user_total_ops - user_live_ops;
                    let gc_pct = if user_total_ops > 0 {
                        (gc_ops as f64 / user_total_ops as f64) * 100.0
                    } else {
                        0.0
                    };
                    println!(
                        "    user \"{}\": {} ops in PUD ds, {} still in doc delete set, {} already GC'd ({:.1}% prunable)",
                        user_id, user_total_ops, user_live_ops, gc_ops, gc_pct
                    );

                    grand_total_pud_ops += user_total_ops;
                    grand_total_still_live += user_live_ops;
                }
            }
        }

        let grand_gc = grand_total_pud_ops - grand_total_still_live;
        let grand_gc_pct = if grand_total_pud_ops > 0 {
            (grand_gc as f64 / grand_total_pud_ops as f64) * 100.0
        } else {
            0.0
        };
        println!(
            "    TOTAL: {} ops in PUD ds, {} still live, {} prunable ({:.1}%)",
            grand_total_pud_ops, grand_total_still_live, grand_gc, grand_gc_pct
        );
        if grand_total_still_live == 0 && grand_total_pud_ops > 0 {
            println!(
                "    → ALL PermanentUserData ds entries are for GC'd items and could be safely dropped"
            );
        }
        drop(txn);
    }

    println!();
    println!("  filemeta_v0 value history:");
    let fm_map = doc.get_or_insert_map("filemeta_v0");
    let txn = doc.transact();
    let fm_count = fm_map.len(&txn);
    println!("    Current entries: {}", fm_count);

    let mut fm_entries: Vec<(String, String)> = Vec::new();
    for (k, v) in fm_map.iter(&txn) {
        let val_desc = match &v {
            Out::YMap(m) => {
                let inner: Vec<String> = m
                    .iter(&txn)
                    .map(|(ik, iv)| {
                        let iv_s = match &iv {
                            Out::Any(a) => format!("{:?}", a),
                            Out::YText(t) => format!("\"{}\"", t.get_string(&txn)),
                            _ => format!("{:?}", iv),
                        };
                        format!("{}: {}", ik, iv_s)
                    })
                    .collect();
                format!("{{{}}}", inner.join(", "))
            }
            Out::Any(a) => format!("{:?}", a),
            other => format!("{:?}", other),
        };
        fm_entries.push((k.to_string(), val_desc));
    }
    for (i, (k, v)) in fm_entries.iter().enumerate() {
        if i < 10 {
            println!("    [{}] {} = {}", i, k, v);
        }
    }
    if fm_entries.len() > 10 {
        println!("    ... and {} more entries", fm_entries.len() - 10);
    }
    drop(txn);

    let txn = doc.transact();
    let root_names: Vec<String> = txn.root_refs().map(|(name, _)| name.to_string()).collect();
    println!("  Root keys:        {}", root_names.len());
    drop(txn);

    for name in &root_names {
        let map_ref = doc.get_or_insert_map(name.as_str());
        let txn = doc.transact();
        let len = map_ref.len(&txn);
        if len > 0 {
            println!("    \"{}\": YMap ({} entries)", name, len);
            for (k, v) in map_ref.iter(&txn) {
                let val_desc = match &v {
                    Out::YText(t) => {
                        let s = t.get_string(&txn);
                        format!("YText ({} chars, {} bytes)", s.chars().count(), s.len())
                    }
                    Out::YMap(m) => {
                        let inner: Vec<String> = m
                            .iter(&txn)
                            .map(|(ik, iv)| {
                                let iv_desc = match &iv {
                                    Out::YText(t) => {
                                        let s = t.get_string(&txn);
                                        if s.len() > 80 {
                                            format!("YText ({} chars)", s.chars().count())
                                        } else {
                                            format!("{:?}", s)
                                        }
                                    }
                                    Out::YMap(m2) => {
                                        format!("YMap ({} entries)", m2.len(&txn))
                                    }
                                    Out::YArray(a2) => {
                                        format!("YArray (len={})", a2.len(&txn))
                                    }
                                    Out::Any(any) => format!("{:?}", any),
                                    other => format!("{:?}", other),
                                };
                                format!("{}: {}", ik, iv_desc)
                            })
                            .collect();
                        format!("YMap ({})", inner.join(", "))
                    }
                    Out::YArray(a) => format!("YArray (len={})", a.len(&txn)),
                    Out::Any(any) => format!("{:?}", any),
                    other => format!("{:?}", other),
                };
                println!("      \"{}\": {}", k, val_desc);
            }
            drop(txn);
            continue;
        }
        drop(txn);

        let text_ref = doc.get_or_insert_text(name.as_str());
        let txn = doc.transact();
        let s = text_ref.get_string(&txn);
        if !s.is_empty() {
            println!(
                "    \"{}\": YText ({} chars, {} bytes)",
                name,
                s.chars().count(),
                s.len()
            );
            drop(txn);
            continue;
        }
        drop(txn);

        let arr_ref = doc.get_or_insert_array(name.as_str());
        let txn = doc.transact();
        let arr_len = arr_ref.len(&txn);
        if arr_len > 0 {
            println!("    \"{}\": YArray (len={})", name, arr_len);
            drop(txn);
            continue;
        }
        drop(txn);

        println!("    \"{}\": (empty)", name);
    }
}

// -- v1 update binary decoder for filename resolution --

#[derive(Debug)]
pub(crate) struct DecodedItemMeta {
    pub(crate) client: u64,
    pub(crate) clock: u32,
    pub(crate) len: u32,
    pub(crate) parent_named: Option<String>,
    pub(crate) parent_id: Option<(u64, u32)>,
    pub(crate) parent_sub: Option<String>,
    pub(crate) origin: Option<(u64, u32)>,
    pub(crate) right_origin: Option<(u64, u32)>,
    pub(crate) content_ref: u8,
}

pub(crate) fn decode_v1_item_parents(bytes: &[u8]) -> Result<Vec<DecodedItemMeta>, String> {
    use lib0::decoding::{Cursor, Read};

    let mut cursor = Cursor::new(bytes);
    let mut items = Vec::new();

    let num_clients: u32 = cursor
        .read_var()
        .map_err(|e| format!("num_clients: {:?}", e))?;
    for _ in 0..num_clients {
        let num_blocks: u32 = cursor
            .read_var()
            .map_err(|e| format!("num_blocks: {:?}", e))?;
        let client: u64 = cursor.read_var().map_err(|e| format!("client: {:?}", e))?;
        let mut clock: u32 = cursor.read_var().map_err(|e| format!("clock: {:?}", e))?;

        for block_idx in 0..num_blocks {
            let info = cursor.read_u8().map_err(|e| format!("info: {:?}", e))?;
            let content_ref = info & 0x0F;

            if content_ref == 10 || content_ref == 0 {
                let len: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("block len: {:?}", e))?;
                items.push(DecodedItemMeta {
                    client,
                    clock,
                    len,
                    content_ref,
                    parent_named: None,
                    parent_id: None,
                    parent_sub: None,
                    origin: None,
                    right_origin: None,
                });
                clock = clock.checked_add(len).ok_or("clock overflow")?;
                continue;
            }

            let has_origin = info & 0x80 != 0;
            let has_right_origin = info & 0x40 != 0;
            let cant_copy_parent = !has_origin && !has_right_origin;

            let origin = if has_origin {
                let c: u64 = cursor
                    .read_var()
                    .map_err(|e| format!("origin client: {:?}", e))?;
                let k: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("origin clock: {:?}", e))?;
                Some((c as u64, k))
            } else {
                None
            };

            let right_origin = if has_right_origin {
                let c: u64 = cursor
                    .read_var()
                    .map_err(|e| format!("right client: {:?}", e))?;
                let k: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("right clock: {:?}", e))?;
                Some((c, k))
            } else {
                None
            };

            let mut parent_named = None;
            let mut parent_id = None;
            if cant_copy_parent {
                let parent_info: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("parent_info: {:?}", e))?;
                if parent_info == 1 {
                    let name = cursor
                        .read_string()
                        .map_err(|e| format!("parent name: {:?}", e))?;
                    parent_named = Some(name.to_string());
                } else {
                    let c: u64 = cursor
                        .read_var()
                        .map_err(|e| format!("parent id client: {:?}", e))?;
                    let k: u32 = cursor
                        .read_var()
                        .map_err(|e| format!("parent id clock: {:?}", e))?;
                    parent_id = Some((c as u64, k));
                }
            }

            let parent_sub = if cant_copy_parent && (info & 0x20 != 0) {
                let s = cursor
                    .read_string()
                    .map_err(|e| format!("parent_sub: {:?}", e))?;
                Some(s.to_string())
            } else {
                None
            };

            let content_len = skip_v1_content(&mut cursor, content_ref).map_err(|e| {
                format!(
                    "content skip at client={} clock={} block={} ref={}: {}",
                    client, clock, block_idx, content_ref, e
                )
            })?;

            items.push(DecodedItemMeta {
                client: client as u64,
                clock,
                len: content_len,
                parent_named,
                parent_id,
                parent_sub,
                origin,
                right_origin,
                content_ref,
            });

            clock = clock.checked_add(content_len).ok_or("clock overflow")?;
        }
    }

    Ok(items)
}

fn skip_v1_content(cursor: &mut lib0::decoding::Cursor, content_ref: u8) -> Result<u32, String> {
    use lib0::decoding::Read;

    match content_ref {
        1 => {
            let len: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            Ok(len)
        }
        2 => {
            let count: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..count {
                cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            }
            Ok(count)
        }
        3 => {
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(1)
        }
        4 => {
            let buf = cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            let text = std::str::from_utf8(buf).map_err(|_| "invalid UTF-8 string")?;
            Ok(text.encode_utf16().count() as u32)
        }
        5 => {
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(1)
        }
        6 => {
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(1)
        }
        7 => {
            let type_ref = cursor.read_u8().map_err(|e| format!("{:?}", e))?;
            match type_ref {
                3 | 5 => {
                    cursor.read_buf().map_err(|e| format!("{:?}", e))?;
                }
                _ => {}
            }
            Ok(1)
        }
        8 => {
            let count: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..count {
                skip_any_value(cursor)?;
            }
            Ok(count.max(1))
        }
        9 => {
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            skip_any_value(cursor)?;
            Ok(1)
        }
        11 => {
            let flags: i64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            let is_collapsed = (flags & 1) != 0;
            let _: u64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            let _: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            if !is_collapsed {
                let _: u64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
                let _: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            }
            Ok(1)
        }
        _ => Err(format!("unknown content ref: {}", content_ref)),
    }
}

fn skip_any_value(cursor: &mut lib0::decoding::Cursor) -> Result<(), String> {
    use lib0::decoding::Read;

    let tag = cursor.read_u8().map_err(|e| format!("{:?}", e))?;
    match tag {
        127 | 126 | 121 | 120 => {}
        125 => {
            let _: i64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
        }
        124 => {
            cursor.read_exact(4).map_err(|e| format!("{:?}", e))?;
        }
        123 => {
            cursor.read_exact(8).map_err(|e| format!("{:?}", e))?;
        }
        122 => {
            cursor.read_exact(8).map_err(|e| format!("{:?}", e))?;
        }
        119 => {
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
        }
        118 => {
            let len: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..len {
                cursor.read_buf().map_err(|e| format!("{:?}", e))?;
                skip_any_value(cursor)?;
            }
        }
        117 => {
            let len: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..len {
                skip_any_value(cursor)?;
            }
        }
        116 => {
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
        }
        _ => return Err(format!("unknown Any tag: {}", tag)),
    }
    Ok(())
}

fn build_filemeta_clock_map(update_bytes: &[u8]) -> Result<HashMap<(u64, u32), String>, String> {
    let items = decode_v1_item_parents(update_bytes)?;

    let mut by_id: HashMap<(u64, u32), usize> = HashMap::new();
    for (i, item) in items.iter().enumerate() {
        by_id.insert((item.client, item.clock), i);
    }

    let mut resolved: HashMap<(u64, u32), String> = HashMap::new();
    for item in &items {
        if item.parent_named.as_deref() == Some("filemeta_v0") {
            if let Some(ref sub) = item.parent_sub {
                for c in 0..item.len {
                    resolved.insert((item.client, item.clock + c), sub.clone());
                }
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for item in &items {
            if resolved.contains_key(&(item.client, item.clock)) {
                continue;
            }
            if let Some((pc, pk)) = item.parent_id {
                if let Some(filename) = resolved.get(&(pc, pk)).cloned() {
                    for c in 0..item.len {
                        resolved.insert((item.client, item.clock + c), filename.clone());
                    }
                    changed = true;
                }
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for item in &items {
            if resolved.contains_key(&(item.client, item.clock)) {
                continue;
            }
            if let Some((oc, ok)) = item.origin {
                if let Some(filename) = resolved.get(&(oc, ok)).cloned() {
                    for c in 0..item.len {
                        resolved.insert((item.client, item.clock + c), filename.clone());
                    }
                    changed = true;
                }
            }
        }
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_out_to_json_any_types() {
        assert_eq!(any_to_json(&yrs::Any::Null), serde_json::Value::Null);
        assert_eq!(any_to_json(&yrs::Any::Bool(true)), json!(true));
        assert_eq!(any_to_json(&yrs::Any::Number(42.0)), json!(42.0));
        assert_eq!(
            any_to_json(&yrs::Any::String("hello".into())),
            json!("hello")
        );
    }

    #[test]
    fn test_build_client_user_map_empty() {
        use yrs::Doc;
        let doc = Doc::new();
        let map = build_client_user_map(&doc);
        assert!(map.is_empty());
    }

    #[test]
    fn test_json_byte_size() {
        assert_eq!(json_byte_size(&json!({"a": 1})), 7); // {"a":1}
        assert_eq!(json_byte_size(&json!("hello")), 7); // "hello"
    }

    #[test]
    fn test_json_diff() {
        // No changes
        assert_eq!(
            json_diff(&json!({"a": 1}), &json!({"a": 1})),
            serde_json::Value::Null
        );

        // Added key
        assert_eq!(json_diff(&json!({}), &json!({"a": 1})), json!({"a": 1}));

        // Removed key
        assert_eq!(json_diff(&json!({"a": 1}), &json!({})), json!({"a": null}));

        // Changed value
        assert_eq!(
            json_diff(&json!({"a": 1}), &json!({"a": 2})),
            json!({"a": 2})
        );

        // Nested diff
        assert_eq!(
            json_diff(
                &json!({"x": {"a": 1, "b": 2}}),
                &json!({"x": {"a": 1, "b": 3}})
            ),
            json!({"x": {"b": 3}})
        );

        // Scalar diff
        assert_eq!(json_diff(&json!(1), &json!(2)), json!(2));
        assert_eq!(json_diff(&json!(1), &json!(1)), serde_json::Value::Null);
    }
}
