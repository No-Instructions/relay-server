//! The blind block-store surface (see the plugin repo's
//! specs/blind-store-server.md): four object verbs plus pin-set storage
//! and usage accounting, all over opaque keys and bytes.
//!
//!   GET    /kv/<ns>/<key>                 -> 200 bytes | 404
//!   PUT    /kv/<ns>/<key>                 <- bytes     -> 204 | 413
//!   HEAD   /kv/<ns>/<key>                 -> 200 | 404
//!   GET    /kv?ns=<ns>&prefix=<prefix>    -> 200 JSON string[] (keys)
//!   GET    /kv-usage?ns=<ns>              -> { guaranteedBytes, physicalBytes, limit }
//!
//! Access rides the kv grant claim (CWT private claim -80203,
//! "kv:<ns-prefix>:<r|rw>[:<limit-bytes>]") carried by any token the
//! control plane mints: the client names a concrete namespace in the
//! path, the grant must cover it (exact-or-dash prefix rule), writes
//! require rw, and the optional limit is enforced against the summed
//! bytes stored under the grant prefix. Blindness duties: `o/` values
//! are never parsed; `pinset/` values are parsed only to run usage
//! accounting; `refs/` values are never parsed here (clients verify
//! head signatures against the pairing ACL).
//!
//! Device-pubkey verification of `refs/` and `pinset/` writes against
//! the account's registered devices requires the control plane's
//! device registry and is enforced there, not here.

use crate::server::Server;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use dashmap::DashMap;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::cors::CorsLayer;
use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::KvGrant;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn kv_error(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

/// A storage-safe key: the shapes the sync client writes, nothing else.
fn validate_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() < 512
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
        && !key.contains("..")
        && !key.starts_with('/')
}

/// Per-grant-prefix usage in bytes, seeded lazily from the store and
/// maintained incrementally on writes. Process-local: a restart
/// re-seeds on first touch.
static USAGE: std::sync::LazyLock<DashMap<String, u64>> = std::sync::LazyLock::new(DashMap::new);

/// The caller's grant for a requested namespace. Without an
/// authenticator (dev mode) any well-formed namespace is granted in
/// full with no limit.
fn resolve_grant(
    server: &Server,
    headers: &HeaderMap,
    namespace: &str,
) -> Result<KvGrant, Response> {
    if namespace.is_empty() || namespace.contains('/') || !validate_key(namespace) {
        return Err(kv_error(StatusCode::BAD_REQUEST, "invalid namespace"));
    }
    let Some(authenticator) = server.kv_authenticator() else {
        return Ok(KvGrant {
            prefix: namespace.to_string(),
            authorization: Authorization::Full,
            limit_bytes: None,
            user: None,
        });
    };
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| kv_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let grant = authenticator
        .verify_kv_grant(token, now_secs())
        .map_err(|_| kv_error(StatusCode::FORBIDDEN, "no kv grant"))?;
    if !grant.covers(namespace) {
        return Err(kv_error(StatusCode::FORBIDDEN, "namespace not granted"));
    }
    Ok(grant)
}

/// Bytes stored under every namespace the grant prefix covers,
/// seeding the counter from the store on first touch.
async fn grant_usage(
    store: &dyn y_sweet_core::store::Store,
    grant: &KvGrant,
) -> Result<u64, Response> {
    if let Some(usage) = USAGE.get(&grant.prefix) {
        return Ok(*usage);
    }
    let listed = store
        .list(&format!("kv/{}", grant.prefix))
        .await
        .map_err(|e| kv_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let total: u64 = listed
        .iter()
        .filter(|f| {
            f.key
                .strip_prefix("kv/")
                .and_then(|rest| rest.split('/').next())
                .is_some_and(|ns| grant.covers(ns))
        })
        .map(|f| f.size)
        .sum();
    USAGE.insert(grant.prefix.clone(), total);
    Ok(total)
}

fn store_key(ns: &str, key: &str) -> String {
    format!("kv/{}/{}", ns, key)
}

async fn kv_get(
    State(server): State<Arc<Server>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some((ns, key)) = split_ns(&path) else {
        return kv_error(StatusCode::BAD_REQUEST, "expected /kv/<ns>/<key>");
    };
    if let Err(e) = resolve_grant(&server, &headers, ns) {
        return e;
    }
    if !validate_key(key) {
        return kv_error(StatusCode::BAD_REQUEST, "invalid key");
    }
    let Some(store) = server.kv_store() else {
        return kv_error(StatusCode::SERVICE_UNAVAILABLE, "no store configured");
    };
    match store.get(&store_key(ns, key)).await {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => kv_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn kv_head(
    State(server): State<Arc<Server>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some((ns, key)) = split_ns(&path) else {
        return kv_error(StatusCode::BAD_REQUEST, "expected /kv/<ns>/<key>");
    };
    if let Err(e) = resolve_grant(&server, &headers, ns) {
        return e;
    }
    if !validate_key(key) {
        return kv_error(StatusCode::BAD_REQUEST, "invalid key");
    }
    let Some(store) = server.kv_store() else {
        return kv_error(StatusCode::SERVICE_UNAVAILABLE, "no store configured");
    };
    match store.exists(&store_key(ns, key)).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => kv_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn kv_put(
    State(server): State<Arc<Server>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((ns, key)) = split_ns(&path) else {
        return kv_error(StatusCode::BAD_REQUEST, "expected /kv/<ns>/<key>");
    };
    let grant = match resolve_grant(&server, &headers, ns) {
        Ok(g) => g,
        Err(e) => return e,
    };
    if !matches!(grant.authorization, Authorization::Full) {
        return kv_error(StatusCode::FORBIDDEN, "write requires full authorization");
    }
    if !validate_key(key) {
        return kv_error(StatusCode::BAD_REQUEST, "invalid key");
    }
    let Some(store) = server.kv_store() else {
        return kv_error(StatusCode::SERVICE_UNAVAILABLE, "no store configured");
    };
    let full_key = store_key(ns, key);

    // Limit enforcement: content-addressed traffic overwhelmingly PUTs
    // fresh keys, so the delta is the body size; an overwrite adjusts
    // by the old size (one exact list) to keep the counter honest.
    let mut delta = body.len() as u64;
    if let Some(limit) = grant.limit_bytes {
        let usage = match grant_usage(store.as_ref().as_ref(), &grant).await {
            Ok(u) => u,
            Err(e) => return e,
        };
        if let Ok(existing) = store.list(&full_key).await {
            if let Some(old) = existing.iter().find(|f| f.key == full_key) {
                delta = delta.saturating_sub(old.size);
            }
        }
        if usage.saturating_add(delta) > limit {
            return kv_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "storage limit reached for this grant",
            );
        }
    }
    match store.set(&full_key, body.to_vec()).await {
        Ok(()) => {
            if grant.limit_bytes.is_some() {
                if let Some(mut usage) = USAGE.get_mut(&grant.prefix) {
                    *usage += delta;
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => kv_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// "<ns>/<key…>" from the wildcard path.
fn split_ns(path: &str) -> Option<(&str, &str)> {
    let (ns, key) = path.split_once('/')?;
    if ns.is_empty() || key.is_empty() {
        return None;
    }
    Some((ns, key))
}

#[derive(Deserialize)]
struct ListQuery {
    ns: String,
    #[serde(default)]
    prefix: String,
}

async fn kv_list(
    State(server): State<Arc<Server>>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = resolve_grant(&server, &headers, &query.ns) {
        return e;
    }
    let Some(store) = server.kv_store() else {
        return kv_error(StatusCode::SERVICE_UNAVAILABLE, "no store configured");
    };
    let root = format!("kv/{}/", query.ns);
    let full_prefix = format!("{}{}", root, query.prefix);
    match store.list(&full_prefix).await {
        Ok(files) => {
            let mut keys: Vec<String> = files
                .into_iter()
                .filter_map(|f| f.key.strip_prefix(&root).map(|k| k.to_string()))
                .collect();
            keys.sort();
            Json(keys).into_response()
        }
        Err(e) => kv_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Deserialize)]
struct PinSetAccounting {
    #[serde(rename = "expiresAt")]
    expires_at: String,
    bytes: u64,
}

/// Usage per specs/pin-sets.md: guaranteed counts declared bytes of
/// unexpired pin-sets; physical is what the namespace actually holds;
/// limit echoes the grant. Deduped closures overlap, so guaranteed <=
/// physical in the common case of nightly pins over one vault.
async fn kv_usage(
    State(server): State<Arc<Server>>,
    Query(query): Query<UsageQuery>,
    headers: HeaderMap,
) -> Response {
    let grant = match resolve_grant(&server, &headers, &query.ns) {
        Ok(g) => g,
        Err(e) => return e,
    };
    let Some(store) = server.kv_store() else {
        return kv_error(StatusCode::SERVICE_UNAVAILABLE, "no store configured");
    };
    let root = format!("kv/{}/", query.ns);
    let physical: u64 = match store.list(&format!("{}o/", root)).await {
        Ok(files) => files.iter().map(|f| f.size).sum(),
        Err(e) => return kv_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let mut guaranteed: u64 = 0;
    if let Ok(pins) = store.list(&format!("{}pinset/", root)).await {
        let now_ms = now_secs() as i64 * 1000;
        for pin in pins {
            let Ok(Some(raw)) = store.get(&pin.key).await else {
                continue;
            };
            let Ok(parsed) = serde_json::from_slice::<PinSetAccounting>(&raw) else {
                continue;
            };
            let expires_ms = chrono::DateTime::parse_from_rfc3339(&parsed.expires_at)
                .map(|d| d.timestamp_millis())
                .unwrap_or(0);
            if expires_ms > now_ms {
                guaranteed += parsed.bytes;
            }
        }
    }
    Json(serde_json::json!({
        "guaranteedBytes": guaranteed,
        "physicalBytes": physical,
        "limit": grant.limit_bytes.unwrap_or(0),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct UsageQuery {
    ns: String,
}

/// The `/kv` route group. CORS is permissive: callers are Electron and
/// browser renderers, and the surface is bearer-authenticated bytes.
pub fn kv_routes(server: Arc<Server>) -> Router {
    Router::new()
        .route("/kv-usage", get(kv_usage))
        .route("/kv/*key", get(kv_get).put(kv_put).head(kv_head))
        .route("/kv", get(kv_list))
        .layer(CorsLayer::permissive())
        .with_state(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ns_split() {
        assert_eq!(split_ns("kv-u1-g2/o/aabb"), Some(("kv-u1-g2", "o/aabb")));
        assert_eq!(
            split_ns("kv-u1-g2/refs/ab/vault"),
            Some(("kv-u1-g2", "refs/ab/vault"))
        );
        assert_eq!(split_ns("nokey"), None);
        assert_eq!(split_ns("/leading"), None);
    }

    #[test]
    fn key_validation_accepts_sync_shapes() {
        assert!(validate_key("o/00ff aa".replace(' ', "").as_str()));
        assert!(validate_key("refs/ab12/vault"));
        assert!(validate_key("pinset/ab12/nightly-2026-07-07"));
        assert!(!validate_key(""));
        assert!(!validate_key("/leading"));
        assert!(!validate_key("a/../b"));
        assert!(!validate_key("bad key"));
        assert!(!validate_key(&"x".repeat(600)));
    }
}
