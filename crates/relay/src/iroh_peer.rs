//! The server as an iroh peer: the blind KV surface served over the
//! `relay/kv/0` ALPN — the second door into the same store the HTTP
//! /kv routes expose. Devices dial the server by EndpointID (publish
//! it in the control plane's relays table); connections are mutually
//! authenticated and E2E encrypted by iroh itself; no domain or certs
//! are required. Blindness duties are identical to the HTTP door.
//!
//! Wire protocol, one EOF-delimited bi-stream per request:
//!   request  = [verb u8][key_len u16 BE][key utf8][value bytes…]
//!   response = [status u8][payload bytes…]
//!   verbs: 0 GET, 1 PUT, 2 HAS, 3 LIST (key = prefix)
//!   status: 0 ok, 1 not found, 2 denied, 3 error
//!
//! Configuration (environment, staging v0 — the control plane owns
//! this in production):
//!   RELAY_IROH_ENABLED=1        turn the peer on
//!   RELAY_IROH_SECRET_HEX=…     persistent 32-byte identity seed
//!                               (omitted: ephemeral, logged)
//!   RELAY_IROH_ALLOWED=hex,hex  device EndpointIDs served (omitted:
//!                               any dialer, dev only)
//!
//! Every allowed device maps to the "default" namespace, matching the
//! HTTP door's no-authenticator mode; per-account namespaces arrive
//! with the control-plane device registry.

use crate::server::Server;
use std::sync::Arc;
use y_sweet_core::api_types::Authorization;
use y_sweet_core::doc_connection::DocConnection;

const KV_ALPN: &[u8] = b"relay/kv/0";
/// Doc-sync door (DEMO, 2026-08-05): the y-sweet doc protocol served
/// over iroh instead of a WebSocket. One bi-stream per doc connection;
/// frames are u32-BE length-prefixed y-protocol messages, and the first
/// frame from the dialer is the UTF-8 doc id. Auth follows the kv door's
/// dev semantics: the EndpointID allowlist (RELAY_IROH_ALLOWED) is the
/// only gate — no tokens travel on this ALPN. Authorization is Full.
const DOC_ALPN: &[u8] = b"relay/doc/0";
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_DOC_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_DOC_ID_BYTES: usize = 4096;

const VERB_GET: u8 = 0;
const VERB_PUT: u8 = 1;
const VERB_HAS: u8 = 2;
const VERB_LIST: u8 = 3;

const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_DENIED: u8 = 2;
const STATUS_ERROR: u8 = 3;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

struct PeerConfig {
    secret: Option<[u8; 32]>,
    allowed: Option<Vec<String>>,
}

fn config_from_env() -> Option<PeerConfig> {
    if std::env::var("RELAY_IROH_ENABLED").ok().as_deref() != Some("1") {
        return None;
    }
    let secret = std::env::var("RELAY_IROH_SECRET_HEX")
        .ok()
        .and_then(|h| from_hex(&h))
        .and_then(|v| <[u8; 32]>::try_from(v).ok());
    let allowed = std::env::var("RELAY_IROH_ALLOWED").ok().map(|s| {
        s.split(',')
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect()
    });
    Some(PeerConfig { secret, allowed })
}

/// Spawn the iroh peer if RELAY_IROH_ENABLED=1. Returns immediately;
/// the accept loop runs until the server shuts down.
pub fn spawn_if_configured(server: Arc<Server>) {
    let Some(config) = config_from_env() else {
        return;
    };
    tokio::spawn(async move {
        if let Err(e) = run_peer(server, config).await {
            tracing::error!("iroh peer failed: {}", e);
        }
    });
}

async fn run_peer(server: Arc<Server>, config: PeerConfig) -> anyhow::Result<()> {
    let secret_key = match config.secret {
        Some(seed) => iroh::SecretKey::from_bytes(&seed),
        None => {
            let sk = iroh::SecretKey::generate();
            tracing::warn!(
                "iroh peer using an EPHEMERAL identity (set RELAY_IROH_SECRET_HEX to persist)"
            );
            sk
        }
    };
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![KV_ALPN.to_vec(), DOC_ALPN.to_vec()])
        .bind()
        .await?;
    let id = to_hex(endpoint.id().as_bytes());
    tracing::info!(
        "iroh peer up: EndpointID {} (publish as the relay's pubkey)",
        id
    );

    while let Some(incoming) = endpoint.accept().await {
        let server = server.clone();
        let allowed = config.allowed.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let is_doc = conn.alpn() == DOC_ALPN;
                    let result = if is_doc {
                        handle_doc_connection(server, allowed, conn).await
                    } else {
                        handle_connection(server, allowed, conn).await
                    };
                    if let Err(e) = result {
                        tracing::debug!("iroh connection ended: {}", e);
                    }
                }
                Err(e) => tracing::debug!("iroh accept failed: {}", e),
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    server: Arc<Server>,
    allowed: Option<Vec<String>>,
    conn: iroh::endpoint::Connection,
) -> anyhow::Result<()> {
    let remote = to_hex(conn.remote_id().as_bytes());
    let permitted = allowed
        .as_ref()
        .map(|list| list.iter().any(|a| a == &remote))
        .unwrap_or(true);
    if permitted {
        tracing::info!("iroh peer serving device {}", remote);
    } else {
        tracing::warn!("iroh peer refusing unlisted device {}", remote);
    }
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(_) => return Ok(()), // connection closed
        };
        let request = recv.read_to_end(MAX_REQUEST_BYTES).await?;
        let response = if permitted {
            handle_request(&server, &request).await
        } else {
            // Deny before any answer, including not-found: an unscoped
            // has() is an existence oracle.
            vec![STATUS_DENIED]
        };
        send.write_all(&response).await?;
        send.finish()?;
    }
}

/// Serve the doc-sync protocol on one connection (ALPN `relay/doc/0`).
/// Each accepted bi-stream is an independent doc connection.
async fn handle_doc_connection(
    server: Arc<Server>,
    allowed: Option<Vec<String>>,
    conn: iroh::endpoint::Connection,
) -> anyhow::Result<()> {
    let remote = to_hex(conn.remote_id().as_bytes());
    let permitted = allowed
        .as_ref()
        .map(|list| list.iter().any(|a| a == &remote))
        .unwrap_or(true);
    if !permitted {
        tracing::warn!("iroh doc door refusing unlisted device {}", remote);
        conn.close(2u32.into(), b"denied");
        return Ok(());
    }
    tracing::info!("iroh doc door: serving device {}", remote);
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(_) => return Ok(()), // connection closed
        };
        let server = server.clone();
        let remote = remote.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_doc_stream(server, send, recv, &remote).await {
                tracing::debug!("iroh doc stream ended: {}", e);
            }
        });
    }
}

/// Read one u32-BE length-prefixed frame. Ok(None) on clean EOF.
async fn read_frame(
    recv: &mut iroh::endpoint::RecvStream,
    max: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        anyhow::bail!("frame of {} bytes exceeds limit {}", len, max);
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn serve_doc_stream(
    server: Arc<Server>,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    remote: &str,
) -> anyhow::Result<()> {
    // First frame: `doc_id` or `doc_id\nchannel`. The channel names the
    // parent (folder) doc for subdoc snapshot routing — on the WS door it
    // arrives in the token's channel claim; the tokenless dev door takes
    // the client's word for it.
    let Some(first) = read_frame(&mut recv, MAX_DOC_ID_BYTES).await? else {
        return Ok(());
    };
    let handshake = String::from_utf8(first)?;
    let mut parts = handshake.splitn(2, '\n');
    let doc_id = parts.next().unwrap_or("").to_string();
    let second = parts.next().map(|s| s.to_string());
    if doc_id.is_empty() {
        anyhow::bail!("empty doc id");
    }

    // `doc_id\n@as-update` is a one-shot fetch (the HTTP door's
    // GET /d/:doc_id/as-update): respond with one frame holding the full
    // doc as a y update, then finish. Used by keyframe downloads.
    if second.as_deref() == Some("@as-update") {
        let update = {
            let dwskv = server.get_or_create_doc(&doc_id).await?;
            dwskv.as_update()
        };
        tracing::info!(
            "iroh doc door: as-update for doc {} to device {} ({} bytes)",
            doc_id,
            remote,
            update.len()
        );
        let len = (update.len() as u32).to_be_bytes();
        send.write_all(&len).await?;
        send.write_all(&update).await?;
        send.finish()?;
        return Ok(());
    }

    let channel = second.filter(|s| !s.is_empty() && *s != doc_id);

    // Load (or create) the doc; extract handles and DROP the dashmap ref
    // before entering the long-lived message loop.
    let (awareness, sync_kv) = {
        let dwskv = server
            .get_or_create_doc_with_channel_and_user(&doc_id, channel.clone(), None)
            .await?;
        (dwskv.awareness(), dwskv.sync_kv())
    };

    tracing::info!(
        "iroh doc door: device {} connected to doc {} (relay/doc/0, channel {:?})",
        remote,
        doc_id,
        channel
    );

    // Writer task: outbound y-protocol messages, length-prefixed.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let len = (msg.len() as u32).to_be_bytes();
            if send.write_all(&len).await.is_err() {
                break;
            }
            if send.write_all(&msg).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    let tx_cb = tx.clone();
    let mut doc_conn =
        DocConnection::new_with_expiration(awareness, Authorization::Full, None, move |bytes| {
            if tx_cb.try_send(bytes.to_vec()).is_err() {
                tracing::warn!("iroh doc door: outbound channel full/closed; dropping message");
            }
        });
    doc_conn.set_sync_kv(sync_kv);
    let doc_conn = std::sync::Arc::new(doc_conn);
    // Register with the sync-protocol event sender so document.updated
    // events routed to this doc (as a channel) reach subscribers on this
    // connection — the WS path does the same.
    server
        .sync_protocol_event_sender
        .register_doc_connection(doc_id.clone(), std::sync::Arc::downgrade(&doc_conn));

    loop {
        match read_frame(&mut recv, MAX_DOC_FRAME_BYTES).await {
            Ok(Some(msg)) => {
                if let Err(e) = doc_conn.send(&msg).await {
                    tracing::warn!("iroh doc door: error on doc {}: {}", doc_id, e);
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("iroh doc door: doc {} stream closed: {}", doc_id, e);
                break;
            }
        }
    }

    tracing::info!(
        "iroh doc door: device {} disconnected from doc {}",
        remote,
        doc_id
    );
    drop(doc_conn); // clears this client's awareness state
    drop(tx);
    let _ = writer.await;
    Ok(())
}

fn parse_request(request: &[u8]) -> Option<(u8, String, &[u8])> {
    if request.len() < 3 {
        return None;
    }
    let verb = request[0];
    let key_len = u16::from_be_bytes([request[1], request[2]]) as usize;
    if request.len() < 3 + key_len {
        return None;
    }
    let key = std::str::from_utf8(&request[3..3 + key_len])
        .ok()?
        .to_string();
    Some((verb, key, &request[3 + key_len..]))
}

async fn handle_request(server: &Server, request: &[u8]) -> Vec<u8> {
    let Some((verb, key, value)) = parse_request(request) else {
        return vec![STATUS_ERROR];
    };
    let Some(store) = server.kv_store() else {
        return vec![STATUS_ERROR];
    };
    // Keys arrive namespace-first ("<ns>/o/…"), mirroring the HTTP
    // door's path shape. Allowlisted devices may use any namespace
    // until the control plane's device→namespace registry exists.
    let Some((ns, rest)) = key.split_once('/') else {
        return vec![STATUS_ERROR];
    };
    if ns.is_empty() || rest.is_empty() {
        return vec![STATUS_ERROR];
    }
    let ns_key = format!(
        "kv/{}/{}",
        ns,
        key.split_once('/').map(|(_, r)| r).unwrap_or("")
    );
    let _ = rest;
    match verb {
        VERB_GET => match store.get(&ns_key).await {
            Ok(Some(bytes)) => {
                let mut out = vec![STATUS_OK];
                out.extend_from_slice(&bytes);
                out
            }
            Ok(None) => vec![STATUS_NOT_FOUND],
            Err(_) => vec![STATUS_ERROR],
        },
        VERB_PUT => match store.set(&ns_key, value.to_vec()).await {
            Ok(()) => vec![STATUS_OK],
            Err(_) => vec![STATUS_ERROR],
        },
        VERB_HAS => match store.exists(&ns_key).await {
            Ok(true) => vec![STATUS_OK],
            Ok(false) => vec![STATUS_NOT_FOUND],
            Err(_) => vec![STATUS_ERROR],
        },
        VERB_LIST => match store.list(&ns_key).await {
            Ok(files) => {
                let root = format!("kv/{}/", ns);
                let keys: Vec<String> = files
                    .into_iter()
                    .filter_map(|f| f.key.strip_prefix(&root).map(|k| k.to_string()))
                    .collect();
                let mut out = vec![STATUS_OK];
                out.extend_from_slice(serde_json::to_string(&keys).unwrap_or_default().as_bytes());
                out
            }
            Err(_) => vec![STATUS_ERROR],
        },
        _ => vec![STATUS_ERROR],
    }
}
