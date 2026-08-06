//! Smoke round-trip against the blind store over iroh (ALPN relay/kv/0).
//!
//! Dials the server by EndpointID (n0 discovery), optionally with
//! direct socket addresses to skip discovery, and exercises all four
//! verbs: PUT, HAS, GET, LIST.
//!
//! Usage:
//!   kv_smoke <server_endpoint_id_hex> <namespace> [direct_addr ...]
//!
//! Wire protocol (one EOF-delimited bi-stream per request):
//!   request  = [verb u8][key_len u16 BE][key utf8][value bytes…]
//!   response = [status u8][payload bytes…]
//!   verbs: 0 GET, 1 PUT, 2 HAS, 3 LIST   status: 0 ok, 1 nf, 2 denied, 3 err

use anyhow::Context;

const KV_ALPN: &[u8] = b"relay/kv/0";

const VERB_GET: u8 = 0;
const VERB_PUT: u8 = 1;
const VERB_HAS: u8 = 2;
const VERB_LIST: u8 = 3;

fn from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

async fn request(
    conn: &iroh::endpoint::Connection,
    verb: u8,
    key: &str,
    value: &[u8],
) -> anyhow::Result<(u8, Vec<u8>)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut req = vec![verb];
    req.extend_from_slice(&(key.len() as u16).to_be_bytes());
    req.extend_from_slice(key.as_bytes());
    req.extend_from_slice(value);
    send.write_all(&req).await?;
    send.finish()?;
    let resp = recv.read_to_end(16 * 1024 * 1024).await?;
    anyhow::ensure!(!resp.is_empty(), "empty response");
    Ok((resp[0], resp[1..].to_vec()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: kv_smoke <server_endpoint_id_hex> <namespace> [direct_addr ...]");
        std::process::exit(2);
    }
    let id_bytes: [u8; 32] = from_hex(&args[1])
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .context("endpoint id must be 64 hex chars")?;
    let id = iroh::EndpointId::from_bytes(&id_bytes)?;
    let addr = if args.len() > 3 {
        iroh::EndpointAddr::from_parts(
            id,
            args[3..]
                .iter()
                .map(|a| Ok(iroh::TransportAddr::Ip(a.parse()?)))
                .collect::<anyhow::Result<Vec<_>>>()?,
        )
    } else {
        iroh::EndpointAddr::from(id)
    };
    let ns = &args[2];

    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .bind()
        .await?;
    println!("client endpoint id: {}", endpoint.id());
    println!("dialing {} on ALPN {:?} ...", args[1], KV_ALPN);
    let conn = endpoint.connect(addr, KV_ALPN).await?;
    println!("connected");

    let key = format!("{ns}/o/deadbeefcafe");
    let value = b"iroh blind store smoke test";

    let (s, _) = request(&conn, VERB_PUT, &key, value).await?;
    println!("PUT  {key} -> status {s}");
    anyhow::ensure!(s == 0, "put failed");

    let (s, _) = request(&conn, VERB_HAS, &key, &[]).await?;
    println!("HAS  {key} -> status {s}");
    anyhow::ensure!(s == 0, "has failed");

    let (s, payload) = request(&conn, VERB_GET, &key, &[]).await?;
    println!(
        "GET  {key} -> status {s}, {} bytes, match={}",
        payload.len(),
        payload == value
    );
    anyhow::ensure!(s == 0 && payload == value, "get round-trip mismatch");

    let (s, payload) = request(&conn, VERB_LIST, &format!("{ns}/o/"), &[]).await?;
    println!(
        "LIST {ns}/o/ -> status {s}, keys: {}",
        String::from_utf8_lossy(&payload)
    );
    anyhow::ensure!(s == 0, "list failed");

    let (s, _) = request(&conn, VERB_HAS, &format!("{ns}/o/0000missing"), &[]).await?;
    println!("HAS  {ns}/o/0000missing -> status {s} (expect 1 not-found)");
    anyhow::ensure!(s == 1, "expected not-found");

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    println!("smoke round-trip OK");
    Ok(())
}
