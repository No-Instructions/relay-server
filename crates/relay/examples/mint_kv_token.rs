//! Mint a CWT bearing the kv grant claim (-80203) — demo tooling.
//!
//! The grant grammar is "kv:<ns-prefix>:<r|rw>[:<limit-bytes>]"; the
//! audience must equal the server's configured `server.url`.
//!
//! Usage:
//!   mint_kv_token <private_key_b64> <audience> <ns-prefix> <r|rw> [limit_bytes|-] [ttl_secs] [user]

use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::{Authenticator, ExpirationTimeEpochMillis, KvGrant};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: mint_kv_token <private_key_b64> <audience> <ns-prefix> <r|rw> [limit_bytes|-] [ttl_secs] [user]"
        );
        std::process::exit(2);
    }
    let mut auth = Authenticator::new(&args[1])?;
    auth.set_expected_audience(Some(args[2].clone()));
    let authorization = match args[4].as_str() {
        "r" => Authorization::ReadOnly,
        "rw" => Authorization::Full,
        other => anyhow::bail!("mode must be r|rw, got {other}"),
    };
    let limit_bytes = args
        .get(5)
        .filter(|s| s.as_str() != "-")
        .and_then(|s| s.parse::<u64>().ok());
    let ttl_secs: u64 = args.get(6).and_then(|s| s.parse().ok()).unwrap_or(86_400);
    let user = args.get(7).cloned();
    let grant = KvGrant {
        prefix: args[3].clone(),
        authorization,
        limit_bytes,
        user,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let token = auth.gen_kv_token_cwt(&grant, ExpirationTimeEpochMillis(now_ms + ttl_secs * 1000))?;
    println!("{token}");
    Ok(())
}
