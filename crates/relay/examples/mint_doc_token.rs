//! Mint an audience-bound CWT doc token — demo tooling.
//!
//! Works around y-sign on this branch minting `document` tokens without
//! the audience claim (only its `server` branch sets the audience),
//! which an audience-validating server refuses.
//!
//! Usage:
//!   mint_doc_token <private_key_b64> <audience> <doc_id> <r|rw> [ttl_secs] [user]

use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::{Authenticator, ExpirationTimeEpochMillis};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: mint_doc_token <private_key_b64> <audience> <doc_id> <r|rw> [ttl_secs] [user]");
        std::process::exit(2);
    }
    let mut auth = Authenticator::new(&args[1])?;
    auth.set_expected_audience(Some(args[2].clone()));
    let authorization = match args[4].as_str() {
        "r" => Authorization::ReadOnly,
        "rw" => Authorization::Full,
        other => anyhow::bail!("mode must be r|rw, got {other}"),
    };
    let ttl_secs: u64 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(86_400);
    let user = args.get(6).map(|s| s.as_str());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let token = auth.gen_doc_token_cwt(
        &args[3],
        authorization,
        ExpirationTimeEpochMillis(now_ms + ttl_secs * 1000),
        user,
        None,
    )?;
    println!("{token}");
    Ok(())
}
