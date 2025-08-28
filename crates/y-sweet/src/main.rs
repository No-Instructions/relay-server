use anyhow::Context;
use anyhow::Result;
use axum::middleware;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;
use y_sweet::cli::{print_auth_message, print_server_url, sign_stdin, verify_stdin};
use y_sweet::server::AllowedHost;
use y_sweet::stores::filesystem::FileSystemStore;
use y_sweet_core::{
    auth::Authenticator,
    store::{
        s3::{S3Config, S3Store},
        Store,
    },
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn generate_public_key_from_private(private_key_b64: &str) -> Result<String, anyhow::Error> {
    use p256::SecretKey;
    use y_sweet_core::auth::BASE64_CUSTOM;

    let private_key_bytes = BASE64_CUSTOM.decode(private_key_b64.as_bytes())?;
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;
    let public_key = secret_key.public_key();
    let public_key_bytes = public_key.to_sec1_bytes();

    Ok(BASE64_CUSTOM.encode(&public_key_bytes))
}

#[derive(Clone, ValueEnum)]
enum KeyType {
    #[value(name = "HMAC-SHA-256")]
    HmacSha256,
    #[value(name = "ES256")]
    Es256,
}

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    subcmd: ServSubcommand,
}

#[derive(Subcommand)]
enum ServSubcommand {
    Serve {
        #[clap(env = "RELAY_SERVER_STORAGE")]
        store: Option<String>,

        #[clap(long, default_value = "8080", env = "PORT")]
        port: u16,
        #[clap(long, env = "RELAY_SERVER_HOST")]
        host: Option<IpAddr>,
        #[clap(long, default_value = "9090", env = "METRICS_PORT")]
        metrics_port: u16,
        #[clap(
            long,
            default_value = "10",
            env = "RELAY_SERVER_CHECKPOINT_FREQ_SECONDS"
        )]
        checkpoint_freq_seconds: u64,

        #[clap(long, env = "RELAY_SERVER_AUTH")]
        auth: Option<String>,

        #[clap(long, env = "RELAY_SERVER_URL")]
        url_prefix: Option<Url>,

        #[clap(long, env = "RELAY_SERVER_ALLOWED_HOSTS", value_delimiter = ',')]
        allowed_hosts: Option<Vec<String>>,

        #[clap(long)]
        prod: bool,
    },

    GenAuth {
        #[clap(long)]
        json: bool,

        #[clap(long, default_value = "HMAC-SHA-256")]
        key_type: KeyType,
    },

    /// Convert from a YDoc v1 update format to a .ysweet file.
    /// The YDoc update should be passed in via stdin.
    ConvertFromUpdate {
        /// The store to write the document to.
        #[clap(env = "RELAY_SERVER_STORAGE")]
        store: String,

        /// The ID of the document to write.
        doc_id: String,
    },

    Version,

    ServeDoc {
        #[clap(long, default_value = "8080", env = "PORT")]
        port: u16,

        #[clap(long, env = "RELAY_SERVER_HOST")]
        host: Option<IpAddr>,

        #[clap(
            long,
            default_value = "10",
            env = "RELAY_SERVER_CHECKPOINT_FREQ_SECONDS"
        )]
        checkpoint_freq_seconds: u64,
    },

    Sign {
        #[clap(long, env = "RELAY_SERVER_AUTH")]
        auth: String,
    },

    Verify {
        #[clap(long, env = "RELAY_SERVER_AUTH")]
        auth: String,

        #[clap(long)]
        doc_id: Option<String>,

        #[clap(long)]
        file_hash: Option<String>,
    },
}

fn get_store_from_opts(store_path: &str) -> Result<Box<dyn Store>> {
    if store_path.starts_with("s3://") {
        // Set the RELAY_SERVER_STORAGE environment variable so S3Config::from_env can use it
        env::set_var("RELAY_SERVER_STORAGE", store_path);

        // Use the unified S3Config::from_env method
        let config = S3Config::from_env(None, None)?;
        let store = S3Store::new(config);
        Ok(Box::new(store))
    } else {
        Ok(Box::new(FileSystemStore::new(PathBuf::from(store_path))?))
    }
}

fn parse_allowed_hosts(hosts: Vec<String>) -> Result<Vec<AllowedHost>> {
    let mut parsed_hosts = Vec::new();

    for host_str in hosts {
        if host_str.starts_with("http://") || host_str.starts_with("https://") {
            let url = Url::parse(&host_str)
                .with_context(|| format!("Invalid URL in allowed hosts: {}", host_str))?;

            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("No host in URL: {}", host_str))?;

            parsed_hosts.push(AllowedHost {
                host: host.to_string(),
                scheme: url.scheme().to_string(),
            });
        } else {
            // Assume http for hosts without schemes
            parsed_hosts.push(AllowedHost {
                host: host_str,
                scheme: "http".to_string(),
            });
        }
    }

    Ok(parsed_hosts)
}

fn generate_allowed_hosts(
    url_prefix: Option<&Url>,
    explicit_hosts: Option<Vec<String>>,
) -> Result<Vec<AllowedHost>> {
    if let Some(hosts) = explicit_hosts {
        // Parse explicit hosts with schemes
        parse_allowed_hosts(hosts)
    } else if let Some(prefix) = url_prefix {
        // Auto-generate from url_prefix + flycast
        let mut hosts = vec![AllowedHost {
            host: prefix.host_str().unwrap().to_string(),
            scheme: prefix.scheme().to_string(),
        }];

        // Add flycast if FLY_APP_NAME is set
        if let Ok(app_name) = env::var("FLY_APP_NAME") {
            hosts.push(AllowedHost {
                host: format!("{}.flycast", app_name),
                scheme: "http".to_string(),
            });
        }

        Ok(hosts)
    } else {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    match &opts.subcmd {
        ServSubcommand::Serve {
            port,
            host,
            metrics_port,
            checkpoint_freq_seconds,
            store,
            auth,
            url_prefix,
            allowed_hosts,
            prod,
        } => {
            let auth = if let Some(auth) = auth {
                Some(Authenticator::new(auth)?)
            } else {
                tracing::warn!("No auth key set. Only use this for local development!");
                None
            };

            let addr = SocketAddr::new(
                host.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                *port,
            );

            let listener = TcpListener::bind(addr).await?;
            let addr = listener.local_addr()?;

            let metrics_addr = SocketAddr::new(
                host.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                *metrics_port,
            );
            let metrics_listener = TcpListener::bind(metrics_addr).await?;
            let metrics_addr = metrics_listener.local_addr()?;

            let store = if let Some(store) = store {
                let store = get_store_from_opts(store)?;
                store.init().await?;
                Some(store)
            } else {
                tracing::warn!("No store set. Documents will be stored in memory only.");
                None
            };

            let allowed_hosts = generate_allowed_hosts(url_prefix.as_ref(), allowed_hosts.clone())?;

            if !prod {
                print_server_url(auth.as_ref(), url_prefix.as_ref(), addr);
            }

            let token = CancellationToken::new();

            // Load webhook configs from environment for now (store loading can be added later)
            let webhook_configs = y_sweet::webhook::load_webhook_configs();
            if let Some(ref configs) = webhook_configs {
                tracing::info!(
                    "Loaded {} webhook configurations from environment",
                    configs.len()
                );
            }

            let server = y_sweet::server::Server::new(
                store,
                std::time::Duration::from_secs(*checkpoint_freq_seconds),
                auth,
                url_prefix.clone(),
                allowed_hosts,
                token.clone(),
                true,
                webhook_configs,
            )
            .await?;

            let prod = *prod;
            let server = Arc::new(server);

            let main_handle = tokio::spawn({
                let server = server.clone();
                let token = token.clone();
                async move {
                    let routes = server.routes();
                    let app = routes.layer(middleware::from_fn(
                        y_sweet::server::Server::version_header_middleware,
                    ));
                    let app = if prod {
                        app
                    } else {
                        app.layer(middleware::from_fn(
                            y_sweet::server::Server::redact_error_middleware,
                        ))
                    };
                    axum::serve(listener, app.into_make_service())
                        .with_graceful_shutdown(async move { token.cancelled().await })
                        .await
                        .unwrap();
                }
            });

            let metrics_handle = tokio::spawn({
                let server = server.clone();
                let token = token.clone();
                async move {
                    let metrics_routes = server.metrics_routes();
                    axum::serve(metrics_listener, metrics_routes.into_make_service())
                        .with_graceful_shutdown(async move { token.cancelled().await })
                        .await
                        .unwrap();
                }
            });

            tracing::info!("Listening on ws://{}", addr);
            tracing::info!("Metrics listening on http://{}", metrics_addr);

            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");

            tracing::info!("Shutting down.");
            token.cancel();

            let _ = tokio::join!(main_handle, metrics_handle);
            tracing::info!("Server shut down.");
        }
        ServSubcommand::GenAuth { json, key_type } => {
            let auth = match key_type {
                KeyType::HmacSha256 => Authenticator::gen_key_hmac()?,
                KeyType::Es256 => Authenticator::gen_key_ecdsa()?,
            };

            if *json {
                let mut result = json!({
                    "private_key": auth.private_key(),
                    "server_token": auth.server_token(),
                });

                // For ES256, also include public key
                if matches!(key_type, KeyType::Es256) {
                    if let Ok(public_key) = generate_public_key_from_private(&auth.private_key()) {
                        result
                            .as_object_mut()
                            .unwrap()
                            .insert("public_key".to_string(), json!(public_key));
                    }
                }

                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_auth_message(&auth);

                // For ES256, also print public key
                if matches!(key_type, KeyType::Es256) {
                    if let Ok(public_key) = generate_public_key_from_private(&auth.private_key()) {
                        println!("Public key for ES256:");
                        println!("   {}", public_key);
                        println!();
                    }
                }
            }
        }
        ServSubcommand::ConvertFromUpdate { store, doc_id } => {
            let store = get_store_from_opts(store)?;
            store.init().await?;

            let mut stdin = tokio::io::stdin();
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).await?;

            y_sweet::convert::convert(store, &buf, doc_id).await?;
        }
        ServSubcommand::Version => {
            println!("{}", VERSION);
        }
        ServSubcommand::Sign { auth } => {
            let authenticator = Authenticator::new(auth)?;
            sign_stdin(&authenticator).await?;
        }
        ServSubcommand::Verify {
            auth,
            doc_id,
            file_hash,
        } => {
            let authenticator = Authenticator::new(auth)?;
            // Use the doc_id if provided, otherwise use file_hash if provided
            let id = doc_id.as_deref().or(file_hash.as_deref());
            verify_stdin(&authenticator, id).await?;
        }

        ServSubcommand::ServeDoc {
            port,
            host,
            checkpoint_freq_seconds,
        } => {
            let doc_id = env::var("SESSION_BACKEND_KEY").expect("SESSION_BACKEND_KEY must be set");

            let store = if let Ok(bucket) = env::var("STORAGE_BUCKET") {
                let prefix = if let Ok(prefix) = env::var("STORAGE_PREFIX") {
                    // If the prefix is set, it should contain the document ID as its last '/'-separated part.
                    // We want to pop that, because we will add it back when accessing the doc.
                    let mut parts: Vec<&str> = prefix.split('/').collect();
                    if let Some(last) = parts.pop() {
                        if last != doc_id {
                            anyhow::bail!("STORAGE_PREFIX must end with the document ID. Found: {} Expected: {}", last, doc_id);
                        }

                        let prefix = parts.join("/");
                        Some(prefix)
                    } else {
                        // As far as y-sweet is concerned, `STORAGE_BUCKET` = "" is equivalent to `STORAGE_BUCKET` not being set.
                        None
                    }
                } else {
                    None
                };

                // Use the unified S3Config::from_env method with explicit bucket and prefix
                let s3_config = S3Config::from_env(Some(bucket), prefix)?;
                let store = S3Store::new(s3_config);
                let store: Box<dyn Store> = Box::new(store);
                store.init().await?;
                Some(store)
            } else {
                if env::var("STORAGE_PREFIX").is_ok() {
                    anyhow::bail!("If STORAGE_PREFIX is set, STORAGE_BUCKET must also be set.");
                }

                None
            };

            let cancellation_token = CancellationToken::new();

            // Load webhook configs from environment for single doc mode
            let webhook_configs = y_sweet::webhook::load_webhook_configs();
            if let Some(ref configs) = webhook_configs {
                tracing::info!(
                    "Loaded {} webhook configurations for single doc mode from environment",
                    configs.len()
                );
            }

            let server = y_sweet::server::Server::new(
                store,
                std::time::Duration::from_secs(*checkpoint_freq_seconds),
                None,   // No authenticator
                None,   // No URL prefix
                vec![], // No allowed hosts for single doc mode
                cancellation_token.clone(),
                false,
                webhook_configs,
            )
            .await?;

            // Load the one document we're operating with
            server
                .load_doc(&doc_id, None)
                .await
                .context("Failed to load document")?;

            let addr = SocketAddr::new(
                host.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                *port,
            );

            let listener = TcpListener::bind(addr).await?;
            let addr = listener.local_addr()?;

            tokio::spawn(async move {
                server.serve_doc(listener, false).await.unwrap();
            });

            tracing::info!("Listening on http://{}", addr);

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received Ctrl+C, shutting down.");
                },
                _ = async {
                    #[cfg(unix)]
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                        Ok(mut signal) => signal.recv().await,
                        Err(e) => {
                            tracing::error!("Failed to install SIGTERM handler: {}", e);
                            std::future::pending::<Option<()>>().await
                        }
                    }

                    #[cfg(not(unix))]
                    std::future::pending::<Option<()>>().await
                } => {
                    tracing::info!("Received SIGTERM, shutting down.");
                }
            }

            cancellation_token.cancel();
            tracing::info!("Server shut down.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_allowed_hosts() {
        let hosts = vec![
            "https://api.example.com".to_string(),
            "http://app.flycast".to_string(),
            "localhost".to_string(),
        ];

        let parsed = parse_allowed_hosts(hosts).unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].host, "api.example.com");
        assert_eq!(parsed[0].scheme, "https");
        assert_eq!(parsed[1].host, "app.flycast");
        assert_eq!(parsed[1].scheme, "http");
        assert_eq!(parsed[2].host, "localhost");
        assert_eq!(parsed[2].scheme, "http");
    }

    #[test]
    fn test_generate_allowed_hosts_explicit() {
        let explicit_hosts = Some(vec![
            "https://api.example.com".to_string(),
            "http://app.flycast".to_string(),
        ]);

        let hosts = generate_allowed_hosts(None, explicit_hosts).unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");
        assert_eq!(hosts[1].host, "app.flycast");
        assert_eq!(hosts[1].scheme, "http");
    }

    #[test]
    fn test_generate_allowed_hosts_from_prefix() {
        let url_prefix: Url = "https://api.example.com".parse().unwrap();

        // Without FLY_APP_NAME
        env::remove_var("FLY_APP_NAME");
        let hosts = generate_allowed_hosts(Some(&url_prefix), None).unwrap();

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");

        // With FLY_APP_NAME
        env::set_var("FLY_APP_NAME", "my-app");
        let hosts = generate_allowed_hosts(Some(&url_prefix), None).unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");
        assert_eq!(hosts[1].host, "my-app.flycast");
        assert_eq!(hosts[1].scheme, "http");

        // Clean up
        env::remove_var("FLY_APP_NAME");
    }

    #[test]
    fn test_generate_allowed_hosts_empty() {
        let hosts = generate_allowed_hosts(None, None).unwrap();
        assert_eq!(hosts.len(), 0);
    }

    #[test]
    fn test_fly_io_scenario() {
        // Simulate a Fly.io deployment scenario
        env::set_var("FLY_APP_NAME", "my-relay-server");

        let url_prefix: Url = "https://api.mycompany.com".parse().unwrap();
        let hosts = generate_allowed_hosts(Some(&url_prefix), None).unwrap();

        // Should have both external and internal hosts
        assert_eq!(hosts.len(), 2);

        // External host for public access
        assert_eq!(hosts[0].host, "api.mycompany.com");
        assert_eq!(hosts[0].scheme, "https");

        // Internal flycast host for internal access
        assert_eq!(hosts[1].host, "my-relay-server.flycast");
        assert_eq!(hosts[1].scheme, "http");

        env::remove_var("FLY_APP_NAME");
    }
}
