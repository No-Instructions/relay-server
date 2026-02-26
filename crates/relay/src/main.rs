use anyhow::Context;
use anyhow::Result;
use axum::middleware;
use clap::{Parser, Subcommand, ValueEnum};
use relay::cli::{print_auth_message, sign_stdin, verify_stdin};
use relay::server::AllowedHost;
use relay::stores::filesystem::FileSystemStore;
use serde_json::json;
use std::{
    collections::BTreeMap,
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
use y_sweet_core::{
    auth::Authenticator,
    config::Config,
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

fn generate_ed25519_public_key_from_private(
    private_key_b64: &str,
) -> Result<String, anyhow::Error> {
    use ed25519_dalek::{SecretKey as Ed25519SecretKey, SigningKey};
    use y_sweet_core::auth::BASE64_CUSTOM;

    let private_key_bytes = BASE64_CUSTOM.decode(private_key_b64.as_bytes())?;
    let secret_key: Ed25519SecretKey = private_key_bytes.as_slice().try_into()?;
    let signing_key = SigningKey::from(&secret_key);
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    Ok(BASE64_CUSTOM.encode(&public_key_bytes))
}

#[derive(Clone, ValueEnum)]
enum KeyType {
    #[value(name = "legacy")]
    Legacy,
    #[value(name = "HMAC256")]
    Hmac256,
    #[value(name = "ES256")]
    Es256,
    #[value(name = "EdDSA")]
    EdDsa,
}

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    subcmd: ServSubcommand,
}

#[derive(Subcommand)]
enum ServSubcommand {
    Serve {
        /// Path to configuration file
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,

        // Legacy CLI arguments - kept for backward compatibility
        #[clap()]
        store: Option<String>,

        #[clap(long)]
        port: Option<u16>,
        #[clap(long)]
        host: Option<IpAddr>,
        #[clap(long)]
        metrics_port: Option<u16>,
        #[clap(long)]
        checkpoint_freq_seconds: Option<u64>,

        #[clap(long)]
        auth: Option<String>,

        #[clap(long)]
        url: Option<String>,

        #[clap(long, value_delimiter = ',')]
        allowed_hosts: Option<Vec<String>>,
    },

    GenAuth {
        #[clap(long)]
        json: bool,

        #[clap(long, default_value = "legacy")]
        key_type: KeyType,
    },

    /// Convert from a YDoc v1 update format to a .ysweet file.
    /// The YDoc update should be passed in via stdin.
    ConvertFromUpdate {
        /// The store to write the document to.
        #[clap()]
        store: String,

        /// The ID of the document to write.
        doc_id: String,
    },

    Version,

    /// Configuration management commands
    Config {
        #[clap(subcommand)]
        cmd: ConfigSubcommand,
    },

    ServeDoc {
        #[clap(long)]
        port: Option<u16>,

        #[clap(long)]
        host: Option<IpAddr>,

        #[clap(long)]
        checkpoint_freq_seconds: Option<u64>,
    },

    /// Read a .ysweet file and dump its contents.
    DumpDoc {
        /// Path to the .ysweet file to dump.
        #[clap()]
        path: PathBuf,

        /// Also print the raw key-value entries.
        #[clap(long)]
        keys: bool,
    },

    /// Garbage-collect a .ysweet file by rebuilding the Yrs document fresh,
    /// compacting PermanentUserData (dedup ids, merge ds entries), and
    /// eliminating all tombstones.
    GcDoc {
        /// Path to the .ysweet file to GC.
        #[clap()]
        path: PathBuf,

        /// Output path (defaults to <path>.gc).
        #[clap(short, long)]
        output: Option<PathBuf>,
    },

    /// Compact PermanentUserData in a .ysweet file by clearing ds (delete-set
    /// attribution) arrays for each user.  This is safe for live documents:
    /// it mutates the existing Yrs doc in-place (preserving all client IDs,
    /// state vectors, and CRDT history) and writes the result to the output
    /// path.  Connected clients will receive the ds deletions via normal sync.
    CompactPud {
        /// Path to the .ysweet file to compact.
        #[clap()]
        path: PathBuf,

        /// Output path (defaults to <path>.compact).
        #[clap(short, long)]
        output: Option<PathBuf>,

        /// Dry-run: show what would be removed without writing anything.
        #[clap(long)]
        dry_run: bool,
    },

    Sign {
        #[clap(long)]
        auth: String,
    },

    Verify {
        #[clap(long)]
        auth: String,

        #[clap(long)]
        doc_id: Option<String>,

        #[clap(long)]
        file_hash: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigSubcommand {
    /// Validate a TOML configuration file
    Validate {
        /// Path to configuration file to validate
        #[clap(short = 'c', long = "config", default_value = "relay.toml")]
        config: PathBuf,
    },

    /// Show the current configuration (merged from file and environment)
    Show {
        /// Path to configuration file
        #[clap(short = 'c', long = "config", default_value = "relay.toml")]
        config: PathBuf,
    },
}

fn load_config_for_serve_args(
    config: Option<&PathBuf>,
    // CLI overrides
    store: &Option<String>,
    port: &Option<u16>,
    host: &Option<IpAddr>,
    metrics_port: &Option<u16>,
    checkpoint_freq_seconds: &Option<u64>,
    auth: &Option<String>,
    url: &Option<String>,
    allowed_hosts: &Option<Vec<String>>,
) -> Result<Config> {
    // Load base configuration
    let mut config = Config::load(config.as_deref().map(|v| v.as_path()))?;

    // Apply CLI overrides (these have highest precedence)
    if let Some(store_path) = store {
        use y_sweet_core::config::{FilesystemStoreConfig, S3StoreConfig, StoreConfig};

        if store_path.starts_with("s3://") {
            let url = Url::parse(store_path)?;
            let bucket = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid S3 URL: missing bucket"))?
                .to_string();
            let prefix = url.path().trim_start_matches('/');
            let prefix = if prefix.is_empty() {
                String::new()
            } else {
                prefix.to_string()
            };

            config.store = StoreConfig::S3(S3StoreConfig {
                bucket,
                prefix,
                region: env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
                endpoint: String::new(),
                path_style: false,
                presigned_url_expiration: 3600,
                access_key_id: None,
                secret_access_key: None,
            });
        } else {
            config.store = StoreConfig::Filesystem(FilesystemStoreConfig {
                path: store_path.clone(),
            });
        }
    }

    // Override server settings with CLI args (always apply when provided)
    if let Some(port_val) = port {
        config.server.port = *port_val;
    }
    if let Some(port) = metrics_port {
        if config.metrics.is_none() {
            config.metrics = Some(y_sweet_core::config::MetricsConfig { port: *port });
        } else if let Some(ref mut metrics_config) = config.metrics {
            metrics_config.port = *port;
        }
    }
    if let Some(freq) = checkpoint_freq_seconds {
        config.server.checkpoint_freq_seconds = *freq;
    }

    if let Some(host) = host {
        config.server.host = host.to_string();
    }

    if let Some(auth_key) = auth {
        if config.auth.is_empty() {
            config.auth.push(y_sweet_core::config::AuthKeyConfig {
                key_id: None,
                private_key: Some(auth_key.clone()),
                public_key: None,
                allowed_token_types: vec![
                    y_sweet_core::config::TokenType::Document,
                    y_sweet_core::config::TokenType::File,
                    y_sweet_core::config::TokenType::Server,
                    y_sweet_core::config::TokenType::Prefix,
                ],
            });
        } else {
            // Update the first auth entry
            config.auth[0].private_key = Some(auth_key.clone());
        }
    }

    if let Some(url) = url {
        config.server.url = Some(url.clone());
    }

    if let Some(allowed_hosts) = allowed_hosts {
        let parsed_hosts = parse_allowed_hosts(allowed_hosts.clone())?;
        config.server.allowed_hosts = parsed_hosts
            .into_iter()
            .map(|h| y_sweet_core::config::AllowedHost {
                host: h.host,
                scheme: h.scheme,
            })
            .collect();
    }

    Ok(config)
}

fn get_store_from_config(
    store_config: &y_sweet_core::config::StoreConfig,
) -> Result<Option<Box<dyn Store>>> {
    use y_sweet_core::config::StoreConfig;

    match store_config {
        StoreConfig::Memory => Ok(None),
        StoreConfig::Filesystem(fs_config) => {
            let store = FileSystemStore::new(PathBuf::from(&fs_config.path))?;
            Ok(Some(Box::new(store)))
        }
        StoreConfig::S3(s3_config) => {
            // Build S3 configuration from our config
            let s3_store_config = S3Config {
                key: s3_config
                    .access_key_id
                    .clone()
                    .or_else(|| env::var("AWS_ACCESS_KEY_ID").ok())
                    .ok_or_else(|| anyhow::anyhow!("AWS_ACCESS_KEY_ID is required"))?,
                secret: s3_config
                    .secret_access_key
                    .clone()
                    .or_else(|| env::var("AWS_SECRET_ACCESS_KEY").ok())
                    .ok_or_else(|| anyhow::anyhow!("AWS_SECRET_ACCESS_KEY is required"))?,
                token: env::var("AWS_SESSION_TOKEN").ok(),
                endpoint: if s3_config.endpoint.is_empty() {
                    format!("https://s3.dualstack.{}.amazonaws.com", s3_config.region)
                } else {
                    s3_config.endpoint.clone()
                },
                region: s3_config.region.clone(),
                bucket: s3_config.bucket.clone(),
                bucket_prefix: if s3_config.prefix.is_empty() {
                    None
                } else {
                    Some(s3_config.prefix.clone())
                },
                path_style: s3_config.path_style,
            };

            let store = S3Store::new(s3_store_config);
            Ok(Some(Box::new(store)))
        }
        // Convert provider-specific configs to generic S3 config
        StoreConfig::Aws(_)
        | StoreConfig::Cloudflare(_)
        | StoreConfig::Backblaze(_)
        | StoreConfig::Minio(_)
        | StoreConfig::Tigris(_) => {
            let s3_config = store_config
                .to_s3_config()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert provider config to S3 config"))?;

            // Build S3 configuration from our config
            let s3_store_config = S3Config {
                key: s3_config
                    .access_key_id
                    .clone()
                    .or_else(|| env::var("AWS_ACCESS_KEY_ID").ok())
                    .ok_or_else(|| anyhow::anyhow!("AWS_ACCESS_KEY_ID is required"))?,
                secret: s3_config
                    .secret_access_key
                    .clone()
                    .or_else(|| env::var("AWS_SECRET_ACCESS_KEY").ok())
                    .ok_or_else(|| anyhow::anyhow!("AWS_SECRET_ACCESS_KEY is required"))?,
                token: env::var("AWS_SESSION_TOKEN").ok(),
                endpoint: if s3_config.endpoint.is_empty() {
                    format!("https://s3.dualstack.{}.amazonaws.com", s3_config.region)
                } else {
                    s3_config.endpoint.clone()
                },
                region: s3_config.region.clone(),
                bucket: s3_config.bucket.clone(),
                bucket_prefix: if s3_config.prefix.is_empty() {
                    None
                } else {
                    Some(s3_config.prefix.clone())
                },
                path_style: s3_config.path_style,
            };

            let store = S3Store::new(s3_store_config);
            Ok(Some(Box::new(store)))
        }
    }
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
    url: Option<&Url>,
    explicit_hosts: Option<Vec<String>>,
    fly_app_name: Option<&str>,
) -> Result<Vec<AllowedHost>> {
    if let Some(hosts) = explicit_hosts {
        // Parse explicit hosts with schemes
        parse_allowed_hosts(hosts)
    } else if let Some(prefix) = url {
        // Auto-generate from url + flycast
        let mut hosts = vec![AllowedHost {
            host: prefix.host_str().unwrap().to_string(),
            scheme: prefix.scheme().to_string(),
        }];

        // Add flycast if app name is provided
        if let Some(app_name) = fly_app_name {
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
            config,
            port,
            host,
            metrics_port,
            checkpoint_freq_seconds,
            store,
            auth,
            url,
            allowed_hosts,
        } => {
            // Load configuration
            let config = load_config_for_serve_args(
                config.as_ref(),
                store,
                port,
                host,
                metrics_port,
                checkpoint_freq_seconds,
                auth,
                url,
                allowed_hosts,
            )?;

            // Initialize logging based on config
            let log_level = &config.logging.level;
            tracing::info!("Using log level: {}", log_level);

            // Create authenticator from config
            let mut auth = if !config.auth.is_empty() {
                Some(Authenticator::from_multi_key_config(&config.auth)?)
            } else {
                tracing::warn!("No auth key set. Only use this for local development!");
                None
            };

            // Set expected audience for CWT validation if server URL is configured
            if let Some(ref mut authenticator) = auth {
                authenticator.set_expected_audience(config.server.url.clone());
                if let Some(ref url) = config.server.url {
                    tracing::info!("CWT audience validation enabled for: {}", url);
                } else {
                    return Err(anyhow::anyhow!("Server URL is required"));
                }
            }

            // Parse server host
            let server_host: IpAddr = config
                .server
                .host
                .parse()
                .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

            let addr = SocketAddr::new(server_host, config.server.port);
            let listener = TcpListener::bind(addr).await?;
            let addr = listener.local_addr()?;

            // Only bind metrics listener if metrics are enabled
            let metrics_listener_and_addr = if let Some(ref metrics_config) = config.metrics {
                let metrics_addr = SocketAddr::new(server_host, metrics_config.port);
                let metrics_listener = TcpListener::bind(metrics_addr).await?;
                let metrics_addr = metrics_listener.local_addr()?;
                Some((metrics_listener, metrics_addr))
            } else {
                None
            };

            // Create store from config
            let store = if let Some(store) = get_store_from_config(&config.store)? {
                store.init().await?;
                Some(store)
            } else {
                tracing::warn!("No store set. Documents will be stored in memory only.");
                None
            };

            // Parse URL prefix
            let url = config
                .server
                .url
                .as_ref()
                .map(|s| Url::parse(s))
                .transpose()?;

            // Get FLY_APP_NAME once at configuration time to avoid race conditions
            let fly_app_name = env::var("FLY_APP_NAME").ok();

            // Generate allowed hosts (use config + auto-generation from URL prefix)
            let allowed_hosts = if config.server.allowed_hosts.is_empty() {
                // Auto-generate from url if no explicit hosts configured
                generate_allowed_hosts(url.as_ref(), None, fly_app_name.as_deref())?
            } else {
                // Use configured hosts, but also add Fly.io auto-detection if applicable
                let explicit_hosts: Vec<String> = config
                    .server
                    .allowed_hosts
                    .iter()
                    .map(|h| {
                        if h.scheme == "https" || h.scheme == "http" {
                            format!("{}://{}", h.scheme, h.host)
                        } else {
                            h.host.clone()
                        }
                    })
                    .collect();
                generate_allowed_hosts(url.as_ref(), Some(explicit_hosts), fly_app_name.as_deref())?
            };

            let token = CancellationToken::new();

            // Use webhook configs from configuration (TOML file or env vars)
            let webhook_configs = if config.webhooks.is_empty() {
                // Fallback to environment variable for backward compatibility
                relay::webhook::load_webhook_configs()
            } else {
                Some(config.webhooks.clone())
            };

            if let Some(ref configs) = webhook_configs {
                tracing::info!("Loaded {} webhook configurations", configs.len());
            }

            let server = relay::server::Server::new(
                store,
                std::time::Duration::from_secs(config.server.checkpoint_freq_seconds),
                auth,
                url.clone(),
                allowed_hosts,
                token.clone(),
                config.server.doc_gc,
                webhook_configs,
            )
            .await?;

            let redact_errors = config.server.redact_errors;
            let server = Arc::new(server);

            let main_handle = tokio::spawn({
                let server = server.clone();
                let token = token.clone();
                async move {
                    let routes = server.routes();
                    let app = routes.layer(middleware::from_fn(
                        relay::server::Server::version_header_middleware,
                    ));
                    let app = if redact_errors {
                        app.layer(middleware::from_fn(
                            relay::server::Server::redact_error_middleware,
                        ))
                    } else {
                        app
                    };
                    axum::serve(listener, app.into_make_service())
                        .with_graceful_shutdown(async move { token.cancelled().await })
                        .await
                        .unwrap();
                }
            });

            let metrics_addr_for_logging =
                metrics_listener_and_addr.as_ref().map(|(_, addr)| *addr);

            let metrics_handle = if let Some((metrics_listener, _)) = metrics_listener_and_addr {
                Some(tokio::spawn({
                    let server = server.clone();
                    let token = token.clone();
                    async move {
                        let metrics_routes = server.metrics_routes();
                        axum::serve(metrics_listener, metrics_routes.into_make_service())
                            .with_graceful_shutdown(async move { token.cancelled().await })
                            .await
                            .unwrap();
                    }
                }))
            } else {
                None
            };

            tracing::info!("Listening on ws://{}", addr);
            if let Some(metrics_addr) = metrics_addr_for_logging {
                tracing::info!("Metrics listening on http://{}", metrics_addr);
            } else {
                tracing::info!("Metrics disabled");
            }

            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");

            tracing::info!("Shutting down.");
            token.cancel();

            if let Some(metrics_handle) = metrics_handle {
                let _ = tokio::join!(main_handle, metrics_handle);
            } else {
                let _ = main_handle.await;
            }
            tracing::info!("Server shut down.");
        }
        ServSubcommand::GenAuth { json, key_type } => {
            let auth = match key_type {
                KeyType::Legacy => Authenticator::gen_key_legacy()?,
                KeyType::Hmac256 => Authenticator::gen_key_hmac()?,
                KeyType::Es256 => Authenticator::gen_key_ecdsa()?,
                KeyType::EdDsa => Authenticator::gen_key_ed25519()?,
            };

            // Generate a key-id using nanoid
            let key_id = nanoid::nanoid!();

            if *json {
                let mut result = serde_json::Map::new();

                // Add key-id to output
                result.insert("key_id".to_string(), json!(key_id));

                // Generate appropriate server token based on key type
                match auth.key_material() {
                    y_sweet_core::auth::AuthKeyMaterial::Legacy(_) => {
                        // Generate legacy format server token
                        let server_token = auth.server_token_legacy()?;
                        result.insert("server_token".to_string(), json!(server_token));
                    }
                    _ => {
                        // Generate CWT server token for modern keys
                        let server_token = auth.server_token()?;
                        result.insert("server_token".to_string(), json!(server_token));
                    }
                };

                match auth.key_material() {
                    y_sweet_core::auth::AuthKeyMaterial::Legacy(key_bytes) => {
                        result.insert(
                            "private_key".to_string(),
                            json!(y_sweet_core::auth::b64_encode(key_bytes)),
                        );
                    }
                    y_sweet_core::auth::AuthKeyMaterial::Hmac256(key_bytes) => {
                        result.insert(
                            "private_key".to_string(),
                            json!(y_sweet_core::auth::b64_encode(key_bytes)),
                        );
                    }
                    y_sweet_core::auth::AuthKeyMaterial::EcdsaP256Private(key_bytes) => {
                        let private_key_b64 = y_sweet_core::auth::b64_encode(key_bytes);
                        result.insert("private_key".to_string(), json!(private_key_b64));

                        // Also generate and include public key
                        if let Ok(public_key) = generate_public_key_from_private(&private_key_b64) {
                            result.insert("public_key".to_string(), json!(public_key));
                        }
                    }
                    y_sweet_core::auth::AuthKeyMaterial::EcdsaP256Public(key_bytes) => {
                        result.insert(
                            "public_key".to_string(),
                            json!(y_sweet_core::auth::b64_encode(key_bytes)),
                        );
                        // No private_key field for public keys!
                    }
                    y_sweet_core::auth::AuthKeyMaterial::Ed25519Private(key_bytes) => {
                        let private_key_b64 = y_sweet_core::auth::b64_encode(key_bytes);
                        result.insert("private_key".to_string(), json!(private_key_b64));

                        // Also generate and include public key
                        if let Ok(public_key) =
                            generate_ed25519_public_key_from_private(&private_key_b64)
                        {
                            result.insert("public_key".to_string(), json!(public_key));
                        }
                    }
                    y_sweet_core::auth::AuthKeyMaterial::Ed25519Public(key_bytes) => {
                        result.insert(
                            "public_key".to_string(),
                            json!(y_sweet_core::auth::b64_encode(key_bytes)),
                        );
                        // No private_key field for public keys!
                    }
                }

                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Object(result))?
                );
            } else {
                println!("Key ID: {}", key_id);
                println!();
                print_auth_message(&auth);

                // Print additional info based on key type
                match auth.key_material() {
                    y_sweet_core::auth::AuthKeyMaterial::EcdsaP256Private(key_bytes) => {
                        let private_key_b64 = y_sweet_core::auth::b64_encode(key_bytes);
                        if let Ok(public_key) = generate_public_key_from_private(&private_key_b64) {
                            println!("Public key for ES256:");
                            println!("   {}", public_key);
                            println!();
                        }
                    }
                    y_sweet_core::auth::AuthKeyMaterial::EcdsaP256Public(_) => {
                        println!("Note: This is a public key - it can only verify tokens, not create them.");
                        println!();
                    }
                    y_sweet_core::auth::AuthKeyMaterial::Ed25519Private(key_bytes) => {
                        let private_key_b64 = y_sweet_core::auth::b64_encode(key_bytes);
                        if let Ok(public_key) =
                            generate_ed25519_public_key_from_private(&private_key_b64)
                        {
                            println!("Public key for EdDSA:");
                            println!("   {}", public_key);
                            println!();
                        }
                    }
                    y_sweet_core::auth::AuthKeyMaterial::Ed25519Public(_) => {
                        println!("Note: This is a public key - it can only verify tokens, not create them.");
                        println!();
                    }
                    _ => {}
                }
            }
        }
        ServSubcommand::ConvertFromUpdate { store, doc_id } => {
            let store = get_store_from_opts(store)?;
            store.init().await?;

            let mut stdin = tokio::io::stdin();
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).await?;

            relay::convert::convert(store, &buf, doc_id).await?;
        }
        ServSubcommand::Version => {
            println!("{}", VERSION);
        }
        ServSubcommand::Config { cmd } => {
            match cmd {
                ConfigSubcommand::Validate { config } => {
                    println!("Validating configuration file: {}", config.display());

                    match Config::load(Some(config.as_path())) {
                        Ok(config) => {
                            println!("✅ Configuration is valid!");
                            println!();
                            println!("Configuration summary:");
                            println!("  Server: {}:{}", config.server.host, config.server.port);
                            if let Some(ref metrics_config) = config.metrics {
                                println!(
                                    "  Metrics: {}:{}",
                                    config.server.host, metrics_config.port
                                );
                            } else {
                                println!("  Metrics: disabled");
                            }
                            println!(
                                "  Auth: {}",
                                if config.auth.is_empty() {
                                    "disabled"
                                } else {
                                    "enabled"
                                }
                            );
                            println!(
                                "  Store: {}",
                                match &config.store {
                                    y_sweet_core::config::StoreConfig::Memory =>
                                        "Memory".to_string(),
                                    y_sweet_core::config::StoreConfig::Filesystem(fs) =>
                                        format!("Filesystem ({})", fs.path),
                                    y_sweet_core::config::StoreConfig::S3(s3) =>
                                        format!("S3 ({})", s3.bucket),
                                    y_sweet_core::config::StoreConfig::Aws(aws) =>
                                        format!("AWS S3 ({})", aws.bucket),
                                    y_sweet_core::config::StoreConfig::Cloudflare(cf) =>
                                        format!("Cloudflare R2 ({})", cf.bucket),
                                    y_sweet_core::config::StoreConfig::Backblaze(b2) =>
                                        format!("Backblaze B2 ({})", b2.bucket),
                                    y_sweet_core::config::StoreConfig::Minio(minio) =>
                                        format!("MinIO ({} at {})", minio.bucket, minio.endpoint),
                                    y_sweet_core::config::StoreConfig::Tigris(tigris) =>
                                        format!("Tigris ({})", tigris.bucket),
                                }
                            );
                            println!("  Webhooks: {}", config.webhooks.len());
                            println!(
                                "  Logging: {} ({})",
                                config.logging.level, config.logging.format
                            );

                            if let Some(url) = &config.server.url {
                                println!("  URL prefix: {}", url);
                            }

                            if !config.server.allowed_hosts.is_empty() {
                                println!("  Allowed hosts: {}", config.server.allowed_hosts.len());
                                for host in &config.server.allowed_hosts {
                                    println!("    - {}://{}", host.scheme, host.host);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Configuration validation failed:");
                            eprintln!("   {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                ConfigSubcommand::Show { config } => {
                    match Config::load(Some(config.as_path())) {
                        Ok(config) => {
                            // Print environment variables to stderr first
                            config.print_env();

                            println!("Current configuration:");
                            println!();

                            // Convert to regular TOML for display
                            match toml::to_string_pretty(&config) {
                                Ok(toml_str) => println!("{}", toml_str),
                                Err(e) => {
                                    eprintln!("❌ Failed to serialize configuration: {}", e);
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to load configuration:");
                            eprintln!("   {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        ServSubcommand::DumpDoc { path, keys } => {
            dump_ysweet_file(path, *keys)?;
        }
        ServSubcommand::GcDoc { path, output } => {
            let output = output.clone().unwrap_or_else(|| {
                let mut p = path.as_os_str().to_owned();
                p.push(".gc");
                PathBuf::from(p)
            });
            gc_ysweet_file(path, &output)?;
        }
        ServSubcommand::CompactPud { path, output, dry_run } => {
            let output = output.clone().unwrap_or_else(|| {
                let mut p = path.as_os_str().to_owned();
                p.push(".compact");
                PathBuf::from(p)
            });
            compact_pud(path, &output, *dry_run)?;
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
            let webhook_configs = relay::webhook::load_webhook_configs();
            if let Some(ref configs) = webhook_configs {
                tracing::info!(
                    "Loaded {} webhook configurations for single doc mode from environment",
                    configs.len()
                );
            }

            let server = relay::server::Server::new(
                store,
                std::time::Duration::from_secs(checkpoint_freq_seconds.unwrap_or(10)),
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
                port.unwrap_or(8080),
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

// -- dump-doc support --

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

fn deserialize_btree_dump<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde::Deserialize;
    let cbor_value = ciborium::value::Value::deserialize(deserializer)?;
    if let ciborium::value::Value::Map(entries) = cbor_value {
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            if let (ciborium::value::Value::Bytes(key), ciborium::value::Value::Bytes(val)) =
                (k, v)
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
    // Serialize as a CBOR map of Bytes -> Bytes
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

fn format_timestamp_ms(ms: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = UNIX_EPOCH + Duration::from_millis(ms);
    // Best-effort human-readable; fall back to raw ms.
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
    // Key layout from yrs-kvstore:
    //   00{doc_name:N}0       - OID mapping
    //   01{oid:4}0            - document state
    //   01{oid:4}1            - state vector
    //   01{oid:4}2{clock:4}0  - update
    //   01{oid:4}3{name:M}0   - metadata
    if k.len() < 2 {
        return format!("unknown ({})", hex::encode(k));
    }
    let version = k[0];
    let keyspace = k[1];
    match (version, keyspace) {
        (0, 0) => {
            // OID key: 00{doc_name}0
            if k.len() >= 3 && k[k.len() - 1] == 0 {
                let name = &k[2..k.len() - 1];
                let name_str = String::from_utf8_lossy(name);
                format!("OID mapping: \"{}\"", name_str)
            } else {
                format!("OID key (malformed): {}", hex::encode(k))
            }
        }
        (0, 1) => {
            // Document keyspace
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
        _ => format!("unknown (v={}, ks={}): {}", version, keyspace, hex::encode(k)),
    }
}

fn dump_kv_entries(map: &BTreeMap<Vec<u8>, Vec<u8>>, show_keys: bool) {
    let total_key_bytes: usize = map.keys().map(|k| k.len()).sum();
    let total_val_bytes: usize = map.values().map(|v| v.len()).sum();

    // Categorize entries
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
        println!(
            "  Updates:       {} ({} bytes)",
            update_count, update_size
        );
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

    // Try to load as a Yrs document and inspect its contents
    println!();
    dump_yrs_doc(map);
}

fn dump_yrs_doc(map: &BTreeMap<Vec<u8>, Vec<u8>>) {
    use yrs::updates::decoder::Decode;
    use yrs::updates::encoder::Encode;
    use yrs::{Array, Doc, GetString, Map, Out, ReadTxn, StateVector, Transact, Update};

    // Find the doc state entry (key pattern: 01{oid:4}0)
    let doc_state = map.iter().find(|(k, _)| {
        k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0
    });

    let Some((_, doc_state_bytes)) = doc_state else {
        println!("(No doc state entry found, cannot inspect Yrs document)");
        return;
    };

    let doc = Doc::new();
    let mut loaded = false;

    // Apply the main document state
    match Update::decode_v1(doc_state_bytes) {
        Ok(update) => {
            let mut txn = doc.transact_mut();
            txn.apply_update(update);
            loaded = true;
        }
        Err(e) => {
            println!("(Failed to decode doc state as Yrs v1 update: {})", e);
        }
    }

    // Apply any pending updates
    let mut updates_applied = 0;
    for (k, v) in map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 2 {
            match Update::decode_v1(v) {
                Ok(update) => {
                    let mut txn = doc.transact_mut();
                    txn.apply_update(update);
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

    // Show the full state as update size
    let full_update = txn.encode_state_as_update_v1(&StateVector::default());

    // Build the filemeta clock map for filename resolution in deletion analysis
    let filemeta_clock_map = match build_filemeta_clock_map(&full_update) {
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
            println!("  (failed to decode update items for filename mapping: {})", e);
            None
        }
    };

    println!("Yrs document:");
    println!("  Full update size: {} bytes", full_update.len());
    if updates_applied > 0 {
        println!("  (includes {} pending updates)", updates_applied);
    }

    // Show state vector (which clients contributed and how many ops)
    let sv = txn.state_vector();
    let sv_encoded = sv.encode_v1();
    let total_ops: u32 = sv.iter().map(|(_, &clock)| clock).sum();
    println!("  State vector:     {} bytes encoded", sv_encoded.len());
    println!("  Client IDs:       {}", sv.len());
    println!("  Total ops:        {}", total_ops);

    // Analyze delete set (tombstones)
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
    // Extract the doc-level delete set into a standalone structure for later comparison
    // with PermanentUserData ds entries.
    let mut doc_ds_ranges: std::collections::HashMap<u64, Vec<(u32, u32)>> =
        std::collections::HashMap::new();
    for (&client_id, ranges) in ds.iter() {
        let mut sorted: Vec<(u32, u32)> = ranges.iter().map(|r| (r.start, r.end)).collect();
        sorted.sort();
        doc_ds_ranges.insert(client_id, sorted);
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

    // Per-client breakdown (top 10 by ops)
    let mut client_stats: Vec<(u64, u32)> = sv.iter().map(|(&id, &clock)| (id, clock)).collect();
    client_stats.sort_by(|a, b| b.1.cmp(&a.1));
    println!();
    println!("  Top clients by ops:");
    for (i, (client_id, clock)) in client_stats.iter().take(10).enumerate() {
        // Compute per-client diff size to show how much data this client contributes
        // Create an SV that excludes this client
        let mut sv_all_but_one = StateVector::default();
        for (&c, &clk) in sv.iter() {
            if c != *client_id {
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

    // Per-client diffs: show which clients touched each root and what they did.
    println!();
    println!("  Per-client diffs:");
    for (i, (client_id, clock)) in client_stats.iter().enumerate() {
        // Build an SV excluding this client
        let mut sv_without = StateVector::default();
        for (&c, &clk) in sv.iter() {
            if c != *client_id {
                sv_without.set_max(c, clk);
            }
        }
        let diff = txn.encode_diff_v1(&sv_without);

        // Load the diff into a fresh doc to see what this client did
        let diff_doc = Doc::new();
        if let Ok(update) = Update::decode_v1(&diff) {
            let mut diff_txn = diff_doc.transact_mut();
            diff_txn.apply_update(update);
            drop(diff_txn);

            let diff_txn = diff_doc.transact();
            let diff_roots: Vec<_> = diff_txn.root_refs().map(|(n, _)| n.to_string()).collect();
            drop(diff_txn);

            // Collect per-root info
            let mut root_summaries: Vec<String> = Vec::new();
            for root_name in &diff_roots {
                let map_ref = diff_doc.get_or_insert_map(root_name.as_str());
                let diff_txn = diff_doc.transact();
                let keys: Vec<String> = map_ref.keys(&diff_txn).map(|k| k.to_string()).collect();
                drop(diff_txn);

                if root_name == "filemeta_v0" || root_name == "docs" {
                    // Show all keys for these maps
                    if keys.is_empty() {
                        root_summaries.push(format!("{}: (all overwritten)", root_name));
                    } else {
                        root_summaries.push(format!("{}: {} keys", root_name, keys.len()));
                        for k in &keys {
                            // Show value
                            let diff_txn = diff_doc.transact();
                            if let Some(val) = map_ref.get(&diff_txn, k) {
                                let val_desc = match &val {
                                    Out::YMap(m) => {
                                        let inner: Vec<String> = m.iter(&diff_txn).map(|(ik, iv)| {
                                            format!("{}: {:?}", ik, match &iv {
                                                Out::Any(a) => format!("{:?}", a),
                                                Out::YText(t) => t.get_string(&diff_txn),
                                                other => format!("{:?}", other),
                                            })
                                        }).collect();
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

            // Only print clients that touched something interesting
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
    // Delete set breakdown by client
    println!();
    println!("  Delete set breakdown (top 15 by tombstone count):");
    let mut ds_by_client: Vec<(u64, u64, usize)> = Vec::new(); // (client_id, deleted_ops, num_ranges)
    for (&client_id, ranges) in ds.iter() {
        let mut client_deleted: u64 = 0;
        let mut num_ranges: usize = 0;
        for r in ranges.iter() {
            client_deleted += (r.end - r.start) as u64;
            num_ranges += 1;
        }
        ds_by_client.push((client_id, client_deleted, num_ranges));
    }
    ds_by_client.sort_by(|a, b| b.1.cmp(&a.1));
    for (i, (client_id, deleted, num_ranges)) in ds_by_client.iter().take(15).enumerate() {
        let ops_for_client = sv
            .iter()
            .find(|(&c, _)| c == *client_id)
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

    // Per-root size estimation: for each root, create a doc with only that root's data
    // by excluding ops from a carefully constructed SV.
    // Alternative approach: measure doc size with and without each root.
    println!();
    println!("  Per-root size estimation:");
    drop(txn);
    let txn = doc.transact();
    let root_names_for_size: Vec<String> = txn
        .root_refs()
        .map(|(name, _)| name.to_string())
        .collect();
    drop(txn);

    // Get the full update size as baseline
    let txn = doc.transact();
    let full_update = txn.encode_state_as_update_v1(&StateVector::default());
    let _full_size = full_update.len();
    drop(txn);

    // For each root, create a doc WITHOUT that root and measure the difference
    for root_name in &root_names_for_size {
        // Build a doc with all roots except this one
        let partial_doc = Doc::new();
        {
            let txn = doc.transact();
            let full_update_bytes = txn.encode_state_as_update_v1(&StateVector::default());
            drop(txn);

            if let Ok(update) = Update::decode_v1(&full_update_bytes) {
                let mut txn = partial_doc.transact_mut();
                txn.apply_update(update);
            }
        }

        // Clear this root by getting a reference and measuring state before/after
        // Actually we can't easily remove a root. Instead, create a doc with ONLY this root.
        // We'll use a different approach: for each root, measure the diff that contains
        // ops from clients that ONLY wrote to this root.
        // Simpler: just show how much data each root's current values occupy.
        let map_ref = doc.get_or_insert_map(root_name.as_str());
        let txn = doc.transact();
        let len = map_ref.len(&txn);

        // Estimate: encode each value separately
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

    // PermanentUserData ds analysis
    println!();
    println!("  PermanentUserData ds array analysis:");
    let users_map = doc.get_or_insert_map("users");
    let txn = doc.transact();
    let mut total_ds_elements = 0u32;
    let mut total_ds_decoded_ops = 0u64;
    for (user_id, user_val) in users_map.iter(&txn) {
        if let Out::YMap(user_map) = &user_val {
            // Check ids array
            let ids_info = if let Some(Out::YArray(ids_arr)) = user_map.get(&txn, "ids") {
                let mut client_ids = Vec::new();
                for item in ids_arr.iter(&txn) {
                    if let Out::Any(yrs::Any::Number(n)) = &item {
                        client_ids.push(*n as u64);
                    } else if let Out::Any(yrs::Any::BigInt(n)) = &item {
                        client_ids.push(*n as u64);
                    } else {
                        client_ids.push(0); // unknown format
                    }
                }
                client_ids
            } else {
                Vec::new()
            };

            // Check ds array
            if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                let ds_len = ds_arr.len(&txn);
                total_ds_elements += ds_len;

                // Try to decode ds elements - they should be encoded DeleteSets
                let mut decoded_count = 0u32;
                let mut decoded_total_deleted = 0u64;
                let mut decoded_client_ids: std::collections::HashSet<u64> =
                    std::collections::HashSet::new();
                let mut element_types: BTreeMap<String, u32> = BTreeMap::new();

                // Per-client breakdown: client_id -> (total_deleted_ops, Vec<(start, end)>)
                let mut per_client_deletions: BTreeMap<u64, (u64, Vec<(u32, u32)>)> =
                    BTreeMap::new();

                for (idx, item) in ds_arr.iter(&txn).enumerate() {
                    let type_name = match &item {
                        Out::Any(yrs::Any::Buffer(buf)) => {
                            // Try to decode as a DeleteSet
                            use yrs::updates::decoder::DecoderV1;
                            use yrs::encoding::read::Cursor;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            match yrs::DeleteSet::decode(&mut decoder) {
                                Ok(decoded_ds) => {
                                    decoded_count += 1;
                                    for (&cid, ranges) in decoded_ds.iter() {
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
                // Now show individual ds entries (first 30)
                println!("      first {} ds entries (of {}):", ds_len.min(30), ds_len);
                for (idx, item) in ds_arr.iter(&txn).enumerate() {
                    if idx >= 30 { break; }
                    if let Out::Any(yrs::Any::Buffer(buf)) = &item {
                        use yrs::updates::decoder::DecoderV1;
                        use yrs::encoding::read::Cursor;
                        let cursor = Cursor::new(buf.as_ref());
                        let mut decoder = DecoderV1::new(cursor);
                        if let Ok(decoded_ds) = yrs::DeleteSet::decode(&mut decoder) {
                            let mut parts = Vec::new();
                            for (&cid, ranges) in decoded_ds.iter() {
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
                    // Also show last 10
                    println!("      last 10 ds entries:");
                    let entries: Vec<_> = ds_arr.iter(&txn).collect();
                    let start_idx = entries.len().saturating_sub(10);
                    for (i, item) in entries[start_idx..].iter().enumerate() {
                        let idx = start_idx + i;
                        if let Out::Any(yrs::Any::Buffer(buf)) = item {
                            use yrs::updates::decoder::DecoderV1;
                            use yrs::encoding::read::Cursor;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            if let Ok(decoded_ds) = yrs::DeleteSet::decode(&mut decoder) {
                                let mut parts = Vec::new();
                                for (&cid, ranges) in decoded_ds.iter() {
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

                    // Show per-client deletion breakdown
                    println!("      per-client deletion breakdown:");
                    for (&cid, (total, ranges)) in &per_client_deletions {
                        // Merge overlapping/adjacent ranges for display
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
                        let merged_total: u64 =
                            merged.iter().map(|(s, e)| (*e - *s) as u64).sum();
                        println!(
                            "        client {:>12}: {} deleted ops ({} after merging), {} unique ranges",
                            cid,
                            total,
                            merged_total,
                            merged.len()
                        );
                        // Show the merged ranges
                        if merged.len() <= 10 {
                            for (s, e) in &merged {
                                println!(
                                    "          clock {}..{} ({} ops)",
                                    s,
                                    e,
                                    e - s
                                );
                            }
                        } else {
                            for (s, e) in &merged[..5] {
                                println!(
                                    "          clock {}..{} ({} ops)",
                                    s,
                                    e,
                                    e - s
                                );
                            }
                            println!("          ... {} more ranges ...", merged.len() - 10);
                            for (s, e) in &merged[merged.len() - 5..] {
                                println!(
                                    "          clock {}..{} ({} ops)",
                                    s,
                                    e,
                                    e - s
                                );
                            }
                        }

                        // Resolve deleted clocks to filenames using the filemeta clock map
                        if let Some(ref fm_map) = filemeta_clock_map {
                            let mut filename_counts: BTreeMap<&str, u64> = BTreeMap::new();
                            let mut unresolved = 0u64;
                            for (start, end) in &merged {
                                for clock in *start..*end {
                                    if let Some(filename) = fm_map.get(&(cid, clock)) {
                                        *filename_counts
                                            .entry(filename.as_str())
                                            .or_default() += 1;
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

    // PermanentUserData ds vs document delete set intersection analysis.
    // The document's delete set contains only items that are deleted but NOT yet GC'd.
    // Any PermanentUserData ds ranges that fall outside the doc DS have been GC'd and
    // are dead weight — there's no item to attribute anymore.
    println!();
    println!("  PermanentUserData ds vs document GC analysis:");
    {
        // Reuse users_map obtained earlier (get_or_insert_map would conflict with txn)
        let txn = doc.transact();

        // Helper: count how many ops in a range overlap with the doc delete set for a client
        let count_overlap = |client_id: u64, start: u32, end: u32| -> u64 {
            let Some(doc_ranges) = doc_ds_ranges.get(&client_id) else {
                return 0;
            };
            let mut overlap = 0u64;
            for &(ds_start, ds_end) in doc_ranges {
                // Skip ranges entirely before our range
                if ds_end <= start {
                    continue;
                }
                // Stop if past our range
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
                            if let Ok(decoded_ds) = yrs::DeleteSet::decode(&mut decoder) {
                                for (&cid, ranges) in decoded_ds.iter() {
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

    // filemeta_v0 overwrite analysis: look at the document's delete set
    // and correlate with clients that wrote to filemeta_v0
    println!();
    println!("  filemeta_v0 value history:");
    let fm_map = doc.get_or_insert_map("filemeta_v0");
    let txn = doc.transact();
    let fm_count = fm_map.len(&txn);
    println!("    Current entries: {}", fm_count);

    // For each filemeta_v0 entry, show its current content
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
    // Show a sample
    for (i, (k, v)) in fm_entries.iter().enumerate() {
        if i < 10 {
            println!("    [{}] {} = {}", i, k, v);
        }
    }
    if fm_entries.len() > 10 {
        println!("    ... and {} more entries", fm_entries.len() - 10);
    }
    drop(txn);

    // Iterate root-level types.
    // root_refs() may return UndefinedRef for types not yet accessed via a typed getter.
    // We collect names first, then try typed access on each.
    let txn = doc.transact();
    let root_names: Vec<String> = txn
        .root_refs()
        .map(|(name, _)| name.to_string())
        .collect();
    println!("  Root keys:        {}", root_names.len());
    drop(txn);

    for name in &root_names {
        // Try map first (most common in relay docs), then text, then array.
        let map_ref = doc.get_or_insert_map(name.as_str());
        let txn = doc.transact();
        let len = map_ref.len(&txn);
        if len > 0 {
            println!("    \"{}\": YMap ({} entries)", name, len);
            // Show top-level map keys with value types
            for (k, v) in map_ref.iter(&txn) {
                let val_desc = match &v {
                    Out::YText(t) => {
                        let s = t.get_string(&txn);
                        format!("YText ({} chars, {} bytes)", s.chars().count(), s.len())
                    }
                    Out::YMap(m) => {
                        let inner: Vec<String> = m.iter(&txn).map(|(ik, iv)| {
                            let iv_desc = match &iv {
                                Out::YText(t) => {
                                    let s = t.get_string(&txn);
                                    if s.len() > 80 {
                                        format!("YText ({} chars)", s.chars().count())
                                    } else {
                                        format!("{:?}", s)
                                    }
                                }
                                Out::YMap(m2) => format!("YMap ({} entries)", m2.len(&txn)),
                                Out::YArray(a2) => format!("YArray (len={})", a2.len(&txn)),
                                Out::Any(any) => format!("{:?}", any),
                                other => format!("{:?}", other),
                            };
                            format!("{}: {}", ik, iv_desc)
                        }).collect();
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

fn gc_ysweet_file(path: &std::path::Path, output: &std::path::Path) -> Result<()> {
    use std::collections::{HashMap, HashSet};
    use yrs::updates::decoder::Decode;
    use yrs::updates::encoder::{Encode, Encoder};
    use yrs::{Array, Doc, Map, Out, ReadTxn, StateVector, Transact};

    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    println!("Input:  {} ({} bytes)", path.display(), data.len());

    // Parse the file (CBOR or bincode) to get the KV map and format info.
    let (kv_map, is_cbor, cbor_doc) = parse_ysweet_data(&data)?;

    // Load the old doc from the KV data.
    let old_doc = load_doc_from_kv(&kv_map)?;

    // Phase 1: Read everything from the old doc into intermediate structures.
    // (Avoids holding transactions on both docs simultaneously.)

    // docs: Vec<(key, Any)>
    let mut docs_data: Vec<(String, yrs::Any)> = Vec::new();
    // filemeta_v0: Vec<(key, HashMap<inner_key, Any>)>
    let mut fm_data: Vec<(String, HashMap<String, yrs::Any>)> = Vec::new();
    // users: Vec<(user_id, deduped_ids, merged_ds_bytes)>
    struct UserData {
        user_id: String,
        unique_ids: Vec<f64>,
        original_ids_count: usize,
        original_ds_count: u32,
        merged_ds_bytes: Option<Vec<u8>>,
    }
    let mut users_data: Vec<UserData> = Vec::new();
    let mut other_roots: Vec<String> = Vec::new();

    {
        // get_or_insert_map needs a mut transaction internally, so do them one at a time.
        let old_docs = old_doc.get_or_insert_map("docs");
        let old_fm = old_doc.get_or_insert_map("filemeta_v0");
        let old_users = old_doc.get_or_insert_map("users");

        let old_txn = old_doc.transact();

        // Read docs
        for (key, val) in old_docs.iter(&old_txn) {
            if let Out::Any(any) = val {
                docs_data.push((key.to_string(), any));
            }
        }

        // Read filemeta_v0
        // Values may be Out::YMap (nested Yrs type) or Out::Any(Any::Map(...)) (plain map).
        for (key, val) in old_fm.iter(&old_txn) {
            match &val {
                Out::YMap(inner) => {
                    let mut entries: HashMap<String, yrs::Any> = HashMap::new();
                    for (ik, iv) in inner.iter(&old_txn) {
                        if let Out::Any(any) = iv {
                            entries.insert(ik.to_string(), any);
                        }
                    }
                    fm_data.push((key.to_string(), entries));
                }
                Out::Any(yrs::Any::Map(map)) => {
                    let entries: HashMap<String, yrs::Any> = map
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.clone()))
                        .collect();
                    fm_data.push((key.to_string(), entries));
                }
                _ => {}
            }
        }

        // Read & compact users
        for (user_id, user_val) in old_users.iter(&old_txn) {
            if let Out::YMap(user_map) = &user_val {
                // Dedup ids
                let mut unique_ids: Vec<f64> = Vec::new();
                let mut seen: HashSet<u64> = HashSet::new();
                let mut original_ids_count = 0usize;
                if let Some(Out::YArray(ids_arr)) = user_map.get(&old_txn, "ids") {
                    original_ids_count = ids_arr.len(&old_txn) as usize;
                    for item in ids_arr.iter(&old_txn) {
                        let num = match &item {
                            Out::Any(yrs::Any::Number(n)) => Some(*n),
                            Out::Any(yrs::Any::BigInt(n)) => Some(*n as f64),
                            _ => None,
                        };
                        if let Some(n) = num {
                            if seen.insert(n as u64) {
                                unique_ids.push(n);
                            }
                        }
                    }
                }

                // Merge all ds entries into one DeleteSet
                let mut merged_ds_bytes: Option<Vec<u8>> = None;
                let mut original_ds_count = 0u32;
                if let Some(Out::YArray(ds_arr)) = user_map.get(&old_txn, "ds") {
                    original_ds_count = ds_arr.len(&old_txn);
                    let mut all_delete_sets: Vec<yrs::DeleteSet> = Vec::new();
                    for item in ds_arr.iter(&old_txn) {
                        if let Out::Any(yrs::Any::Buffer(buf)) = &item {
                            use yrs::encoding::read::Cursor;
                            use yrs::updates::decoder::DecoderV1;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            if let Ok(ds) = yrs::DeleteSet::decode(&mut decoder) {
                                all_delete_sets.push(ds);
                            }
                        }
                    }
                    if !all_delete_sets.is_empty() {
                        let mut merged = yrs::DeleteSet::new();
                        for ds in &all_delete_sets {
                            for (&client, ranges) in ds.iter() {
                                for r in ranges.iter() {
                                    merged.insert(
                                        yrs::ID::new(client, r.start),
                                        r.end - r.start,
                                    );
                                }
                            }
                        }
                        use yrs::updates::encoder::EncoderV1;
                        let mut encoder = EncoderV1::new();
                        merged.encode(&mut encoder);
                        merged_ds_bytes = Some(encoder.to_vec());
                    }
                }

                users_data.push(UserData {
                    user_id: user_id.to_string(),
                    unique_ids,
                    original_ids_count,
                    original_ds_count,
                    merged_ds_bytes,
                });
            }
        }

        // Check for unknown roots
        for (name, _) in old_txn.root_refs() {
            let name = name.to_string();
            if name != "docs" && name != "filemeta_v0" && name != "users" {
                other_roots.push(name);
            }
        }
    }

    for name in &other_roots {
        println!("  warning: skipping unknown root \"{}\"", name);
    }

    // Phase 2: Build the new doc from the extracted data.
    let new_doc = Doc::new();
    {
        let new_docs = new_doc.get_or_insert_map("docs");
        let new_fm = new_doc.get_or_insert_map("filemeta_v0");
        let new_users = new_doc.get_or_insert_map("users");

        let mut new_txn = new_doc.transact_mut();

        // Write docs
        for (key, any) in docs_data {
            new_docs.insert(&mut new_txn, key, any);
        }

        // Write filemeta_v0 — preserve values as Any::Map (same as original)
        for (key, entries) in &fm_data {
            let inner: HashMap<String, yrs::Any> = entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let map_val = yrs::Any::Map(std::sync::Arc::new(inner));
            new_fm.insert(&mut new_txn, key.as_str(), map_val);
        }
        println!("  filemeta_v0: {} entries copied", fm_data.len());

        // Write compacted users
        for ud in &users_data {
            let empty_map: yrs::MapPrelim =
                std::iter::empty::<(String, yrs::Any)>().collect();
            let new_user_map = new_users.insert(&mut new_txn, ud.user_id.as_str(), empty_map);

            // Deduped ids
            let ids_prelim: Vec<yrs::Any> = ud
                .unique_ids
                .iter()
                .map(|&n| yrs::Any::Number(n))
                .collect();
            new_user_map.insert(
                &mut new_txn,
                "ids",
                yrs::ArrayPrelim::from(ids_prelim),
            );

            // Single merged ds entry
            if let Some(ref ds_bytes) = ud.merged_ds_bytes {
                let ds_prelim =
                    yrs::ArrayPrelim::from(vec![yrs::Any::Buffer(ds_bytes.clone().into())]);
                new_user_map.insert(&mut new_txn, "ds", ds_prelim);
            } else {
                let empty: Vec<yrs::Any> = Vec::new();
                new_user_map.insert(&mut new_txn, "ds", yrs::ArrayPrelim::from(empty));
            }

            println!(
                "  user \"{}\": ids {} -> {}, ds {} -> {}",
                ud.user_id,
                ud.original_ids_count,
                ud.unique_ids.len(),
                ud.original_ds_count,
                if ud.merged_ds_bytes.is_some() { 1 } else { 0 },
            );
        }
    }

    // Encode the new doc.
    let new_txn = new_doc.transact();
    let new_update = new_txn.encode_state_as_update_v1(&StateVector::default());
    let new_sv = new_txn.state_vector().encode_v1();
    drop(new_txn);

    // Find OID and doc name from original KV map.
    let oid_key = kv_map.keys().find(|k| k.len() >= 3 && k[0] == 0 && k[1] == 0);
    let oid = kv_map
        .keys()
        .find(|k| k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0)
        .map(|k| [k[2], k[3], k[4], k[5]])
        .unwrap_or([0, 0, 0, 0]);

    // Build new KV map.
    let mut new_kv: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    // OID mapping
    if let Some(oid_k) = oid_key {
        new_kv.insert(oid_k.clone(), kv_map[oid_k].clone());
    }

    // Doc state: 01{oid}0
    let mut doc_state_key = vec![0u8, 1];
    doc_state_key.extend_from_slice(&oid);
    doc_state_key.push(0);
    new_kv.insert(doc_state_key, new_update.clone());

    // State vector: 01{oid}1
    let mut sv_key = vec![0u8, 1];
    sv_key.extend_from_slice(&oid);
    sv_key.push(1);
    new_kv.insert(sv_key, new_sv);

    // Copy metadata entries: 01{oid}3{name}0
    for (k, v) in &kv_map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 3 {
            new_kv.insert(k.clone(), v.clone());
        }
    }

    // Write the output file in the same format as the input.
    if is_cbor {
        if let Some(doc) = cbor_doc {
            // Reconstruct CBOR with the original metadata.
            let out = YSweetDataDump {
                version: doc.version,
                created_at: doc.created_at,
                modified_at: doc.modified_at,
                metadata: doc.metadata.clone(),
                data: new_kv,
            };
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&out, &mut buf)
                .context("Failed to serialize CBOR")?;
            std::fs::write(output, &buf)?;
        }
    } else {
        let encoded = bincode::serialize(&new_kv)
            .context("Failed to serialize bincode")?;
        std::fs::write(output, &encoded)?;
    }

    let output_size = std::fs::metadata(output)?.len();
    println!("Output: {} ({} bytes)", output.display(), output_size);
    println!(
        "Reduction: {:.1}%",
        (1.0 - output_size as f64 / data.len() as f64) * 100.0
    );

    Ok(())
}

/// Compact PermanentUserData in a .ysweet file by clearing all `ds` (delete-set
/// attribution) arrays.  Unlike `gc-doc`, this mutates the existing Yrs document
/// in-place: all client IDs, state vectors, and CRDT history are preserved.  The
/// only change is that each user's `ds` YArray is emptied, which propagates to
/// clients as normal CRDT deletions on their next sync.
fn compact_pud(path: &std::path::Path, output: &std::path::Path, dry_run: bool) -> Result<()> {
    use yrs::updates::decoder::Decode;
    use yrs::updates::encoder::Encode;
    use yrs::{Array, Map, Out, ReadTxn, StateVector, Transact};

    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    println!("Input:  {} ({} bytes)", path.display(), data.len());

    let (kv_map, is_cbor, cbor_doc) = parse_ysweet_data(&data)?;
    let doc = load_doc_from_kv(&kv_map)?;

    // Snapshot before compaction.
    let before_size = {
        let txn = doc.transact();
        txn.encode_state_as_update_v1(&StateVector::default()).len()
    };

    // Inspect the users map and collect stats before mutating.
    let users_map = doc.get_or_insert_map("users");
    {
        let txn = doc.transact();
        let mut any_ds = false;
        for (user_id, user_val) in users_map.iter(&txn) {
            if let Out::YMap(user_map) = &user_val {
                let ids_count = user_map
                    .get(&txn, "ids")
                    .and_then(|o| if let Out::YArray(a) = o { Some(a.len(&txn)) } else { None })
                    .unwrap_or(0);
                let ds_count = user_map
                    .get(&txn, "ds")
                    .and_then(|o| if let Out::YArray(a) = o { Some(a.len(&txn)) } else { None })
                    .unwrap_or(0);

                // Count total ops tracked in ds entries.
                let mut ds_ops: u64 = 0;
                if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                    for item in ds_arr.iter(&txn) {
                        if let Out::Any(yrs::Any::Buffer(buf)) = &item {
                            use yrs::encoding::read::Cursor;
                            use yrs::updates::decoder::DecoderV1;
                            let cursor = Cursor::new(buf.as_ref());
                            let mut decoder = DecoderV1::new(cursor);
                            if let Ok(ds) = yrs::DeleteSet::decode(&mut decoder) {
                                for (_client, ranges) in ds.iter() {
                                    for r in ranges.iter() {
                                        ds_ops += (r.end - r.start) as u64;
                                    }
                                }
                            }
                        }
                    }
                }

                if ds_count > 0 {
                    any_ds = true;
                }
                println!(
                    "  user \"{}\": {} ids, {} ds entries ({} deletion-ops tracked)",
                    user_id, ids_count, ds_count, ds_ops,
                );
            }
        }

        if !any_ds {
            println!("Nothing to compact — no ds entries found.");
            return Ok(());
        }
    }

    if dry_run {
        println!("Dry run — no changes written.");
        return Ok(());
    }

    // Collect user IDs that have ds entries (can't iterate and mutate simultaneously).
    let ds_users: Vec<String> = {
        let txn = doc.transact();
        users_map
            .iter(&txn)
            .filter_map(|(user_id, user_val)| {
                if let Out::YMap(user_map) = &user_val {
                    if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                        if ds_arr.len(&txn) > 0 {
                            return Some(user_id.to_string());
                        }
                    }
                }
                None
            })
            .collect()
    };

    // Mutate: clear each user's ds array in-place.
    {
        let mut txn = doc.transact_mut();
        for user_id in &ds_users {
            if let Some(Out::YMap(user_map)) = users_map.get(&txn, user_id) {
                if let Some(Out::YArray(ds_arr)) = user_map.get(&txn, "ds") {
                    let len = ds_arr.len(&txn);
                    if len > 0 {
                        for i in (0..len).rev() {
                            ds_arr.remove(&mut txn, i);
                        }
                        println!("  cleared {} ds entries for \"{}\"", len, user_id);
                    }
                }
            }
        }
    }

    // Re-encode the (now mutated) doc.
    let txn = doc.transact();
    let new_update = txn.encode_state_as_update_v1(&StateVector::default());
    let new_sv = txn.state_vector().encode_v1();
    let after_size = new_update.len();
    drop(txn);

    // Rebuild the KV map with the updated doc state.
    let oid_key = kv_map.keys().find(|k| k.len() >= 3 && k[0] == 0 && k[1] == 0);
    let oid = kv_map
        .keys()
        .find(|k| k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0)
        .map(|k| [k[2], k[3], k[4], k[5]])
        .unwrap_or([0, 0, 0, 0]);

    let mut new_kv: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    // OID mapping
    if let Some(oid_k) = oid_key {
        new_kv.insert(oid_k.clone(), kv_map[oid_k].clone());
    }

    // Doc state: 01{oid}0
    let mut doc_state_key = vec![0u8, 1];
    doc_state_key.extend_from_slice(&oid);
    doc_state_key.push(0);
    new_kv.insert(doc_state_key, new_update);

    // State vector: 01{oid}1
    let mut sv_key = vec![0u8, 1];
    sv_key.extend_from_slice(&oid);
    sv_key.push(1);
    new_kv.insert(sv_key, new_sv);

    // Copy metadata entries: 01{oid}3{name}0
    for (k, v) in &kv_map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 3 {
            new_kv.insert(k.clone(), v.clone());
        }
    }

    // Write output in the same format as input.
    if is_cbor {
        if let Some(doc) = cbor_doc {
            let out = YSweetDataDump {
                version: doc.version,
                created_at: doc.created_at,
                modified_at: doc.modified_at,
                metadata: doc.metadata.clone(),
                data: new_kv,
            };
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&out, &mut buf)
                .context("Failed to serialize CBOR")?;
            std::fs::write(output, &buf)?;
        }
    } else {
        let encoded = bincode::serialize(&new_kv)
            .context("Failed to serialize bincode")?;
        std::fs::write(output, &encoded)?;
    }

    let output_size = std::fs::metadata(output)?.len();
    println!("Output: {} ({} bytes)", output.display(), output_size);
    println!(
        "Yrs update: {} -> {} bytes ({:.1}% reduction)",
        before_size,
        after_size,
        (1.0 - after_size as f64 / before_size as f64) * 100.0,
    );
    println!(
        "File: {} -> {} bytes ({:.1}% reduction)",
        data.len(),
        output_size,
        (1.0 - output_size as f64 / data.len() as f64) * 100.0,
    );

    Ok(())
}

/// Parse a .ysweet file into its KV map, format flag, and optional CBOR metadata.
fn parse_ysweet_data(
    data: &[u8],
) -> Result<(BTreeMap<Vec<u8>, Vec<u8>>, bool, Option<YSweetDataDump>)> {
    match ciborium::de::from_reader::<YSweetDataDump, _>(data) {
        Ok(doc) => Ok((doc.data.clone(), true, Some(doc))),
        Err(cbor_err) => match bincode::deserialize::<BTreeMap<Vec<u8>, Vec<u8>>>(data) {
            Ok(map) => Ok((map, false, None)),
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

/// Load a Yrs Doc from the KV entries in a .ysweet file.
fn load_doc_from_kv(map: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<yrs::Doc> {
    use yrs::updates::decoder::Decode;
    use yrs::{Doc, Transact, Update};

    let doc = Doc::new();

    // Apply doc state (key pattern: 01{oid:4}0)
    if let Some((_, state_bytes)) = map.iter().find(|(k, _)| {
        k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 0
    }) {
        let update = Update::decode_v1(state_bytes)
            .context("Failed to decode doc state")?;
        let mut txn = doc.transact_mut();
        txn.apply_update(update);
    }

    // Apply pending updates (key pattern: 01{oid:4}2{clock:4}0)
    for (k, v) in map {
        if k.len() >= 7 && k[0] == 0 && k[1] == 1 && k[6] == 2 {
            if let Ok(update) = Update::decode_v1(v) {
                let mut txn = doc.transact_mut();
                txn.apply_update(update);
            }
        }
    }

    Ok(doc)
}

// -- v1 update binary decoder for filename resolution --

/// Metadata about a decoded Item from a v1 update binary.
#[derive(Debug)]
struct DecodedItemMeta {
    client: u64,
    clock: u32,
    len: u32,
    /// Named parent (root type name), e.g. "filemeta_v0"
    parent_named: Option<String>,
    /// ID parent (nested type, pointing to another Item)
    parent_id: Option<(u64, u32)>,
    /// Map key (filename for filemeta_v0 entries)
    parent_sub: Option<String>,
    /// Left origin (previous item in chain)
    origin: Option<(u64, u32)>,
}

/// Decode a v1 update binary to extract Item metadata (parent, parent_sub, origin).
fn decode_v1_item_parents(bytes: &[u8]) -> Result<Vec<DecodedItemMeta>, String> {
    use lib0::decoding::{Cursor, Read};

    let mut cursor = Cursor::new(bytes);
    let mut items = Vec::new();

    let num_clients: u32 = cursor.read_var().map_err(|e| format!("num_clients: {:?}", e))?;
    for _ in 0..num_clients {
        let num_blocks: u32 = cursor
            .read_var()
            .map_err(|e| format!("num_blocks: {:?}", e))?;
        let client: u32 = cursor.read_var().map_err(|e| format!("client: {:?}", e))?;
        let mut clock: u32 = cursor.read_var().map_err(|e| format!("clock: {:?}", e))?;

        for block_idx in 0..num_blocks {
            let info = cursor.read_u8().map_err(|e| format!("info: {:?}", e))?;
            let content_ref = info & 0x0F;

            // SKIP block
            if content_ref == 10 {
                let len: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("skip len: {:?}", e))?;
                clock += len;
                continue;
            }
            // GC block
            if content_ref == 0 {
                let len: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("gc len: {:?}", e))?;
                clock += len;
                continue;
            }

            let has_origin = info & 0x80 != 0;
            let has_right_origin = info & 0x40 != 0;
            let cant_copy_parent = !has_origin && !has_right_origin;

            let origin = if has_origin {
                let c: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("origin client: {:?}", e))?;
                let k: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("origin clock: {:?}", e))?;
                Some((c as u64, k))
            } else {
                None
            };

            if has_right_origin {
                let _: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("right client: {:?}", e))?;
                let _: u32 = cursor
                    .read_var()
                    .map_err(|e| format!("right clock: {:?}", e))?;
            }

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
                    let c: u32 = cursor
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
            });

            clock += content_len;
        }
    }

    Ok(items)
}

/// Skip content bytes in a v1 update and return the content length (number of ops consumed).
fn skip_v1_content(cursor: &mut lib0::decoding::Cursor, content_ref: u8) -> Result<u32, String> {
    use lib0::decoding::Read;

    match content_ref {
        1 => {
            // DELETED
            let len: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            Ok(len)
        }
        2 => {
            // JSON
            let count: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..=count {
                cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            }
            Ok(count + 1)
        }
        3 => {
            // BINARY
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(1)
        }
        4 => {
            // STRING
            let buf = cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(buf.len() as u32)
        }
        5 => {
            // EMBED (read_json in V1 = read a length-prefixed string)
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(1)
        }
        6 => {
            // FORMAT: read_key (string) + read_json (string)
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            Ok(1)
        }
        7 => {
            // TYPE
            let type_ref = cursor.read_u8().map_err(|e| format!("{:?}", e))?;
            match type_ref {
                3 | 5 => {
                    // XmlElement, XmlHook — have a name string
                    cursor.read_buf().map_err(|e| format!("{:?}", e))?;
                }
                _ => {} // Array(0), Map(1), Text(2), XmlFragment(4), XmlText(6), SubDoc(9), etc
            }
            Ok(1)
        }
        8 => {
            // ANY
            let count: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..count {
                skip_any_value(cursor)?;
            }
            Ok(count.max(1))
        }
        9 => {
            // DOC: string (guid) + any value (options)
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
            skip_any_value(cursor)?;
            Ok(1)
        }
        11 => {
            // MOVE: signed flags + start_id + optional end_id
            let flags: i64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            let is_collapsed = (flags & 1) != 0;
            // start_id
            let _: u64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            let _: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            if !is_collapsed {
                // end_id
                let _: u64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
                let _: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            }
            Ok(1)
        }
        _ => Err(format!("unknown content ref: {}", content_ref)),
    }
}

/// Skip a lib0 Any value in the binary stream.
fn skip_any_value(cursor: &mut lib0::decoding::Cursor) -> Result<(), String> {
    use lib0::decoding::Read;

    let tag = cursor.read_u8().map_err(|e| format!("{:?}", e))?;
    match tag {
        127 | 126 | 121 | 120 => {} // undefined, null, false, true
        125 => {
            // integer (signed var int)
            let _: i64 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
        }
        124 => {
            // float32
            cursor.read_exact(4).map_err(|e| format!("{:?}", e))?;
        }
        123 => {
            // float64
            cursor.read_exact(8).map_err(|e| format!("{:?}", e))?;
        }
        122 => {
            // bigint64
            cursor.read_exact(8).map_err(|e| format!("{:?}", e))?;
        }
        119 => {
            // string
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
        }
        118 => {
            // map
            let len: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..len {
                cursor.read_buf().map_err(|e| format!("{:?}", e))?; // key
                skip_any_value(cursor)?; // value
            }
        }
        117 => {
            // array
            let len: u32 = cursor.read_var().map_err(|e| format!("{:?}", e))?;
            for _ in 0..len {
                skip_any_value(cursor)?;
            }
        }
        116 => {
            // buffer
            cursor.read_buf().map_err(|e| format!("{:?}", e))?;
        }
        _ => return Err(format!("unknown Any tag: {}", tag)),
    }
    Ok(())
}

/// Build a mapping from (client_id, clock) → filename for all Items
/// that belong to the "filemeta_v0" root map (directly or via nesting/origin chains).
fn build_filemeta_clock_map(
    update_bytes: &[u8],
) -> Result<std::collections::HashMap<(u64, u32), String>, String> {
    use std::collections::HashMap;

    let items = decode_v1_item_parents(update_bytes)?;

    // Index by (client, clock) for origin chain resolution
    let mut by_id: HashMap<(u64, u32), usize> = HashMap::new();
    for (i, item) in items.iter().enumerate() {
        by_id.insert((item.client, item.clock), i);
    }

    // Phase 1: Items with explicit parent=Named("filemeta_v0") and parent_sub
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

    // Phase 2: Items whose parent_id points to a resolved filemeta_v0 item (nested fields)
    // Repeat until no new resolutions (handles multi-level nesting)
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

    // Phase 3: Items with origin pointing to a resolved item (map overwrites)
    // Origin chains can be long (one per sync loop iteration), so iterate until stable
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

fn dump_ysweet_file(path: &std::path::Path, show_keys: bool) -> Result<()> {
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    println!("File: {}", path.display());
    println!("Size: {} bytes", data.len());
    println!();

    // Try CBOR first, then bincode.
    match ciborium::de::from_reader::<YSweetDataDump, _>(&data[..]) {
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
        Err(cbor_err) => {
            // Try bincode fallback
            match bincode::deserialize::<BTreeMap<Vec<u8>, Vec<u8>>>(&data) {
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
            }
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

        let hosts = generate_allowed_hosts(None, explicit_hosts, None).unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");
        assert_eq!(hosts[1].host, "app.flycast");
        assert_eq!(hosts[1].scheme, "http");
    }

    #[test]
    fn test_generate_allowed_hosts_from_prefix() {
        let url: Url = "https://api.example.com".parse().unwrap();

        // Without FLY_APP_NAME
        let hosts = generate_allowed_hosts(Some(&url), None, None).unwrap();

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");

        // With FLY_APP_NAME
        let hosts = generate_allowed_hosts(Some(&url), None, Some("my-app")).unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");
        assert_eq!(hosts[1].host, "my-app.flycast");
        assert_eq!(hosts[1].scheme, "http");
    }

    #[test]
    fn test_generate_allowed_hosts_empty() {
        let hosts = generate_allowed_hosts(None, None, None).unwrap();
        assert_eq!(hosts.len(), 0);
    }

    #[test]
    fn test_fly_io_scenario() {
        // Simulate a Fly.io deployment scenario
        let url: Url = "https://api.mycompany.com".parse().unwrap();
        let hosts = generate_allowed_hosts(Some(&url), None, Some("my-relay-server")).unwrap();

        // Should have both external and internal hosts
        assert_eq!(hosts.len(), 2);

        // External host for public access
        assert_eq!(hosts[0].host, "api.mycompany.com");
        assert_eq!(hosts[0].scheme, "https");

        // Internal flycast host for internal access
        assert_eq!(hosts[1].host, "my-relay-server.flycast");
        assert_eq!(hosts[1].scheme, "http");
    }
}
