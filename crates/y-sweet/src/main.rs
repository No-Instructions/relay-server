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
use y_sweet::cli::{print_auth_message, sign_stdin, verify_stdin};
use y_sweet::server::AllowedHost;
use y_sweet::stores::filesystem::FileSystemStore;
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

#[derive(Clone, ValueEnum)]
enum KeyType {
    #[value(name = "legacy")]
    Legacy,
    #[value(name = "HMAC256")]
    Hmac256,
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
        /// Path to configuration file
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,

        // Legacy CLI arguments - kept for backward compatibility
        #[clap(env = "RELAY_SERVER_STORAGE")]
        store: Option<String>,

        #[clap(long, default_value = "8080", env = "PORT")]
        port: u16,
        #[clap(long, env = "RELAY_SERVER_HOST")]
        host: Option<IpAddr>,
        #[clap(long, env = "METRICS_PORT")]
        metrics_port: Option<u16>,
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
        #[clap(env = "RELAY_SERVER_STORAGE")]
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
    port: u16,
    host: &Option<IpAddr>,
    metrics_port: &Option<u16>,
    checkpoint_freq_seconds: u64,
    auth: &Option<String>,
    url_prefix: &Option<Url>,
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

    // Override server settings with CLI args (non-default values)
    if port != 8080 {
        config.server.port = port;
    }
    if let Some(port) = metrics_port {
        if config.metrics.is_none() {
            config.metrics = Some(y_sweet_core::config::MetricsConfig { port: *port });
        } else if let Some(ref mut metrics_config) = config.metrics {
            metrics_config.port = *port;
        }
    }
    if checkpoint_freq_seconds != 10 {
        config.server.checkpoint_freq_seconds = checkpoint_freq_seconds;
    }

    if let Some(host) = host {
        config.server.host = host.to_string();
    }

    if let Some(auth_key) = auth {
        if config.auth.is_none() {
            config.auth = Some(y_sweet_core::config::AuthConfig::default());
        }
        if let Some(ref mut auth_config) = config.auth {
            auth_config.private_key = Some(auth_key.clone());
        }
    }

    if let Some(url_prefix) = url_prefix {
        config.server.url_prefix = Some(url_prefix.to_string());
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
    url_prefix: Option<&Url>,
    explicit_hosts: Option<Vec<String>>,
    fly_app_name: Option<&str>,
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
            url_prefix,
            allowed_hosts,
        } => {
            // Load configuration
            let config = load_config_for_serve_args(
                config.as_ref(),
                store,
                *port,
                host,
                metrics_port,
                *checkpoint_freq_seconds,
                auth,
                url_prefix,
                allowed_hosts,
            )?;

            // Initialize logging based on config
            let log_level = &config.logging.level;
            tracing::info!("Using log level: {}", log_level);

            // Create authenticator from config
            let auth = if let Some(ref auth_config) = config.auth {
                if let Some(private_key) = &auth_config.private_key {
                    Some(Authenticator::new(private_key)?)
                } else if let Some(public_key) = &auth_config.public_key {
                    Some(Authenticator::new(public_key)?)
                } else {
                    return Err(anyhow::anyhow!(
                        "Auth section present but no private_key or public_key provided"
                    ));
                }
            } else {
                tracing::warn!("No auth key set. Only use this for local development!");
                None
            };

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
            let url_prefix = config
                .server
                .url_prefix
                .as_ref()
                .map(|s| Url::parse(s))
                .transpose()?;

            // Get FLY_APP_NAME once at configuration time to avoid race conditions
            let fly_app_name = env::var("FLY_APP_NAME").ok();

            // Generate allowed hosts (use config + auto-generation from URL prefix)
            let allowed_hosts = if config.server.allowed_hosts.is_empty() {
                // Auto-generate from url_prefix if no explicit hosts configured
                generate_allowed_hosts(url_prefix.as_ref(), None, fly_app_name.as_deref())?
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
                generate_allowed_hosts(
                    url_prefix.as_ref(),
                    Some(explicit_hosts),
                    fly_app_name.as_deref(),
                )?
            };

            let token = CancellationToken::new();

            // Use webhook configs from configuration (TOML file or env vars)
            let webhook_configs = if config.webhooks.is_empty() {
                // Fallback to environment variable for backward compatibility
                y_sweet::webhook::load_webhook_configs()
            } else {
                Some(config.webhooks.clone())
            };

            if let Some(ref configs) = webhook_configs {
                tracing::info!("Loaded {} webhook configurations", configs.len());
            }

            let server = y_sweet::server::Server::new(
                store,
                std::time::Duration::from_secs(config.server.checkpoint_freq_seconds),
                auth,
                url_prefix.clone(),
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
                        y_sweet::server::Server::version_header_middleware,
                    ));
                    let app = if redact_errors {
                        app.layer(middleware::from_fn(
                            y_sweet::server::Server::redact_error_middleware,
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
            };

            if *json {
                let mut result = serde_json::Map::new();

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
                }

                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::Value::Object(result))?
                );
            } else {
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

            y_sweet::convert::convert(store, &buf, doc_id).await?;
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
                                if config.auth.is_some() {
                                    "enabled"
                                } else {
                                    "disabled"
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

                            if let Some(url_prefix) = &config.server.url_prefix {
                                println!("  URL prefix: {}", url_prefix);
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
                            println!("Current configuration:");
                            println!();

                            // Convert to TOML for display
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

        let hosts = generate_allowed_hosts(None, explicit_hosts, None).unwrap();

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
        let hosts = generate_allowed_hosts(Some(&url_prefix), None, None).unwrap();

        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "api.example.com");
        assert_eq!(hosts[0].scheme, "https");

        // With FLY_APP_NAME
        let hosts = generate_allowed_hosts(Some(&url_prefix), None, Some("my-app")).unwrap();

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
        let url_prefix: Url = "https://api.mycompany.com".parse().unwrap();
        let hosts =
            generate_allowed_hosts(Some(&url_prefix), None, Some("my-relay-server")).unwrap();

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
