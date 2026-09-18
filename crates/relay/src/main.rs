use anyhow::Context;
use anyhow::Result;
use axum::middleware;
use clap::{Args, Parser, Subcommand, ValueEnum};
use relay::cli::{print_auth_message, sign_stdin, verify_stdin};
use relay::server::AllowedHost;
use relay::stores::filesystem::FileSystemStore;
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
use y_sweet_core::{
    auth::Authenticator,
    config::Config,
    metrics::RelayMetrics,
    store::{
        s3::{
            load_credentials_file, reload_credentials_file, RotatingCredentials, S3Config, S3Store,
        },
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

        /// Run pending data migrations before binding the listener. If any
        /// migration fails, the server will not start. Useful for baking
        /// migrations into a single-tenant container image's entrypoint.
        #[clap(long)]
        migrate: bool,
    },

    /// Run any pending data migrations against the configured store, then exit.
    Migrate {
        /// Path to relay.toml (defaults to standard discovery).
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,

        /// Store URL override: `s3://bucket[/prefix]` or a filesystem path.
        /// If omitted, the configured store from relay.toml/env is used.
        #[clap(long)]
        store: Option<String>,
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

    /// Subdoc-related maintenance commands.
    Subdocs {
        #[clap(subcommand)]
        cmd: SubdocsCommand,
    },

    /// Per-document maintenance and inspection commands.
    Doc {
        #[clap(subcommand)]
        cmd: DocCommand,
    },
}

#[derive(Subcommand)]
enum DocCommand {
    /// Inspect a single doc — print envelope metadata, KV layout,
    /// per-user contributions, or update history.
    Inspect {
        #[clap(subcommand)]
        cmd: DocInspectCommand,
    },

    /// List S3 object versions for a single doc (newest first).
    /// Requires the bucket to have versioning enabled.
    Versions {
        /// Path to relay.toml (defaults to standard discovery).
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,

        /// Store URL override: `s3://bucket[/prefix]` or a filesystem path.
        #[clap(long)]
        store: Option<String>,

        /// Relay GUID prefix used to construct the storage key.
        #[clap(long = "relay")]
        relay_id: String,

        /// Doc GUID to list versions for.
        #[clap(long)]
        doc: String,

        /// Limit the number of versions shown (0 = no limit).
        #[clap(long, default_value_t = 25)]
        limit: usize,
    },

    /// Fetch the raw `data.ysweet` bytes for a doc and write them to a file
    /// (or stdout). With `--version`, fetches a specific past version.
    Get {
        /// Path to relay.toml (defaults to standard discovery).
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,

        /// Store URL override: `s3://bucket[/prefix]` or a filesystem path.
        #[clap(long)]
        store: Option<String>,

        /// Relay GUID prefix used to construct the storage key.
        #[clap(long = "relay")]
        relay_id: String,

        /// Doc GUID.
        #[clap(long)]
        doc: String,

        /// Specific S3 VersionId to fetch. If omitted, fetches the latest.
        #[clap(long)]
        version: Option<String>,

        /// Output path. Defaults to stdout.
        #[clap(short = 'o', long)]
        output: Option<PathBuf>,
    },

    /// Restore supported document roots from a historical version by writing
    /// fresh Yjs operations into the current doc.
    Restore {
        #[clap(flatten)]
        args: DocRestoreArgs,
    },
}

#[derive(Args)]
struct DocRestoreArgs {
    /// Path to relay.toml (defaults to standard discovery).
    #[clap(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Store URL override: `s3://bucket[/prefix]` or a filesystem path.
    #[clap(long)]
    store: Option<String>,

    /// Relay GUID prefix used to construct the storage key.
    #[clap(long = "relay")]
    relay_id: String,

    /// Doc GUID to restore.
    #[clap(long)]
    doc: String,

    /// Specific S3 VersionId to restore supported roots from.
    #[clap(long = "from-version")]
    from_version: String,

    /// Restore only this top-level root. Repeat for multiple roots.
    #[clap(long, conflicts_with = "except")]
    only: Vec<String>,

    /// Exclude this top-level root. Repeat for multiple roots.
    #[clap(long)]
    except: Vec<String>,

    /// Persist the restored roots. Without this flag, this is a dry run.
    #[clap(long, conflicts_with = "verify")]
    write: bool,

    /// Verify current root entries and writer client clocks against source.
    #[clap(long, conflicts_with = "write")]
    verify: bool,
}

#[derive(Subcommand)]
enum DocInspectCommand {
    /// Text dump of file format, metadata, KV layout, and yrs doc stats.
    Info {
        #[clap(flatten)]
        input: InspectInput,

        /// Also print the raw key-value entries.
        #[clap(long)]
        keys: bool,
    },

    /// Per-user content contributions as JSON.
    Users {
        #[clap(flatten)]
        input: InspectInput,
    },

    /// Timeline of update content diffs as JSON.
    History {
        #[clap(flatten)]
        input: InspectInput,
    },
}

/// Where the bytes for `relay doc inspect` come from. Either a local file,
/// or fetched from the configured store using `{relay}-{doc}/data.ysweet`.
#[derive(Args)]
struct InspectInput {
    /// Read from a local .ysweet file. Mutually exclusive with --doc.
    #[clap(long)]
    file: Option<PathBuf>,

    /// Doc GUID to fetch from the configured store. Requires --relay.
    #[clap(long, requires = "relay_id", conflicts_with = "file")]
    doc: Option<String>,

    /// Relay GUID prefix used to construct the storage key.
    #[clap(long = "relay", requires = "doc")]
    relay_id: Option<String>,

    /// Store URL override: `s3://bucket[/prefix]` or a filesystem path.
    /// If omitted, the configured store from relay.toml/env is used.
    #[clap(long)]
    store: Option<String>,

    /// Path to relay.toml (defaults to standard discovery).
    #[clap(short = 'c', long = "config")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum SubdocsCommand {
    /// Rebuild the parent folder's `metadata.subdocs` snapshot index by
    /// walking `filemeta_v0`, fetching each child doc, encoding its
    /// snapshot, and writing the result back to the parent.
    ///
    /// The store is taken from the relay config (relay.toml + env vars,
    /// same resolution as `serve`) unless `--store` is given as an override.
    Index {
        /// Path to relay.toml (defaults to standard discovery).
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,

        /// Store URL override: `s3://bucket[/prefix]` or a filesystem path.
        /// If omitted, the configured store from relay.toml/env is used.
        #[clap(long)]
        store: Option<String>,

        /// Relay GUID prefix used to construct storage keys
        /// (`{relay}-{doc}/data.ysweet`).
        #[clap(long = "relay")]
        relay_id: String,

        /// Folder doc GUID.
        #[clap(long)]
        folder: String,

        /// Print the current coverage of the parent's subdocs index against
        /// its `filemeta_v0` and exit. No fetches, no writes.
        #[clap(long)]
        check: bool,

        /// Compute everything but skip both the in-memory parent mutation
        /// and the persist back to storage. Ignored if `--check` is set.
        #[clap(long)]
        dry_run: bool,
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
                credentials_file: None,
                probe_prefix: None,
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

/// A constructed store plus, when the store loads its credentials from a
/// file, the handle a background task needs to hot-reload them.
struct BuiltStore {
    store: Box<dyn Store>,
    creds_reload: Option<CredentialsReload>,
}

/// Everything the credentials-reload worker needs: the file to watch, the
/// shared rotating handle to update, and the legacy env-key fallback used if
/// the file goes stale.
struct CredentialsReload {
    path: String,
    credentials: RotatingCredentials,
    fallback: Option<(String, String)>,
}

/// Build an [`S3Config`] from a resolved `S3StoreConfig`, applying
/// TOML-then-env fallbacks. When a credentials file resolves, the initial
/// key/secret/token come from the file (fail fast) and the access-key env
/// vars are no longer required.
fn s3_config_from_store(s3_config: &y_sweet_core::config::S3StoreConfig) -> Result<S3Config> {
    let credentials_file = s3_config
        .credentials_file
        .clone()
        .or_else(|| env::var("AWS_CREDENTIALS_FILE").ok());
    let probe_prefix = s3_config
        .probe_prefix
        .clone()
        .or_else(|| env::var("STORAGE_PROBE_PREFIX").ok());

    let (key, secret, token) = if let Some(path) = &credentials_file {
        let creds = load_credentials_file(path)
            .with_context(|| format!("failed to load AWS credentials file {}", path))?;
        (
            creds.key().to_string(),
            creds.secret().to_string(),
            Some(creds.token().to_string()),
        )
    } else {
        (
            s3_config
                .access_key_id
                .clone()
                .or_else(|| env::var("AWS_ACCESS_KEY_ID").ok())
                .ok_or_else(|| anyhow::anyhow!("AWS_ACCESS_KEY_ID is required"))?,
            s3_config
                .secret_access_key
                .clone()
                .or_else(|| env::var("AWS_SECRET_ACCESS_KEY").ok())
                .ok_or_else(|| anyhow::anyhow!("AWS_SECRET_ACCESS_KEY is required"))?,
            env::var("AWS_SESSION_TOKEN").ok(),
        )
    };

    Ok(S3Config {
        key,
        secret,
        token,
        endpoint: if !s3_config.endpoint.is_empty() {
            s3_config.endpoint.clone()
        } else if let Ok(ep) = env::var("AWS_ENDPOINT_URL_S3") {
            ep
        } else {
            format!("https://s3.dualstack.{}.amazonaws.com", s3_config.region)
        },
        region: s3_config.region.clone(),
        bucket: s3_config.bucket.clone(),
        bucket_prefix: if s3_config.prefix.is_empty() {
            None
        } else {
            Some(s3_config.prefix.clone())
        },
        path_style: s3_config.path_style,
        credentials_file,
        probe_prefix,
    })
}

/// Construct an S3-backed store and, in credentials-file mode, the reload
/// handle. The env-key fallback is captured only when both
/// `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are present.
fn build_s3_store(s3_config: &y_sweet_core::config::S3StoreConfig) -> Result<BuiltStore> {
    let config = s3_config_from_store(s3_config)?;
    let credentials_file = config.credentials_file.clone();
    let store = S3Store::new(config);

    let creds_reload = credentials_file.map(|path| {
        let fallback = match (
            env::var("AWS_ACCESS_KEY_ID").ok(),
            env::var("AWS_SECRET_ACCESS_KEY").ok(),
        ) {
            (Some(key), Some(secret)) => Some((key, secret)),
            _ => None,
        };
        CredentialsReload {
            path,
            credentials: store.rotating_credentials(),
            fallback,
        }
    });

    Ok(BuiltStore {
        store: Box::new(store),
        creds_reload,
    })
}

fn get_store_from_config(
    store_config: &y_sweet_core::config::StoreConfig,
) -> Result<Option<BuiltStore>> {
    use y_sweet_core::config::StoreConfig;

    match store_config {
        StoreConfig::Memory => Ok(None),
        StoreConfig::Filesystem(fs_config) => {
            let store = FileSystemStore::new(PathBuf::from(&fs_config.path))?;
            Ok(Some(BuiltStore {
                store: Box::new(store),
                creds_reload: None,
            }))
        }
        StoreConfig::S3(s3_config) => Ok(Some(build_s3_store(s3_config)?)),
        // Convert provider-specific configs to generic S3 config
        StoreConfig::Aws(_)
        | StoreConfig::Cloudflare(_)
        | StoreConfig::Backblaze(_)
        | StoreConfig::Minio(_)
        | StoreConfig::Tigris(_) => {
            let s3_config = store_config
                .to_s3_config()
                .ok_or_else(|| anyhow::anyhow!("Failed to convert provider config to S3 config"))?;
            Ok(Some(build_s3_store(&s3_config)?))
        }
    }
}

/// Resolve a store for an offline subcommand: explicit `--store` override
/// wins; otherwise load relay.toml (default discovery if `config` is None)
/// and use its configured store.
fn build_store_for_subcommand(
    store_override: Option<&str>,
    config_path: Option<&PathBuf>,
) -> Result<Arc<Box<dyn Store>>> {
    let raw: Box<dyn Store> = if let Some(arg) = store_override {
        get_store_from_opts(arg)?
    } else {
        let cfg = Config::load(config_path.map(|p| p.as_path()))?;
        get_store_from_config(&cfg.store)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "configured store is in-memory; this subcommand requires a real store. \
                     Pass --store s3://... or --config <path> pointing at a config with a store."
                )
            })?
            .store
    };
    Ok(Arc::new(raw))
}

/// Resolve an `InspectInput` to (label, bytes). Either reads a local file
/// or fetches `{relay_id}-{doc}/data.ysweet` from the configured store.
async fn resolve_inspect_input(input: &InspectInput) -> Result<(String, Vec<u8>)> {
    if let Some(path) = &input.file {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        Ok((path.display().to_string(), bytes))
    } else {
        let doc = input
            .doc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("must pass --file or --doc"))?;
        let relay_id = input
            .relay_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--doc requires --relay"))?;
        let store = build_store_for_subcommand(input.store.as_deref(), input.config.as_ref())?;
        store.init().await.context("store init failed")?;
        let data_key = format!("{}-{}/data.ysweet", relay_id, doc);
        let bytes = store
            .get(&data_key)
            .await
            .with_context(|| format!("get failed for {}", data_key))?
            .ok_or_else(|| anyhow::anyhow!("no object at {}", data_key))?;
        Ok((data_key, bytes))
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

fn log_store_backend(store_config: &y_sweet_core::config::StoreConfig) {
    use y_sweet_core::config::StoreConfig;

    match store_config {
        StoreConfig::Memory => {
            tracing::info!("Store backend: memory (documents will not be persisted)");
        }
        StoreConfig::Filesystem(fs) => {
            tracing::info!("Store backend: filesystem at {}", fs.path);
        }
        other => {
            let kind = match other {
                StoreConfig::S3(_) => "s3",
                StoreConfig::Aws(_) => "aws",
                StoreConfig::Cloudflare(_) => "cloudflare",
                StoreConfig::Backblaze(_) => "backblaze",
                StoreConfig::Minio(_) => "minio",
                StoreConfig::Tigris(_) => "tigris",
                _ => "s3-compatible",
            };
            if let Some(s3) = other.to_s3_config() {
                let prefix = if s3.prefix.is_empty() {
                    "(no prefix)".to_string()
                } else {
                    format!("prefix={}", s3.prefix)
                };
                let endpoint = if s3.endpoint.is_empty() {
                    format!("region={}", s3.region)
                } else {
                    format!("endpoint={}", s3.endpoint)
                };
                tracing::info!(
                    "Store backend: {} bucket={} {} {}",
                    kind,
                    s3.bucket,
                    endpoint,
                    prefix,
                );
            } else {
                tracing::info!("Store backend: {}", kind);
            }
        }
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
    let mut loaded_serve_config = None;

    if let ServSubcommand::Serve {
        config,
        port,
        host,
        metrics_port,
        checkpoint_freq_seconds,
        store,
        auth,
        url,
        allowed_hosts,
        migrate: _,
    } = &opts.subcmd
    {
        loaded_serve_config = Some(load_config_for_serve_args(
            config.as_ref(),
            store,
            port,
            host,
            metrics_port,
            checkpoint_freq_seconds,
            auth,
            url,
            allowed_hosts,
        )?);
    }

    let filter = if let Some(config) = &loaded_serve_config {
        EnvFilter::try_new(&config.logging.level).with_context(|| {
            format!(
                "Invalid logging.level/RUST_LOG filter: {}",
                config.logging.level
            )
        })?
    } else {
        EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy()
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    match &opts.subcmd {
        ServSubcommand::Serve { migrate, .. } => {
            let config = loaded_serve_config
                .take()
                .expect("serve config should be loaded before tracing initialization");

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

            // Run pending migrations first if requested. We build a
            // throwaway store handle for this so we don't have to share
            // ownership with the long-lived server store below.
            if *migrate {
                let migrate_store = get_store_from_config(&config.store)?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "--migrate requires a persistent store; in-memory store has nothing to migrate"
                        )
                    })?
                    .store;
                relay::migrations::run_pending(Arc::new(migrate_store)).await?;
            }

            // Create store from config
            let (store, creds_reload) = if let Some(built) = get_store_from_config(&config.store)? {
                log_store_backend(&config.store);
                built.store.init().await?;
                (Some(built.store), built.creds_reload)
            } else {
                tracing::warn!("No store set. Documents will be stored in memory only.");
                (None, None)
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

            // In credentials-file mode, hot-reload the scoped credentials in
            // the background so the store keeps signing after the wrapper
            // rotates them. No-op when the store isn't file-backed.
            if let Some(reload) = creds_reload {
                let worker_token = token.clone();
                tokio::spawn(async move {
                    credentials_reload_worker(reload, worker_token).await;
                });
            }

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
            .await?
            .with_semantic_logging(config.server.semantic_logging)
            .with_user_names(
                config
                    .server
                    .user_names
                    .iter()
                    .map(|(id, name)| (id.clone(), name.clone())),
            );

            let redact_errors = config.server.redact_errors;
            let server = Arc::new(server);

            let main_handle = tokio::spawn({
                let server = server.clone();
                let token = token.clone();
                async move {
                    let routes = server.routes_with_metrics();
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

            let signal = shutdown_signal().await;

            tracing::info!("Received {}, shutting down.", signal);
            // Client-compatible drain: deployed clients stop retrying a
            // dropped socket after a brief burst of refused attempts, so
            // the close-to-exit window must stay well under a second.
            //
            // Beat 1: flush every dirty doc while sockets keep serving —
            // the slow store work happens before any client notices.
            server.flush_all_docs().await;
            // Beat 2: cutover. Close doc sockets; their detaches trigger
            // idle-entry flushes, and the delta drain repeats until every
            // doc is clean — bounded by a handful of PUTs since beat 1
            // already did the slow work.
            server.close_doc_sockets();
            token.cancel();
            server.flush_until_clean().await;
            // Beat 3: exit now. Deliberately do NOT await the HTTP drain:
            // a bound listener that refuses upgrades eats into the
            // reconnect budget of every client it turns away.
            main_handle.abort();
            if let Some(metrics_handle) = metrics_handle {
                metrics_handle.abort();
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
        ServSubcommand::Migrate { config, store } => {
            let store = build_store_for_subcommand(store.as_deref(), config.as_ref())?;
            relay::migrations::run_pending(store).await?;
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

        ServSubcommand::Subdocs { cmd } => match cmd {
            SubdocsCommand::Index {
                config,
                store,
                relay_id,
                folder,
                check,
                dry_run,
            } => {
                let store = build_store_for_subcommand(store.as_deref(), config.as_ref())?;
                relay::subdocs::run_backfill(store, relay_id, folder, *check, *dry_run).await?;
            }
        },

        ServSubcommand::Doc { cmd } => match cmd {
            DocCommand::Inspect { cmd } => match cmd {
                DocInspectCommand::Info { input, keys } => {
                    let (label, bytes) = resolve_inspect_input(input).await?;
                    relay::doc_inspect::run_info(&label, &bytes, *keys)?;
                }
                DocInspectCommand::Users { input } => {
                    let (label, bytes) = resolve_inspect_input(input).await?;
                    relay::doc_inspect::run_users(&label, &bytes)?;
                }
                DocInspectCommand::History { input } => {
                    let (label, bytes) = resolve_inspect_input(input).await?;
                    relay::doc_inspect::run_history(&label, &bytes)?;
                }
            },
            DocCommand::Versions {
                config,
                store,
                relay_id,
                doc,
                limit,
            } => {
                let store = build_store_for_subcommand(store.as_deref(), config.as_ref())?;
                let limit = if *limit == 0 { None } else { Some(*limit) };
                relay::doc_versions::run(store, relay_id, doc, limit).await?;
            }
            DocCommand::Get {
                config,
                store,
                relay_id,
                doc,
                version,
                output,
            } => {
                let store = build_store_for_subcommand(store.as_deref(), config.as_ref())?;
                store.init().await.context("store init failed")?;
                let data_key = format!("{}-{}/data.ysweet", relay_id, doc);
                let bytes = match version {
                    Some(vid) => store
                        .get_version(&data_key, vid)
                        .await
                        .with_context(|| format!("get_version failed for {} @ {}", data_key, vid))?
                        .ok_or_else(|| {
                            anyhow::anyhow!("no object at {} version {}", data_key, vid)
                        })?,
                    None => store
                        .get(&data_key)
                        .await
                        .with_context(|| format!("get failed for {}", data_key))?
                        .ok_or_else(|| anyhow::anyhow!("no object at {}", data_key))?,
                };

                match output {
                    Some(path) => {
                        std::fs::write(path, &bytes)
                            .with_context(|| format!("failed to write {}", path.display()))?;
                        eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
                    }
                    None => {
                        use std::io::Write;
                        std::io::stdout().write_all(&bytes)?;
                    }
                }
            }
            DocCommand::Restore { args } => {
                let DocRestoreArgs {
                    config,
                    store,
                    relay_id,
                    doc,
                    from_version,
                    only,
                    except,
                    write,
                    verify,
                } = args;
                let store = build_store_for_subcommand(store.as_deref(), config.as_ref())?;
                relay::doc_restore::run(
                    store,
                    relay_id,
                    doc,
                    from_version,
                    only,
                    except,
                    *write,
                    *verify,
                )
                .await?;
            }
        },
    }

    Ok(())
}

/// Resolve when the process receives a shutdown signal: SIGTERM (what
/// process supervisors and container platforms send on stop/deploy) or
/// Ctrl+C/SIGINT (interactive use).
async fn shutdown_signal() -> &'static str {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => "SIGINT",
        _ = terminate => "SIGTERM",
    }
}

// ---------------------------------------------------------------------------
// Scoped-credential hot-reload (credentials-file mode)
// ---------------------------------------------------------------------------

/// Switch to the env-key fallback when the file credentials are within this
/// many seconds of expiry (or already expired).
const CREDENTIALS_STALE_LEAD_SECS: i64 = 300;

/// Redact an access key id for logging: keep the first and last 4 chars with
/// an ellipsis between, so the full id never reaches the logs. Ids too short
/// to redact that way are elided entirely.
fn redact_key_id(key_id: &str) -> String {
    let chars: Vec<char> = key_id.chars().collect();
    if chars.len() <= 8 {
        return "…".to_string();
    }
    let first: String = chars[..4].iter().collect();
    let last: String = chars[chars.len() - 4..].iter().collect();
    format!("{first}…{last}")
}

/// Poll interval for the credentials file: `AWS_CREDENTIALS_POLL_SECS`,
/// default 30s, floored at 5s.
fn credentials_poll_interval() -> std::time::Duration {
    const DEFAULT_SECS: u64 = 30;
    const MIN_SECS: u64 = 5;
    let secs = env::var("AWS_CREDENTIALS_POLL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECS)
        .max(MIN_SECS);
    std::time::Duration::from_secs(secs)
}

fn file_mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Result of (attempting to) re-read the credentials file on one tick.
enum ParseOutcome {
    /// mtime was unchanged; the file was not re-read.
    Unchanged,
    /// The file was re-read and parsed; carries the new expiry (unix secs).
    Reloaded { expiry: i64 },
    /// The file was re-read but failed to parse.
    Failed,
}

/// Pure decision state for the reload worker, isolated from files, clocks,
/// and metrics so the transitions are unit-testable.
struct ReloadDecider {
    current_expiry: i64,
    fallback_active: bool,
    /// Whether the "stale, no fallback" error has already been logged for the
    /// current stale episode (so it warns once, not every tick).
    stale_logged: bool,
}

/// What the worker should do as a result of one tick. The decider decides;
/// the caller performs the IO / logging / metrics.
#[derive(Debug, Default, PartialEq)]
struct ReloadActions {
    /// Freshly rotated from the file; carries the expiry to publish.
    rotated: Option<i64>,
    /// A reload was attempted but failed to parse.
    rotation_failed: bool,
    /// A fresh file arrived while on fallback: fallback was deactivated.
    recovered: bool,
    /// File credentials went stale: switch the store onto the env-key fallback.
    switch_to_fallback: bool,
    /// File credentials went stale and no fallback exists (deduped here).
    stale_no_fallback: bool,
}

impl ReloadDecider {
    fn step(&mut self, parse: ParseOutcome, now: i64, fallback_available: bool) -> ReloadActions {
        let mut actions = ReloadActions::default();

        // Phase (a): react to a changed file.
        match parse {
            ParseOutcome::Unchanged => {}
            ParseOutcome::Reloaded { expiry } => {
                self.current_expiry = expiry;
                self.stale_logged = false;
                actions.rotated = Some(expiry);
                if self.fallback_active {
                    self.fallback_active = false;
                    actions.recovered = true;
                }
            }
            ParseOutcome::Failed => {
                actions.rotation_failed = true;
            }
        }

        // Phase (b): staleness check against the currently-loaded expiry.
        if !self.fallback_active && now >= self.current_expiry - CREDENTIALS_STALE_LEAD_SECS {
            if fallback_available {
                self.fallback_active = true;
                actions.switch_to_fallback = true;
            } else if !self.stale_logged {
                self.stale_logged = true;
                actions.stale_no_fallback = true;
            }
        }

        actions
    }
}

/// Poll the credentials file and hot-rotate the store's credentials in place.
/// Runs until the cancellation token fires.
async fn credentials_reload_worker(reload: CredentialsReload, token: CancellationToken) {
    let CredentialsReload {
        path,
        credentials,
        fallback,
    } = reload;
    let poll = credentials_poll_interval();
    let fallback_available = fallback.is_some();

    // Establish the starting expiry by parsing once (harmless re-rotation of
    // the identical creds the store already loaded at construction).
    let mut decider = match reload_credentials_file(&path, &credentials) {
        Ok(reloaded) => {
            if let Ok(metrics) = RelayMetrics::new() {
                metrics.set_credential_expiry(reloaded.expiration_unix);
            }
            ReloadDecider {
                current_expiry: reloaded.expiration_unix,
                fallback_active: false,
                stale_logged: false,
            }
        }
        Err(e) => {
            // build_s3_store already loaded the file, so this is unexpected;
            // start with expiry 0 so the staleness check still protects us.
            tracing::warn!(
                "credentials reload worker: initial parse of {} failed: {}",
                path,
                e
            );
            ReloadDecider {
                current_expiry: 0,
                fallback_active: false,
                stale_logged: false,
            }
        }
    };

    let mut last_mtime = file_mtime(&path);

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = tokio::time::sleep(poll) => {}
        }

        // Phase (a) input: re-read only when mtime changed. Record the
        // observed mtime BEFORE parsing so a persistently-bad file warns
        // once, not every tick.
        let mtime = file_mtime(&path);
        let changed = mtime != last_mtime;
        last_mtime = mtime;
        let parse = if changed {
            match reload_credentials_file(&path, &credentials) {
                Ok(reloaded) => {
                    tracing::info!(
                        "rotated S3 credentials from {} (key {})",
                        path,
                        redact_key_id(&reloaded.key_id)
                    );
                    ParseOutcome::Reloaded {
                        expiry: reloaded.expiration_unix,
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to reload credentials file {}: {}", path, e);
                    ParseOutcome::Failed
                }
            }
        } else {
            ParseOutcome::Unchanged
        };

        let actions = decider.step(parse, now_unix(), fallback_available);

        if let Ok(metrics) = RelayMetrics::new() {
            if let Some(expiry) = actions.rotated {
                metrics.record_credential_rotation("success");
                metrics.set_credential_expiry(expiry);
            }
            if actions.rotation_failed {
                metrics.record_credential_rotation("error");
            }
            if actions.recovered {
                metrics.set_credential_fallback_active(false);
            }
            if actions.switch_to_fallback {
                metrics.set_credential_fallback_active(true);
            }
        }

        if actions.recovered {
            tracing::info!(
                "credentials file {} refreshed; recovered from fallback",
                path
            );
        }
        if actions.switch_to_fallback {
            if let Some((key, secret)) = &fallback {
                credentials.update(key.clone(), secret.clone(), None);
            }
            tracing::error!(
                "credentials file {} stale; switched to env-key fallback",
                path
            );
        }
        if actions.stale_no_fallback {
            tracing::error!(
                "credentials file {} stale and no env-key fallback available; keeping expired credentials",
                path
            );
        }
    }
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

    #[test]
    fn test_redact_key_id_hides_full_key() {
        let key = "ASIAIOSFODNN7EXAMPLE";
        let redacted = redact_key_id(key);
        // The full id must never survive redaction.
        assert!(!redacted.contains(key));
        assert_eq!(redacted, "ASIA…MPLE");
        // Ids too short to redact are elided entirely.
        assert_eq!(redact_key_id("ASIA1234"), "…");
        assert_eq!(redact_key_id("short"), "…");
    }

    #[test]
    fn test_reload_decider_normal_rotation() {
        let mut d = ReloadDecider {
            current_expiry: 1_000_000,
            fallback_active: false,
            stale_logged: false,
        };
        // A fresh file with a far-future expiry rotates and does nothing else.
        let actions = d.step(ParseOutcome::Reloaded { expiry: 2_000_000 }, 1_000, true);
        assert_eq!(
            actions,
            ReloadActions {
                rotated: Some(2_000_000),
                ..Default::default()
            }
        );
        assert_eq!(d.current_expiry, 2_000_000);
        assert!(!d.fallback_active);
    }

    #[test]
    fn test_reload_decider_stale_switches_to_fallback() {
        let mut d = ReloadDecider {
            current_expiry: 1_000,
            fallback_active: false,
            stale_logged: false,
        };
        // now is past (expiry - lead) and a fallback exists -> switch.
        let actions = d.step(ParseOutcome::Unchanged, 1_000, true);
        assert!(actions.switch_to_fallback);
        assert!(!actions.stale_no_fallback);
        assert!(d.fallback_active);
        // Once on fallback, further stale ticks are inert.
        let actions = d.step(ParseOutcome::Unchanged, 2_000, true);
        assert_eq!(actions, ReloadActions::default());
    }

    #[test]
    fn test_reload_decider_recovers_on_fresh_file() {
        let mut d = ReloadDecider {
            current_expiry: 1_000,
            fallback_active: true,
            stale_logged: false,
        };
        // A fresh file with a future expiry recovers from fallback.
        let actions = d.step(ParseOutcome::Reloaded { expiry: 5_000 }, 1_000, true);
        assert_eq!(actions.rotated, Some(5_000));
        assert!(actions.recovered);
        assert!(!d.fallback_active);
    }

    #[test]
    fn test_reload_decider_stale_no_fallback_logs_once() {
        let mut d = ReloadDecider {
            current_expiry: 1_000,
            fallback_active: false,
            stale_logged: false,
        };
        // No fallback available: log once...
        let actions = d.step(ParseOutcome::Unchanged, 1_000, false);
        assert!(actions.stale_no_fallback);
        assert!(!actions.switch_to_fallback);
        // ...and not again on subsequent stale ticks; creds are kept and we
        // never enter fallback.
        let actions = d.step(ParseOutcome::Unchanged, 2_000, false);
        assert!(!actions.stale_no_fallback);
        assert!(!d.fallback_active);
    }
}
