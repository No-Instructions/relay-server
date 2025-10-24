use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use url::Url;

use crate::webhook::WebhookConfig as CoreWebhookConfig;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file {0}: {1}")]
    ReadFile(std::path::PathBuf, std::io::Error),
    #[error("Failed to parse TOML in {0}: {1}")]
    ParseToml(std::path::PathBuf, toml::de::Error),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub auth: Vec<AuthKeyConfig>,

    #[serde(default)]
    pub store: StoreConfig,

    #[serde(default)]
    pub webhooks: Vec<CoreWebhookConfig>,

    #[serde(default)]
    pub logging: LoggingConfig,

    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    pub url: Option<String>,

    #[serde(default)]
    pub allowed_hosts: Vec<AllowedHost>,

    #[serde(default = "default_checkpoint_freq_seconds")]
    pub checkpoint_freq_seconds: u64,

    #[serde(default = "default_doc_gc")]
    pub doc_gc: bool,

    #[serde(default = "default_redact_errors")]
    pub redact_errors: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowedHost {
    pub host: String,
    pub scheme: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub private_key: Option<String>,

    pub public_key: Option<String>,

    pub key_id: Option<String>,

    #[serde(default = "default_expiration_seconds")]
    pub default_expiration_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthKeyConfig {
    pub key_id: Option<String>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StoreConfig {
    #[serde(rename = "filesystem")]
    Filesystem(FilesystemStoreConfig),
    #[serde(rename = "s3")]
    S3(S3StoreConfig),
    #[serde(rename = "aws")]
    Aws(AwsStoreConfig),
    #[serde(rename = "cloudflare")]
    Cloudflare(CloudflareStoreConfig),
    #[serde(rename = "backblaze")]
    Backblaze(BackblazeStoreConfig),
    #[serde(rename = "minio")]
    Minio(MinioStoreConfig),
    #[serde(rename = "tigris")]
    Tigris(TigrisStoreConfig),
    #[serde(rename = "memory")]
    Memory,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilesystemStoreConfig {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3StoreConfig {
    pub bucket: String,

    #[serde(default = "default_s3_region")]
    pub region: String,

    #[serde(default)]
    pub endpoint: String,

    #[serde(default)]
    pub path_style: bool,

    #[serde(default = "default_presigned_url_expiration")]
    pub presigned_url_expiration: u64,

    #[serde(default)]
    pub prefix: String,

    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsStoreConfig {
    pub bucket: String,

    #[serde(default = "default_s3_region")]
    pub region: String,

    pub access_key_id: String,
    pub secret_access_key: String,

    #[serde(default)]
    pub prefix: String,

    #[serde(default = "default_presigned_url_expiration")]
    pub presigned_url_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudflareStoreConfig {
    pub bucket: String,
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,

    #[serde(default)]
    pub prefix: String,

    #[serde(default = "default_presigned_url_expiration")]
    pub presigned_url_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackblazeStoreConfig {
    pub bucket: String,
    pub key_id: String,
    pub application_key: String,

    #[serde(default)]
    pub prefix: String,

    #[serde(default = "default_presigned_url_expiration")]
    pub presigned_url_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MinioStoreConfig {
    pub bucket: String,
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,

    #[serde(default)]
    pub prefix: String,

    #[serde(default = "default_presigned_url_expiration")]
    pub presigned_url_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TigrisStoreConfig {
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,

    #[serde(default)]
    pub prefix: String,

    #[serde(default = "default_presigned_url_expiration")]
    pub presigned_url_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,

    #[serde(default = "default_log_format")]
    pub format: String,
}

// Default value functions
fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_checkpoint_freq_seconds() -> u64 {
    10
}

fn default_doc_gc() -> bool {
    true
}

fn default_redact_errors() -> bool {
    false
}

fn default_expiration_seconds() -> u64 {
    3600
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_presigned_url_expiration() -> u64 {
    3600
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            url: None,
            allowed_hosts: Vec::new(),
            checkpoint_freq_seconds: default_checkpoint_freq_seconds(),
            doc_gc: default_doc_gc(),
            redact_errors: default_redact_errors(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            private_key: None,
            public_key: None,
            key_id: None,
            default_expiration_seconds: default_expiration_seconds(),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self::Memory
    }
}

impl StoreConfig {
    /// Convert provider-specific configs to generic S3 config for internal use
    pub fn to_s3_config(&self) -> Option<S3StoreConfig> {
        match self {
            StoreConfig::S3(config) => Some(config.clone()),
            StoreConfig::Aws(aws) => Some(S3StoreConfig {
                bucket: aws.bucket.clone(),
                region: aws.region.clone(),
                endpoint: String::new(),
                path_style: false,
                presigned_url_expiration: aws.presigned_url_expiration,
                prefix: aws.prefix.clone(),
                access_key_id: Some(aws.access_key_id.clone()),
                secret_access_key: Some(aws.secret_access_key.clone()),
            }),
            StoreConfig::Cloudflare(cf) => Some(S3StoreConfig {
                bucket: cf.bucket.clone(),
                region: "auto".to_string(),
                endpoint: format!("https://{}.r2.cloudflarestorage.com", cf.account_id),
                path_style: true,
                presigned_url_expiration: cf.presigned_url_expiration,
                prefix: cf.prefix.clone(),
                access_key_id: Some(cf.access_key_id.clone()),
                secret_access_key: Some(cf.secret_access_key.clone()),
            }),
            StoreConfig::Backblaze(b2) => Some(S3StoreConfig {
                bucket: b2.bucket.clone(),
                region: "us-west-000".to_string(),
                endpoint: "https://s3.us-west-000.backblazeb2.com".to_string(),
                path_style: false,
                presigned_url_expiration: b2.presigned_url_expiration,
                prefix: b2.prefix.clone(),
                access_key_id: Some(b2.key_id.clone()),
                secret_access_key: Some(b2.application_key.clone()),
            }),
            StoreConfig::Minio(minio) => Some(S3StoreConfig {
                bucket: minio.bucket.clone(),
                region: "us-east-1".to_string(),
                endpoint: minio.endpoint.clone(),
                path_style: true,
                presigned_url_expiration: minio.presigned_url_expiration,
                prefix: minio.prefix.clone(),
                access_key_id: Some(minio.access_key.clone()),
                secret_access_key: Some(minio.secret_key.clone()),
            }),
            StoreConfig::Tigris(tigris) => Some(S3StoreConfig {
                bucket: tigris.bucket.clone(),
                region: "auto".to_string(),
                endpoint: "https://fly.storage.tigris.dev".to_string(),
                path_style: false,
                presigned_url_expiration: tigris.presigned_url_expiration,
                prefix: tigris.prefix.clone(),
                access_key_id: Some(tigris.access_key_id.clone()),
                secret_access_key: Some(tigris.secret_access_key.clone()),
            }),
            _ => None,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Config {
    /// Load configuration from file with environment variable overrides
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = if let Some(path) = path {
            Self::from_file(path)?
        } else if Path::new("relay.toml").exists() {
            Self::from_file(Path::new("relay.toml"))?
        } else {
            Self::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides()?;

        // Validate final configuration
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from environment variables only
    pub fn from_env_only() -> Result<Self, ConfigError> {
        let mut config = Self::default();
        config.apply_env_overrides()?;
        config.validate()?;
        Ok(config)
    }

    fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadFile(path.to_path_buf(), e))?;

        toml::from_str(&contents).map_err(|e| ConfigError::ParseToml(path.to_path_buf(), e))
    }

    fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        use std::env;

        // Override server configuration
        if let Ok(host) = env::var("RELAY_SERVER_HOST") {
            tracing::info!(
                "Config override: server.host = {} (from RELAY_SERVER_HOST)",
                host
            );
            self.server.host = host;
        }

        if let Ok(port) = env::var("PORT") {
            tracing::info!("Config override: server.port = {} (from PORT)", port);
            self.server.port = port.parse().map_err(|_| ConfigError::InvalidPort(port))?;
        }

        if let Ok(metrics_port) = env::var("METRICS_PORT") {
            let port: u16 = metrics_port
                .parse()
                .map_err(|_| ConfigError::InvalidPort(metrics_port.clone()))?;
            tracing::info!(
                "Config override: metrics.port = {} (from METRICS_PORT)",
                port
            );
            if self.metrics.is_none() {
                self.metrics = Some(MetricsConfig { port });
            } else if let Some(ref mut metrics) = self.metrics {
                metrics.port = port;
            }
        }

        if let Ok(url) = env::var("RELAY_SERVER_URL") {
            tracing::info!(
                "Config override: server.url = {} (from RELAY_SERVER_URL)",
                url
            );
            self.server.url = Some(url);
        }

        if let Ok(checkpoint_freq) = env::var("RELAY_SERVER_CHECKPOINT_FREQ_SECONDS") {
            let freq: u64 = checkpoint_freq.parse().map_err(|_| {
                ConfigError::InvalidConfiguration(format!(
                    "Invalid checkpoint frequency: {}",
                    checkpoint_freq
                ))
            })?;
            tracing::info!("Config override: server.checkpoint_freq_seconds = {} (from RELAY_SERVER_CHECKPOINT_FREQ_SECONDS)", freq);
            self.server.checkpoint_freq_seconds = freq;
        }

        if let Ok(doc_gc) = env::var("RELAY_SERVER_DOC_GC") {
            let gc_enabled = match doc_gc.to_lowercase().as_str() {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                _ => {
                    return Err(ConfigError::InvalidConfiguration(format!(
                        "Invalid doc_gc value: {}",
                        doc_gc
                    )))
                }
            };
            tracing::info!(
                "Config override: server.doc_gc = {} (from RELAY_SERVER_DOC_GC)",
                gc_enabled
            );
            self.server.doc_gc = gc_enabled;
        }

        if let Ok(redact_errors) = env::var("RELAY_SERVER_REDACT_ERRORS") {
            let redact = match redact_errors.to_lowercase().as_str() {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                _ => {
                    return Err(ConfigError::InvalidConfiguration(format!(
                        "Invalid redact_errors value: {}",
                        redact_errors
                    )))
                }
            };
            tracing::info!(
                "Config override: server.redact_errors = {} (from RELAY_SERVER_REDACT_ERRORS)",
                redact
            );
            self.server.redact_errors = redact;
        }

        if let Ok(allowed_hosts) = env::var("RELAY_SERVER_ALLOWED_HOSTS") {
            let hosts: Vec<String> = allowed_hosts
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            let parsed_hosts = Self::parse_allowed_hosts(hosts)?;
            tracing::info!("Config override: server.allowed_hosts = {} hosts (from RELAY_SERVER_ALLOWED_HOSTS)", parsed_hosts.len());
            self.server.allowed_hosts = parsed_hosts;
        }

        // Override auth configuration
        if let Ok(auth_key) = env::var("RELAY_SERVER_AUTH") {
            let key_id = env::var("RELAY_SERVER_KEY_ID").ok();

            // Check if there's already a private key in the config
            let has_private_key = self.auth.iter().any(|config| config.private_key.is_some());

            if has_private_key {
                tracing::info!(
                    "Config override: RELAY_SERVER_AUTH overriding existing private key"
                );

                // Remove existing private key entries and add the new one
                self.auth.retain(|config| config.private_key.is_none());
                self.auth.push(AuthKeyConfig {
                    key_id,
                    private_key: Some(auth_key),
                    public_key: None,
                });
            } else {
                tracing::info!(
                    "Config override: RELAY_SERVER_AUTH added to multi-key list (from RELAY_SERVER_AUTH)"
                );

                // Add to existing multi-key list
                self.auth.push(AuthKeyConfig {
                    key_id,
                    private_key: Some(auth_key),
                    public_key: None,
                });
            }
        }

        // Override store configuration
        if let Ok(storage) = env::var("RELAY_SERVER_STORAGE") {
            if storage.starts_with("s3://") {
                // Parse S3 URL
                let url = Url::parse(&storage).map_err(|_| {
                    ConfigError::InvalidConfiguration(format!("Invalid S3 URL: {}", storage))
                })?;

                let bucket = url
                    .host_str()
                    .ok_or_else(|| {
                        ConfigError::InvalidConfiguration(
                            "Invalid S3 URL: missing bucket".to_string(),
                        )
                    })?
                    .to_string();

                let prefix = url.path().trim_start_matches('/');
                let prefix = if prefix.is_empty() {
                    String::new()
                } else {
                    prefix.to_string()
                };

                let region = env::var("AWS_REGION").unwrap_or_else(|_| default_s3_region());
                tracing::info!("Config override: store = S3 (bucket: {}, prefix: {}, region: {}) (from RELAY_SERVER_STORAGE, AWS_REGION={})", 
                    bucket, prefix, region, env::var("AWS_REGION").unwrap_or_else(|_| "not set".to_string()));
                self.store = StoreConfig::S3(S3StoreConfig {
                    bucket,
                    prefix,
                    region,
                    endpoint: String::new(),
                    path_style: false,
                    presigned_url_expiration: default_presigned_url_expiration(),
                    access_key_id: None,
                    secret_access_key: None,
                });
            } else {
                tracing::info!(
                    "Config override: store = Filesystem (path: {}) (from RELAY_SERVER_STORAGE)",
                    storage
                );
                self.store = StoreConfig::Filesystem(FilesystemStoreConfig { path: storage });
            }
        }

        // Override webhook configuration from environment
        if let Ok(webhook_config) = env::var("RELAY_SERVER_WEBHOOK_CONFIG") {
            let webhooks: Vec<CoreWebhookConfig> =
                serde_json::from_str(&webhook_config).map_err(|e| {
                    ConfigError::InvalidConfiguration(format!("Invalid webhook config JSON: {}", e))
                })?;
            tracing::info!(
                "Config override: {} webhooks loaded (from RELAY_SERVER_WEBHOOK_CONFIG)",
                webhooks.len()
            );
            self.webhooks = webhooks;
        }

        // Override logging configuration
        if let Ok(log_level) = env::var("RUST_LOG") {
            tracing::info!(
                "Config override: logging.level = {} (from RUST_LOG)",
                log_level
            );
            self.logging.level = log_level;
        }

        if let Ok(log_format) = env::var("RELAY_SERVER_LOG_FORMAT") {
            tracing::info!(
                "Config override: logging.format = {} (from RELAY_SERVER_LOG_FORMAT)",
                log_format
            );
            self.logging.format = log_format;
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate server configuration
        if self.server.port == 0 {
            return Err(ConfigError::InvalidConfiguration(
                "Server port cannot be 0".to_string(),
            ));
        }

        if let Some(ref metrics_config) = self.metrics {
            if metrics_config.port == 0 {
                return Err(ConfigError::InvalidConfiguration(
                    "Metrics port cannot be 0".to_string(),
                ));
            }

            if self.server.port == metrics_config.port {
                return Err(ConfigError::InvalidConfiguration(
                    "Server port and metrics port cannot be the same".to_string(),
                ));
            }
        }

        // Validate URL if present
        if let Some(ref url) = self.server.url {
            Url::parse(url)
                .map_err(|_| ConfigError::InvalidConfiguration(format!("Invalid URL: {}", url)))?;
        }

        // Validate store configuration
        match &self.store {
            StoreConfig::S3(s3) if s3.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "S3 bucket name cannot be empty".to_string(),
                ));
            }
            StoreConfig::Aws(aws) if aws.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "AWS S3 bucket name cannot be empty".to_string(),
                ));
            }
            StoreConfig::Cloudflare(cf) if cf.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "Cloudflare R2 bucket name cannot be empty".to_string(),
                ));
            }
            StoreConfig::Cloudflare(cf) if cf.account_id.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "Cloudflare R2 account_id cannot be empty".to_string(),
                ));
            }
            StoreConfig::Backblaze(b2) if b2.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "Backblaze B2 bucket name cannot be empty".to_string(),
                ));
            }
            StoreConfig::Minio(minio) if minio.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "MinIO bucket name cannot be empty".to_string(),
                ));
            }
            StoreConfig::Minio(minio) if minio.endpoint.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "MinIO endpoint cannot be empty".to_string(),
                ));
            }
            StoreConfig::Tigris(tigris) if tigris.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "Tigris bucket name cannot be empty".to_string(),
                ));
            }
            StoreConfig::Filesystem(fs) if fs.path.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "Filesystem path cannot be empty".to_string(),
                ));
            }
            _ => {}
        }

        // Validate multi-key auth configuration
        if !self.auth.is_empty() {
            self.validate_multi_key_auth()?;
        }

        // Validate webhook configurations
        for (i, webhook) in self.webhooks.iter().enumerate() {
            if webhook.url.is_empty() {
                return Err(ConfigError::InvalidConfiguration(format!(
                    "Webhook {} has empty URL",
                    i
                )));
            }

            // Validate URL format
            Url::parse(&webhook.url).map_err(|_| {
                ConfigError::InvalidConfiguration(format!(
                    "Webhook {} has invalid URL: {}",
                    i, webhook.url
                ))
            })?;
        }

        // Validate logging configuration
        match self.logging.format.as_str() {
            "json" | "pretty" => {}
            _ => {
                return Err(ConfigError::InvalidConfiguration(format!(
                    "Invalid log format: {}. Must be 'json' or 'pretty'",
                    self.logging.format
                )))
            }
        }

        Ok(())
    }

    fn validate_multi_key_auth(&self) -> Result<(), ConfigError> {
        use crate::auth::KeyId;

        let mut private_key_count = 0;
        let mut key_ids = std::collections::HashSet::new();

        for auth_config in &self.auth {
            // Validate key_id uniqueness (only for keys that have key_id)
            if let Some(ref key_id) = auth_config.key_id {
                if !key_ids.insert(key_id) {
                    return Err(ConfigError::InvalidConfiguration(format!(
                        "Duplicate key_id: {}",
                        key_id
                    )));
                }

                // Validate key_id format
                KeyId::new(key_id.clone()).map_err(|e| {
                    ConfigError::InvalidConfiguration(format!("Invalid key_id: {}", e))
                })?;
            }

            // Count private keys and validate key configuration
            match (&auth_config.private_key, &auth_config.public_key) {
                (Some(_), None) => {
                    private_key_count += 1;
                }
                (None, Some(_)) => {
                    // Public key only - validation will happen in key parsing
                }
                (Some(_), Some(_)) => {
                    return Err(ConfigError::InvalidConfiguration(
                        "Cannot specify both private_key and public_key in same auth entry"
                            .to_string(),
                    ));
                }
                (None, None) => {
                    return Err(ConfigError::InvalidConfiguration(
                        "Must specify either private_key or public_key in auth entry".to_string(),
                    ));
                }
            }
        }

        // Enforce single private key constraint
        if private_key_count > 1 {
            return Err(ConfigError::InvalidConfiguration(
                "Only one private_key allowed across all auth entries".to_string(),
            ));
        }

        Ok(())
    }

    fn parse_allowed_hosts(hosts: Vec<String>) -> Result<Vec<AllowedHost>, ConfigError> {
        let mut parsed_hosts = Vec::new();

        for host_str in hosts {
            if host_str.starts_with("http://") || host_str.starts_with("https://") {
                let url = Url::parse(&host_str).map_err(|_| {
                    ConfigError::InvalidConfiguration(format!(
                        "Invalid URL in allowed hosts: {}",
                        host_str
                    ))
                })?;

                let host = url.host_str().ok_or_else(|| {
                    ConfigError::InvalidConfiguration(format!("No host in URL: {}", host_str))
                })?;

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            auth: Vec::new(),
            store: StoreConfig::default(),
            webhooks: Vec::new(),
            logging: LoggingConfig::default(),
            metrics: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Use a mutex to prevent tests from running concurrently and interfering with each other
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env_vars<F>(vars: Vec<(&str, Option<&str>)>, test: F)
    where
        F: FnOnce(),
    {
        let _guard = TEST_MUTEX.lock().unwrap();

        // Save original values
        let original_values: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), env::var(key).ok()))
            .collect();

        // Clear all auth-related vars first
        for key in &["RELAY_SERVER_AUTH", "RELAY_SERVER_KEY_ID"] {
            env::remove_var(key);
        }

        // Set test values
        for (key, value) in &vars {
            if let Some(val) = value {
                env::set_var(key, val);
            } else {
                env::remove_var(key);
            }
        }

        // Run the test
        test();

        // Restore original values
        for (key, original_value) in original_values {
            if let Some(val) = original_value {
                env::set_var(&key, val);
            } else {
                env::remove_var(&key);
            }
        }
    }

    #[test]
    fn test_relay_server_auth_adds_to_empty_config() {
        with_env_vars(
            vec![
                ("RELAY_SERVER_AUTH", Some("test-auth-key")),
                ("RELAY_SERVER_KEY_ID", Some("test-key-id")),
            ],
            || {
                let config = Config::from_env_only().unwrap();

                // Should have one auth entry from RELAY_SERVER_AUTH
                assert_eq!(config.auth.len(), 1);
                assert_eq!(config.auth[0].key_id, Some("test-key-id".to_string()));
                assert!(config.auth[0].private_key.is_some());
                assert_eq!(
                    config.auth[0].private_key.as_ref().unwrap(),
                    "test-auth-key"
                );
            },
        );
    }

    #[test]
    fn test_relay_server_auth_with_existing_public_keys() {
        // First create a config with some public keys from a TOML file
        let toml_content = r#"
[[auth]]
key_id = "public-key-1"
public_key = "test-public-key-1"

[[auth]]
key_id = "public-key-2"
public_key = "test-public-key-2"
"#;

        // Create a temporary config file
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_config.toml");
        std::fs::write(&config_path, toml_content).unwrap();

        // Load config from file, then apply env vars
        let mut config = Config::from_file(&config_path).unwrap();

        with_env_vars(
            vec![
                ("RELAY_SERVER_AUTH", Some("env-private-key")),
                ("RELAY_SERVER_KEY_ID", Some("env-key")),
            ],
            || {
                config.apply_env_overrides().unwrap();

                // Should have 3 auth entries: 2 public keys + 1 private key from env
                assert_eq!(config.auth.len(), 3);

                // Check that public keys are preserved
                let public_keys = config
                    .auth
                    .iter()
                    .filter(|a| a.public_key.is_some())
                    .count();
                assert_eq!(public_keys, 2);

                // Check that private key was added
                let private_keys = config
                    .auth
                    .iter()
                    .filter(|a| a.private_key.is_some())
                    .count();
                assert_eq!(private_keys, 1);

                // Check the private key content
                let private_key_entry = config
                    .auth
                    .iter()
                    .find(|a| a.key_id == Some("env-key".to_string()));
                assert!(private_key_entry.is_some());
                assert_eq!(
                    private_key_entry.unwrap().private_key.as_ref().unwrap(),
                    "env-private-key"
                );
            },
        );

        // Clean up
        std::fs::remove_file(&config_path).ok();
    }

    #[test]
    fn test_relay_server_auth_overrides_existing_private_key() {
        // Create config with existing private key
        let toml_content = r#"
[[auth]]
key_id = "original-private"
private_key = "original-private-key"

[[auth]]
key_id = "public-key-1"
public_key = "test-public-key"
"#;

        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_config_override.toml");
        std::fs::write(&config_path, toml_content).unwrap();

        let mut config = Config::from_file(&config_path).unwrap();

        with_env_vars(
            vec![
                ("RELAY_SERVER_AUTH", Some("new-private-key")),
                ("RELAY_SERVER_KEY_ID", Some("new-private")),
            ],
            || {
                config.apply_env_overrides().unwrap();

                // Should have 2 auth entries: 1 public key + 1 private key (env override)
                assert_eq!(config.auth.len(), 2);

                // Should have only one private key
                let private_keys = config
                    .auth
                    .iter()
                    .filter(|a| a.private_key.is_some())
                    .count();
                assert_eq!(private_keys, 1);

                // The private key should be from env var, not the original
                let private_key_entry = config
                    .auth
                    .iter()
                    .find(|a| a.private_key.is_some())
                    .unwrap();
                assert_eq!(private_key_entry.key_id, Some("new-private".to_string()));
                assert_eq!(
                    private_key_entry.private_key.as_ref().unwrap(),
                    "new-private-key"
                );

                // Public key should still be there
                let public_key_entry = config.auth.iter().find(|a| a.public_key.is_some()).unwrap();
                assert_eq!(public_key_entry.key_id, Some("public-key-1".to_string()));
            },
        );

        // Clean up
        std::fs::remove_file(&config_path).ok();
    }
}
