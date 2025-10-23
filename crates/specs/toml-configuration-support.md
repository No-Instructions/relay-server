# Architecture Change Request: TOML Configuration File Support

## Summary
Add support for TOML-based configuration files to the relay server, allowing configuration via files as defaults with environment variable overrides. This will improve deployment flexibility, configuration management, and operational consistency.

## Motivation

### Current State
- Configuration exclusively via environment variables
- No centralized configuration management
- Difficult to manage complex deployments with many settings
- No configuration validation before runtime
- No way to version control configuration alongside code

### Problems
1. **Operational Complexity**: Managing dozens of environment variables across environments
2. **Configuration Drift**: No single source of truth for configuration
3. **Limited Validation**: Environment variables are strings, no type checking
4. **Poor Discoverability**: No documentation of available configuration options
5. **Deployment Friction**: Different deployment targets require different env var mechanisms

### Benefits
1. **Centralized Configuration**: Single file containing all settings
2. **Type Safety**: TOML provides typed configuration values
3. **Documentation**: Comments in config files explain options
4. **Version Control**: Configuration can be tracked in git
5. **Environment Flexibility**: Easy per-environment config files
6. **Backward Compatibility**: Environment variables still override file settings

## Proposed Design

### Configuration Precedence (highest to lowest)
1. CLI arguments (explicit command-line flags)
2. Environment variables (RELAY_SERVER_* only, not Y_SWEET_*)
3. TOML configuration file
4. Built-in defaults

Note: The system will log when configuration values are overridden by higher-precedence sources.

### Command Line Interface
```bash
# Use default relay.toml if it exists in current directory
y-sweet serve

# Specify custom config file
y-sweet serve -c production.toml
y-sweet serve --config /etc/relay/config.toml

# Configuration management commands
y-sweet config validate                    # Validate default relay.toml
y-sweet config validate -c production.toml # Validate specific file
y-sweet config show                        # Show merged config from relay.toml + env vars
y-sweet config show -c production.toml     # Show merged config from specific file
```

Note: Configuration file is only looked for in the current directory by default (./relay.toml), not in system directories like /etc or ~/.config.

### Configuration Management Commands

The implementation includes dedicated configuration management commands following the pattern used by tools like Fly.io:

#### `y-sweet config validate`
- Validates TOML configuration files for syntax and logical errors
- Provides detailed error messages for invalid configurations
- Shows a configuration summary when validation passes
- Applies environment variable overrides before validation
- Example output:
  ```
  ✅ Configuration is valid!
  
  Configuration summary:
    Server: 0.0.0.0:8080
    Metrics: 0.0.0.0:9090
    Auth: disabled
    Store: Memory
    Webhooks: 0
    Logging: info (pretty)
    URL prefix: https://api.example.com
    Allowed hosts: 3
  ```

#### `y-sweet config show`
- Displays the fully merged configuration (TOML file + environment overrides)
- Outputs in TOML format for easy inspection
- Shows exactly what configuration the server would use
- Logs when environment variables override file values
- Useful for debugging configuration issues

### TOML Configuration Schema

```toml
# relay.toml - Relay Server Configuration File
# This file provides defaults that can be overridden by environment variables

[server]
# Server binding configuration
host = "0.0.0.0"              # RELAY_SERVER_HOST
port = 8080                   # PORT (standard env var)
metrics_port = 9090           # METRICS_PORT

# URL configuration
url = "https://api.example.com"  # RELAY_SERVER_URL

# Allowed hosts for context-aware URL generation
allowed_hosts = [
    { host = "api.example.com", scheme = "https" },
    { host = "localhost:8080", scheme = "http" },
    { host = "app.flycast", scheme = "http" }
]

# Checkpoint frequency in seconds
checkpoint_freq_seconds = 60  # RELAY_SERVER_CHECKPOINT_FREQ_SECONDS

# Document garbage collection
doc_gc = true                 # RELAY_SERVER_DOC_GC

# Error redaction in responses
redact_errors = false         # RELAY_SERVER_REDACT_ERRORS

[auth]
# Authentication configuration
enabled = true
# Private key for token signing (base64 encoded)
# Can be overridden by RELAY_SERVER_AUTH
private_key = "base64_encoded_key_here"
key_id = "prod-key-2024"     # RELAY_SERVER_KEY_ID

# Token defaults
default_expiration_seconds = 3600  # RELAY_SERVER_DEFAULT_EXPIRATION_SECONDS

[store]
# Storage backend configuration
# Type can be: "filesystem", "s3", "memory"
type = "s3"                   # RELAY_SERVER_STORAGE (as s3://bucket/prefix)

[store.s3]
# S3-specific configuration (when store.type = "s3")
bucket = "relay-docs"         # STORAGE_BUCKET or AWS_S3_BUCKET
region = "us-east-1"          # AWS_REGION
endpoint = ""                 # AWS_ENDPOINT_URL_S3 (for S3-compatible services)
path_style = false            # AWS_S3_USE_PATH_STYLE
presigned_url_expiration = 3600  # RELAY_SERVER_S3_PRESIGNED_URL_EXPIRATION
prefix = ""                   # STORAGE_PREFIX or AWS_S3_BUCKET_PREFIX

# AWS credentials (usually from IAM role or env vars)
# access_key_id = ""          # AWS_ACCESS_KEY_ID
# secret_access_key = ""      # AWS_SECRET_ACCESS_KEY

[store.filesystem]
# Filesystem storage configuration (when store.type = "filesystem")
path = "/var/lib/relay/data"  # RELAY_SERVER_STORAGE (as filesystem path)

[[webhooks]]
# Webhook configuration (can have multiple)
# Can be overridden by RELAY_SERVER_WEBHOOK_CONFIG (as JSON array)
url = "https://webhook.example.com/relay"
auth_token = "Bearer webhook_secret_123"
prefix = "org-123-"           # Optional: only send events for docs with this prefix
timeout_ms = 5000             # Optional: request timeout
retry_count = 3               # Optional: number of retries
retry_delay_ms = 1000         # Optional: delay between retries

[[webhooks]]
url = "https://backup.webhook.com/events"
auth_token = "Bearer backup_secret"
# No prefix = receives all events

[logging]
# Logging configuration
level = "info"                # RUST_LOG
format = "json"               # RELAY_SERVER_LOG_FORMAT: "json" or "pretty"
```

### Implementation Plan

#### Phase 1: Core Configuration Module
```rust
// crates/y-sweet-core/src/config.rs
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    
    #[serde(default)]
    pub auth: AuthConfig,
    
    #[serde(default)]
    pub store: StoreConfig,
    
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    
    #[serde(default)]
    pub logging: LoggingConfig,
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
    
    fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadFile(path.to_path_buf(), e))?;
        
        toml::from_str(&contents)
            .map_err(|e| ConfigError::ParseToml(path.to_path_buf(), e))
    }
    
    fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        // Override with environment variables, logging when overrides occur
        if let Ok(host) = std::env::var("RELAY_SERVER_HOST") {
            tracing::info!("Config override: server.host = {} (from RELAY_SERVER_HOST)", host);
            self.server.host = host;
        }
        
        if let Ok(port) = std::env::var("PORT") {
            tracing::info!("Config override: server.port = {} (from PORT)", port);
            self.server.port = port.parse()
                .map_err(|_| ConfigError::InvalidPort(port))?;
        }
        
        // ... apply all other env var overrides with logging
        
        Ok(())
    }
    
    fn validate(&self) -> Result<(), ConfigError> {
        // Strict validation - fail on any invalid configuration
        if self.server.port == 0 {
            return Err(ConfigError::InvalidConfiguration(
                "Server port cannot be 0".to_string()
            ));
        }
        
        if self.server.port > 65535 {
            return Err(ConfigError::InvalidConfiguration(
                format!("Server port {} is invalid", self.server.port)
            ));
        }
        
        // Validate store configuration
        match &self.store {
            StoreConfig::S3(s3) if s3.bucket.is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "S3 bucket name cannot be empty".to_string()
                ));
            }
            StoreConfig::Filesystem(fs) if fs.path.as_os_str().is_empty() => {
                return Err(ConfigError::InvalidConfiguration(
                    "Filesystem path cannot be empty".to_string()
                ));
            }
            _ => {}
        }
        
        // Validate webhook configurations
        for (i, webhook) in self.webhooks.iter().enumerate() {
            if webhook.url.is_empty() {
                return Err(ConfigError::InvalidConfiguration(
                    format!("Webhook {} has empty URL", i)
                ));
            }
        }
        
        // ... additional strict validation
        
        Ok(())
    }
}
```

#### Phase 2: CLI Integration
```rust
// crates/y-sweet/src/main.rs
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum ServSubcommand {
    Serve {
        /// Path to configuration file
        #[clap(short = 'c', long = "config")]
        config: Option<PathBuf>,
        
        // ... existing args (port, host, etc.)
    },
    
    /// Configuration management commands
    Config {
        #[clap(subcommand)]
        cmd: ConfigSubcommand,
    },
    
    // ... other commands
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
```

#### Phase 3: Server Integration
```rust
// crates/y-sweet/src/main.rs
async fn serve_command(args: ServeArgs) -> Result<()> {
    // Load configuration
    let config = args.load_config()
        .context("Failed to load configuration")?;
    
    // Initialize logging based on config
    init_logging(&config.logging)?;
    
    // Create store from config
    let store = create_store(&config.store).await?;
    
    // Create authenticator from config
    let authenticator = if config.auth.enabled {
        Some(create_authenticator(&config.auth)?)
    } else {
        None
    };
    
    // Create server with config
    let server = Server::new(
        store,
        Duration::from_secs(config.server.checkpoint_freq_seconds),
        authenticator,
        config.server.url.as_ref().map(|s| Url::parse(s)).transpose()?,
        config.server.allowed_hosts.clone(),
        CancellationToken::new(),
        config.server.doc_gc,
        Some(config.webhooks.clone()),
    ).await?;
    
    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await?;
    
    info!("Starting relay server on {}", addr);
    server.serve(listener, config.server.redact_errors).await?;
    
    Ok(())
}
```

### Migration Guide

#### For Existing Deployments
1. Create initial config file manually based on your current environment variables

2. Validate your configuration:
   ```bash
   # Validate config file
   y-sweet config validate -c relay.toml
   
   # Show merged config (file + env vars)
   y-sweet config show -c relay.toml
   ```

3. Test with both config file and env vars:
   ```bash
   # Test config file
   y-sweet serve -c relay.toml
   
   # Test env var override (note: uses PORT, not Y_SWEET_PORT)
   PORT=9000 y-sweet serve -c relay.toml
   ```

4. Gradually migrate from env vars to config files

#### Docker Integration
```dockerfile
# Add default config
COPY relay.toml /etc/relay/relay.toml

# Allow override via volume mount
VOLUME /config

# Use config with fallback
CMD ["y-sweet", "serve", "-c", "/config/relay.toml"]
```

### Dependencies

Add to `Cargo.toml`:
```toml
[dependencies]
toml = "0.8"
serde = { version = "1.0", features = ["derive"] }
```

### Testing Strategy

1. **Unit Tests**: Config loading, parsing, strict validation
2. **Integration Tests**: Environment variable overrides with logging verification
3. **E2E Tests**: Full server startup with various configs
4. **Priority Tests**: Verify CLI > ENV > TOML > defaults precedence

### Rollout Plan

1. **✅ v1.0**: Basic TOML support with core settings - **COMPLETED**
2. **✅ v1.1**: Advanced features (config validation, show commands) - **COMPLETED**
3. **Future**: Potential optimization of environment variable handling

---

**Status**: ✅ **IMPLEMENTED**  
**Author**: Architecture Team  
**Date**: 2025-01-08  
**Implementation Date**: 2025-09-08  
**Review**: ✅ Complete