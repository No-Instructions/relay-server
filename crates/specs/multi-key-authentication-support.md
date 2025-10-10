# Architecture Change Request: Multi-Key Authentication Support

## Problem Statement

The Y-Sweet relay server currently supports only a single authentication key, creating operational challenges during key rotation:

1. **Service Disruption**: Key rotation requires coordinated updates across all services
2. **Token Rejection Risk**: Valid tokens become invalid immediately when keys are rotated
3. **Deployment Complexity**: Rolling deployments are difficult as new services may reject tokens signed with old keys
4. **Emergency Response**: Key compromise scenarios require immediate coordination across all instances

Supporting multiple keys in parallel would enable seamless key rotation without service disruption.

## Current State Analysis

### Current Configuration Structure

```rust
// y-sweet-core/src/config.rs:75
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub private_key: Option<String>,    // Single private key
    pub public_key: Option<String>,     // Single public key (verification-only)
    pub key_id: Option<String>,         // Single key identifier
    #[serde(default = "default_expiration_seconds")]
    pub default_expiration_seconds: u64,
}
```

### Current Authenticator Architecture

```rust
// y-sweet-core/src/auth.rs:128
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Authenticator {
    key_material: AuthKeyMaterial,      // Single key
    key_id: Option<String>,             // Single key ID
}
```

### Current Initialization Flow

```rust
// y-sweet/src/main.rs:465-478
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
    None
};
```

### Current Verification Logic

```rust
// y-sweet-core/src/auth.rs:571-584
let token = if let Some((prefix, token)) = token.split_once('.') {
    if Some(prefix) != self.key_id.as_deref() {
        return Err(AuthError::KeyMismatch);  // Single key_id check
    }
    token
} else {
    if self.key_id.is_some() {
        return Err(AuthError::KeyMismatch);
    }
    token
};
```

## Proposed Solution

Implement multi-key authentication with the following constraints:
- **At most one private key** (for signing)
- **Multiple public keys** (for verification)
- **Clean TOML configuration** using `[[auth]]` array syntax
- **No backward compatibility** - requires migration from existing single-key configurations
- **TOML-only configuration** - no environment variable support for multi-key setups

## Architecture Changes

### 1. New Configuration Structure

```toml
# Multi-key configuration using array syntax
[[auth]]
private_key = "QDaX3oevZGEcHTKgXasP4fy3FahqtDXx7JkZLXlWk4g"  # HMAC signing key

[[auth]]
key_id = "prod-2024-v1"
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"""  # ECDSA verification key

[[auth]]
key_id = "backup-key"
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"""  # Additional verification key
```

### 2. Enhanced AuthConfig

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    // ... existing fields ...
    
    // Multi-key auth configuration
    pub auth: Vec<AuthKeyConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthKeyConfig {
    pub key_id: Option<String>,            // Optional for ALL key types (performance optimization)
    pub private_key: Option<String>,       // For HMAC signing/verification
    pub public_key: Option<String>,        // For ECDSA verification-only
}
```

### 3. Multi-Key Authenticator

```rust
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Authenticator {
    keys: Vec<AuthKeyEntry>,               // All keys (for iteration)
    key_lookup: std::collections::HashMap<String, usize>, // key_id -> index for performance
    keys_without_id: Vec<usize>,           // Indices of keys without key_id
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
struct AuthKeyEntry {
    key_id: Option<String>,                // Optional for performance optimization
    key_material: AuthKeyMaterial,
    can_sign: bool,                        // True only for private keys
}

impl Authenticator {
    /// Create authenticator from multi-key configuration
    pub fn from_multi_key_config(configs: &[AuthKeyConfig]) -> Result<Self, AuthError> {
        let mut keys = Vec::new();
        let mut key_lookup = std::collections::HashMap::new();
        let mut keys_without_id = Vec::new();
        let mut private_key_count = 0;
        
        for (index, config) in configs.iter().enumerate() {
            let (key_material, can_sign) = match (&config.private_key, &config.public_key) {
                (Some(private_key), None) => {
                    private_key_count += 1;
                    if private_key_count > 1 {
                        return Err(AuthError::MultiplePrivateKeys);
                    }
                    let material = parse_key_format(private_key)?;
                    (material, true)
                }
                (None, Some(public_key)) => {
                    let material = parse_key_format(public_key)?;
                    (material, false)
                }
                (Some(_), Some(_)) => {
                    return Err(AuthError::BothKeysProvided);
                }
                (None, None) => {
                    return Err(AuthError::NoKeyProvided);
                }
            };
            
            let key_entry = AuthKeyEntry {
                key_id: config.key_id.clone(),
                key_material,
                can_sign,
            };
            
            // Build lookup structures
            if let Some(ref key_id) = config.key_id {
                key_lookup.insert(key_id.clone(), index);
            } else {
                keys_without_id.push(index);
            }
            
            keys.push(key_entry);
        }
        
        Ok(Self {
            keys,
            key_lookup,
            keys_without_id,
        })
    }
    
}
```

### 4. Enhanced Token Verification

```rust
impl Authenticator {
    pub fn verify_token_auto(
        &self,
        token: &str,
        current_time: u64,
    ) -> Result<Permission, AuthError> {
        // Extract key_id from token (if present)
        let (token_key_id, token_data) = if let Some((prefix, token_part)) = token.split_once('.') {
            (Some(prefix), token_part)
        } else {
            (None, token)
        };
        
        // Try verification with matching key
        if let Some(key_id) = token_key_id {
            // Use hashmap lookup for keys with key_id (O(1) performance)
            if let Some(&index) = self.key_lookup.get(key_id) {
                return self.verify_with_key_entry(&self.keys[index], token_data, current_time);
            } else {
                return Err(AuthError::KeyMismatch);
            }
        }
        
        // For tokens without key_id, try all keys without key_id in configuration order
        for &index in &self.keys_without_id {
            if let Ok(permission) = self.verify_with_key_entry(&self.keys[index], token, current_time) {
                return Ok(permission);
            }
        }
        
        // Generic error - don't reveal which keys were tried for security
        Err(AuthError::KeyMismatch)
    }
    
    fn verify_with_key_entry(
        &self,
        key_entry: &AuthKeyEntry,
        token: &str,
        current_time: u64,
    ) -> Result<Permission, AuthError> {
        // Create temporary single-key authenticator for verification
        let temp_auth = Self {
            keys: vec![key_entry.clone()],
            signing_key_id: None, // Don't need signing for verification
        };
        
        // Use existing verification logic
        match detect_token_format(token) {
            TokenFormat::Custom => temp_auth.verify_custom_token(token, current_time),
            TokenFormat::Cwt => temp_auth.verify_cwt_token(token, current_time),
        }
    }
}
```

### 5. Enhanced Token Generation

```rust
impl Authenticator {
    pub fn server_token(&self) -> Result<String, AuthError> {
        let signing_key = self.get_signing_key()?;
        self.server_token_with_key(signing_key)
    }
    
    pub fn gen_doc_token_cwt(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        user: Option<&str>,
        channel: Option<String>,
    ) -> Result<String, AuthError> {
        let signing_key = self.get_signing_key()?;
        self.gen_doc_token_cwt_with_key(
            signing_key, doc_id, authorization, expiration_time, user, channel
        )
    }
    
    fn get_signing_key(&self) -> Result<&AuthKeyEntry, AuthError> {
        // Find the first key that can sign (there should be at most one)
        self.keys
            .iter()
            .find(|k| k.can_sign)
            .ok_or(AuthError::NoSigningKey)
    }
}
```

### 6. Configuration Loading Changes

```rust
// y-sweet/src/main.rs - Updated authentication loading
fn create_authenticator_from_config(config: &Config) -> Result<Option<Authenticator>, anyhow::Error> {
    if !config.auth.is_empty() {
        let authenticator = Authenticator::from_multi_key_config(&config.auth)?;
        Ok(Some(authenticator))
    } else {
        // No authentication configured
        Ok(None)
    }
}
```

### 7. Configuration Validation

```rust
impl Config {
    fn validate(&self) -> Result<(), ConfigError> {
        // ... existing validation ...
        
        // Validate multi-key authentication
        if !self.auth.is_empty() {
            self.validate_multi_key_auth()?;
        }
        
        Ok(())
    }
    
    fn validate_multi_key_auth(&self) -> Result<(), ConfigError> {
        let mut private_key_count = 0;
        let mut key_ids = std::collections::HashSet::new();
        
        for auth_config in &self.auth {
            // Validate key_id uniqueness (only for keys that have key_id)
            if let Some(ref key_id) = auth_config.key_id {
                if !key_ids.insert(key_id) {
                    return Err(ConfigError::InvalidConfiguration(
                        format!("Duplicate key_id: {}", key_id)
                    ));
                }
                
                // Validate key_id format
                KeyId::new(key_id.clone())
                    .map_err(|e| ConfigError::InvalidConfiguration(format!("Invalid key_id: {}", e)))?;
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
                        "Cannot specify both private_key and public_key in same auth entry".to_string()
                    ));
                }
                (None, None) => {
                    return Err(ConfigError::InvalidConfiguration(
                        "Must specify either private_key or public_key in auth entry".to_string()
                    ));
                }
            }
        }
        
        // Enforce single private key constraint
        if private_key_count > 1 {
            return Err(ConfigError::InvalidConfiguration(
                "Only one private_key allowed across all auth entries".to_string()
            ));
        }
        
        Ok(())
    }
}
```

### 8. Error Handling Extensions

```rust
#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    // ... existing errors ...
    
    #[error("Multiple private keys not allowed")]
    MultiplePrivateKeys,
    
    #[error("Cannot specify both private_key and public_key")]
    BothKeysProvided,
    
    #[error("Must specify either private_key or public_key")]
    NoKeyProvided,
    
    #[error("No signing key available")]
    NoSigningKey,
    
    #[error("Duplicate key_id: {0}")]
    DuplicateKeyId(String),
    
}
```

## Design Decisions

### 1. Configuration Migration
**No backward compatibility** - The configuration changes from `auth: Option<AuthConfig>` to `auth: Vec<AuthKeyConfig>`. Users must migrate existing configurations:

```toml
# OLD (no longer supported)
[auth]
private_key = "key123"
key_id = "main"

# NEW (required)
[[auth]]
private_key = "key123"
key_id = "main"
```

### 2. Key ID Requirements
**key_id is optional for ALL key types** - Whether HMAC, ECDSA, or legacy keys, `key_id` is optional:

```toml
# HMAC without key_id (common for single signing key)
[[auth]]
private_key = "hmac_key"

# ECDSA with key_id (recommended for performance)
[[auth]]
key_id = "ecdsa-v1"
public_key = "-----BEGIN PUBLIC KEY-----..."
```

### 3. Environment Variables
**No environment variable support for multi-key** - Configuration is TOML-only. No `RELAY_SERVER_AUTH_KEYS` or similar environment variables for multi-key setups.

### 4. Error Messages
**Generic errors for security** - Token verification failures return `AuthError::KeyMismatch` without revealing:
- Number of keys tried
- Key types or algorithms  
- Which specific keys failed
- Internal key structure

### 5. Key Ordering
**Configuration order determines verification order** - For tokens without `key_id`, keys are tried in the order they appear in the TOML `[[auth]]` array.

### 6. Legacy Token Handling
**Full legacy token support** - Legacy 30-byte keys support both verification and generation:
- ✅ **Allow**: Verification of existing legacy tokens
- ✅ **Allow**: Generation of new legacy tokens when legacy key is configured

## Implementation Strategy

### Phase 1: Core Implementation
- Implement multi-key `Authenticator` with `Vec<AuthKeyEntry>`
- Add `[[auth]]` array configuration parsing
- Implement token verification with key_id matching
- Add configuration validation for single private key constraint

### Phase 2: Integration
- Update main.rs authentication loading logic
- Update documentation with new configuration format
- Comprehensive testing of key rotation scenarios

## Configuration Examples

### New Multi-Key Format

```toml
# HMAC signing key (no key_id needed)
[[auth]]
private_key = "QDaX3oevZGEcHTKgXasP4fy3FahqtDXx7JkZLXlWk4g"

# ECDSA verification keys (key_id for performance)
[[auth]]
key_id = "ecdsa-v1"
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"""

[[auth]]
key_id = "ecdsa-v2"
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"""
```

### Verification-Only Configuration

```toml
# Multiple public keys for verification only (no signing)
[[auth]]
key_id = "external-service-1"
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"""

[[auth]]
key_id = "external-service-2"
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----
"""

# Legacy key without key_id (fallback verification)
[[auth]]
public_key = "QDaX3oevZGEcHTKgXasP4fy3FahqtDXx7JkZLXlWk4g"  # HMAC key as public
```


## Implementation Priority

1. **High Priority**: Core `Authenticator` multi-key support
2. **High Priority**: Configuration parsing and validation
3. **Medium Priority**: Advanced key management features
4. **Medium Priority**: Documentation and examples
5. **Low Priority**: Advanced configuration features

## Testing Requirements

### Unit Tests
1. Multi-key configuration parsing and validation
2. Token verification with multiple keys
3. Single private key constraint enforcement
4. Key rotation scenarios

### Integration Tests
1. Rolling deployment with mixed key configurations
2. Token persistence across key updates
3. Error handling for invalid configurations

### Security Tests
1. Key isolation (compromised key doesn't affect others)
2. Private key constraint enforcement
3. Token replay prevention
4. Key_id validation and matching

## Benefits

1. **Zero-Downtime Key Rotation**: Add new keys before removing old ones
2. **Operational Flexibility**: Support mixed key types and algorithms
3. **Enhanced Security**: Multiple verification keys for different services
5. **Clean Configuration**: Readable TOML syntax with `[[auth]]` arrays

## Success Metrics

1. New multi-key configurations validate correctly  
2. Token verification works with any configured key
3. Key rotation scenarios complete without service disruption
4. Single private key constraint is properly enforced
5. Performance impact < 10% for token verification with 2-3 keys

This architecture change enables robust key rotation capabilities with a clean, extensible configuration format.