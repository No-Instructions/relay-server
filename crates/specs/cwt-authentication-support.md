# Architecture Change Request: CWT (CBOR Web Token) Authentication Support

## Problem Statement
The relay server currently uses a custom token format based on bincode serialization and SHA256 hashing. While functional, this approach lacks standardization and interoperability. Adding support for CWT (CBOR Web Token) as defined in RFC 8392 would provide:
- Industry-standard token format
- Better interoperability with systems using CBOR/COSE
- Smaller token sizes compared to JWT (binary vs text encoding)
- User identification capabilities
- Prefix-based access control for document namespaces

## Proposed Solution
Add CWT as an alternative authentication token format alongside the existing custom format, maintaining backward compatibility while enabling gradual migration to the standard. Include user identification and prefix-based token support.

## Architecture Changes

### 1. New CWT Module
Create `crates/relay-server-core/src/cwt.rs` with:
- CWT token creation and validation using `coset` crate for COSE primitives
- CBOR encoding/decoding with `ciborium`
- Claims mapping between relay server permissions and CWT claims
- User and prefix token support

### 2. Token Format Detection
Implement automatic token format detection:
- Custom tokens: Base64-encoded bincode (current format)
- CWT tokens: CBOR with optional CWT tag (61)
- Detection based on binary structure and CBOR validation

### 3. Enhanced Permission System
Extend the Permission enum to support prefix tokens and user identification:

```rust
#[derive(Serialize, Deserialize)]
pub struct DocPermission {
    pub doc_id: String,
    pub authorization: Authorization,
    pub user: Option<String>,  // New: User identifier
}

#[derive(Serialize, Deserialize)]
pub struct FilePermission {
    pub file_hash: String,
    pub authorization: Authorization,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub doc_id: String,
    pub user: Option<String>,  // New: User identifier
}

#[derive(Serialize, Deserialize)]
pub struct PrefixPermission {
    pub prefix: String,        // New: Document ID prefix (e.g., "org123-")
    pub authorization: Authorization,
    pub user: Option<String>,  // New: User identifier
}

#[derive(Serialize, Deserialize)]
pub enum Permission {
    Server,
    Doc(DocPermission),
    File(FilePermission),
    Prefix(PrefixPermission),  // New: Prefix-based access
}
```

### 4. Claims Mapping
Map relay server permissions to CWT claims:

| Relay Server Permission | CWT Claim | Description |
|------------------------|-----------|-------------|
| Permission::Server | `scope` (private use claim -80201) | Value: "server" |
| Permission::Doc | `scope` (private use claim -80201) | Value: "doc:{doc_id}:{auth}" |
| Permission::File | `scope` (private use claim -80201) | Value: "file:{hash}:{doc_id}:{auth}" |
| Permission::Prefix | `scope` (private use claim -80201) | Value: "prefix:{prefix}:{auth}" |
| Authorization | Part of scope | "r" for ReadOnly, "rw" for Full |
| user | `sub` (claim 2) | User identifier string |
| expiration_millis | `exp` (claim 4) | NumericDate (seconds since epoch) |
| key_id | `kid` (COSE header) | Key identifier in protected headers |

### 5. Prefix Token Validation
Implement prefix matching logic:

```rust
impl Authenticator {
    pub fn verify_doc_token_with_prefix(&self, token: &str, doc_id: &str, current_time: u64) -> Result<(Authorization, Option<String>), AuthError> {
        // Try direct doc token first
        if let Ok(auth) = self.verify_doc_token(token, doc_id, current_time) {
            return Ok((auth, self.extract_user_from_token(token)?));
        }
        
        // Try prefix tokens
        let payload = self.verify_token_auto(token, current_time)?;
        match payload.payload {
            Permission::Prefix(prefix_permission) => {
                if doc_id.starts_with(&prefix_permission.prefix) {
                    Ok((prefix_permission.authorization, prefix_permission.user))
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            _ => Err(AuthError::InvalidResource),
        }
    }
}
```

### 6. COSE Algorithm Support
Use `coset` crate with initial support for:
- **HMAC-SHA256**: Algorithm 5 (maps to existing relay server HMAC usage)
- **ES256** (ECDSA with P-256): Algorithm -7 (future support)
- **EdDSA** (Ed25519): Algorithm -8 (future support)

### 7. CWT Implementation with Coset
```rust
use coset::{CoseSign1Builder, CoseKey, Algorithm, Label};
use ciborium::{Value, cbor};

pub struct CwtAuthenticator {
    cose_key: CoseKey,
    key_id: Option<String>,
}

impl CwtAuthenticator {
    pub fn new(private_key: &[u8], key_id: Option<String>) -> Result<Self, AuthError> {
        let cose_key = CoseKey {
            kty: coset::KeyType::Assigned(coset::iana::KeyType::Symmetric),
            alg: Some(coset::Algorithm::Assigned(coset::iana::Algorithm::HMAC_256_256)),
            key_ops: Some(vec![coset::KeyOperation::Assigned(coset::iana::KeyOperation::Sign)]),
            k: Some(private_key.to_vec()),
            ..Default::default()
        };
        
        Ok(Self { cose_key, key_id })
    }
    
    pub fn create_cwt(&self, claims: CwtClaims) -> Result<Vec<u8>, AuthError> {
        let claims_map = self.build_claims_map(claims)?;
        let payload = ciborium::to_vec(&claims_map)?;
        
        let sign1 = CoseSign1Builder::new()
            .payload(payload)
            .protected(coset::HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::HMAC_256_256)
                .key_id(self.key_id.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default())
                .build())
            .create_signature(&[], |data| self.sign_with_key(data))
            .build();
            
        Ok(ciborium::to_vec(&sign1)?)
    }
    
    fn build_claims_map(&self, claims: CwtClaims) -> Result<Value, AuthError> {
        let mut map = std::collections::BTreeMap::new();
        
        // Standard claims
        if let Some(iss) = claims.issuer {
            map.insert(Value::Integer(1), Value::Text(iss));
        }
        if let Some(sub) = claims.subject {
            map.insert(Value::Integer(2), Value::Text(sub));
        }
        if let Some(aud) = claims.audience {
            map.insert(Value::Integer(3), Value::Text(aud));
        }
        if let Some(exp) = claims.expiration {
            map.insert(Value::Integer(4), Value::Integer(exp as i128));
        }
        if let Some(iat) = claims.issued_at {
            map.insert(Value::Integer(6), Value::Integer(iat as i128));
        }
        
        // Custom scope claim (private use claim -80201)
        map.insert(Value::Integer(-80201), Value::Text(claims.scope));
        
        Ok(Value::Map(map))
    }
}

#[derive(Debug)]
pub struct CwtClaims {
    pub issuer: Option<String>,
    pub subject: Option<String>,  // User identifier
    pub audience: Option<String>,
    pub expiration: Option<u64>,
    pub issued_at: Option<u64>,
    pub scope: String,            // Relay server permission scope
}
```

### 8. Authentication Flow Updates

#### Token Generation
```rust
impl Authenticator {
    // Existing methods with user parameter
    pub fn gen_doc_token_cwt(&self, doc_id: &str, auth: Authorization, exp: ExpirationTimeEpochMillis, user: Option<&str>) -> String;
    pub fn gen_file_token_cwt(&self, file_hash: &str, doc_id: &str, auth: Authorization, exp: ExpirationTimeEpochMillis, user: Option<&str>) -> String;
    
    // New prefix token generation
    pub fn gen_prefix_token_cwt(&self, prefix: &str, auth: Authorization, exp: ExpirationTimeEpochMillis, user: Option<&str>) -> String;
    pub fn gen_prefix_token(&self, prefix: &str, auth: Authorization, exp: ExpirationTimeEpochMillis, user: Option<&str>) -> String;
    
    pub fn server_token_cwt(&self) -> String;
}
```

#### Token Verification
```rust
impl Authenticator {
    pub fn verify_token_auto(&self, token: &str, current_time: u64) -> Result<Permission, AuthError>;
    pub fn extract_user_from_token(&self, token: &str) -> Result<Option<String>, AuthError>;
    
    // Enhanced verification methods that return user info
    pub fn verify_doc_token_with_user(&self, token: &str, doc_id: &str, current_time: u64) -> Result<(Authorization, Option<String>), AuthError>;
    pub fn verify_file_token_with_user(&self, token: &str, file_hash: &str, current_time: u64) -> Result<(Authorization, Option<String>), AuthError>;
}
```

### 9. Configuration
Add configuration options:
```rust
pub struct AuthConfig {
    pub token_format: TokenFormat,        // Default format for new tokens
    pub accept_legacy_tokens: bool,       // Accept old format tokens
    pub cwt_algorithm: CoseAlgorithm,     // Algorithm for CWT signing
    pub enable_prefix_tokens: bool,       // Enable prefix token support
    pub require_user_claims: bool,        // Require user claims in tokens
}
```

### 10. Migration Strategy
1. **Phase 1**: Add CWT support with user/prefix features, keep custom format as default
2. **Phase 2**: Add configuration to generate CWT tokens
3. **Phase 3**: Switch default to CWT, maintain custom token verification
4. **Phase 4**: Deprecate custom format (with long grace period)

## Implementation Details

### CWT Token Structure
```cbor
{
  1: "relay-server",               // iss: Issuer
  2: "user123",                    // sub: User identifier (NEW)
  3: "https://server.example.com", // aud: Audience (optional)
  4: 1444064944,                   // exp: Expiration (seconds)
  6: 1443944944,                   // iat: Issued At (seconds)
  -80201: "prefix:org123-:rw"     // scope: Custom claim for permissions (NEW: prefix support)
}
```

### Prefix Token Examples
- `"prefix:org123-:rw"` - Full access to any doc starting with "org123-"
- `"prefix:user456-personal-:r"` - Read-only access to docs starting with "user456-personal-"
- `"prefix::rw"` - Empty prefix (server-like access, but with user identification)

### Error Handling
Extend `AuthError` enum:
```rust
pub enum AuthError {
    // Existing errors...
    #[error("Invalid CBOR structure")]
    InvalidCbor,
    #[error("Invalid COSE structure")]
    InvalidCose,
    #[error("Unsupported COSE algorithm")]
    UnsupportedAlgorithm,
    #[error("Invalid CWT claims")]
    InvalidClaims,
    #[error("Prefix token does not match document ID")]
    PrefixMismatch,
    #[error("User claim missing but required")]
    MissingUser,
}
```

### Dependencies
- `coset`: COSE (CBOR Object Signing and Encryption) implementation
- `ciborium`: CBOR encoding/decoding
- `base64`: For token string encoding
- Existing crypto dependencies for key management

## Security Considerations

1. **Prefix Validation**: Strict validation of prefix patterns to prevent overly broad access
2. **User Claims**: Optional but trackable user identification
3. **Algorithm Security**: Use secure HMAC-SHA256 initially, with path to stronger algorithms
4. **Scope Validation**: Strict parsing and validation of scope claims
5. **COSE Security**: Leverage coset's COSE implementation security
6. **Backward Compatibility**: Existing tokens continue to work

## Use Cases

### Prefix Tokens
1. **Organization Access**: `org123-` prefix allows access to all org documents
2. **User Namespaces**: `user456-` prefix for personal document access
3. **Project Spaces**: `project-alpha-` prefix for project-specific access
4. **Multi-tenant**: Different prefixes for different tenants

### User Claims
1. **Audit Logging**: Track which user performed actions
2. **User-specific Logic**: Apply user-based permissions or features
3. **Analytics**: User-based usage tracking
4. **Compliance**: User identification for regulatory requirements

## Performance Impact

- **Token Generation**: Slightly slower due to CBOR/COSE encoding overhead
- **Token Verification**: Comparable to current implementation
- **Memory**: Minimal additional memory for CBOR structures and prefix matching

## Testing Requirements

1. **Unit Tests**:
   - CWT creation and validation with coset
   - CBOR encoding/decoding correctness
   - Prefix token generation and validation
   - Prefix matching logic (positive and negative cases)
   - User claim extraction

2. **Integration Tests**:
   - Token compatibility across services
   - Prefix token access control
   - Migration scenarios with mixed token types
   - COSE signature verification

3. **Security Tests**:
   - Prefix bypass attempts
   - Invalid user claim handling
   - COSE signature tampering
   - Token format confusion attacks

## Benefits

1. **Standards Compliance**: RFC 8392 compliant tokens using proven COSE library
2. **User Tracking**: Built-in user identification
3. **Flexible Access**: Prefix-based namespace access
4. **Security**: Leverage coset's robust COSE implementation
5. **Future Proof**: Easy migration to stronger crypto algorithms

## Example API Usage

```rust
// Generate prefix token for organization
let org_token = authenticator.gen_prefix_token_cwt(
    "org123-", 
    Authorization::Full, 
    exp_time,
    Some("admin@org123.com")
);

// Verify access to org document
let (auth, user) = authenticator.verify_doc_token_with_user(
    &org_token, 
    "org123-project-alpha-doc456", 
    current_time
)?;
// Returns: (Authorization::Full, Some("admin@org123.com"))

// Generate user-specific prefix token
let user_token = authenticator.gen_prefix_token_cwt(
    "user456-", 
    Authorization::ReadOnly, 
    exp_time,
    Some("user456")
);
```

## Success Metrics

1. All existing tests pass with CWT tokens
2. Prefix tokens correctly control document access
3. User claims are properly extracted and tracked
4. Successful COSE signature verification with coset