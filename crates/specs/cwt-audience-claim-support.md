# Architecture Change Request: CWT Audience Claim Verification & URL Field Rename

## Summary

1. **Rename `url_prefix` → `url`** for clearer configuration semantics
2. **Add automatic CWT audience claim verification** using the service URL as the expected audience

## Background

Y-Sweet currently implements CWT authentication with support for standard RFC 8392 claims, including the `aud` (audience) claim in the token structure. However, there are two issues:

1. **Missing audience verification**: The audience claim is parsed but never validated during token verification
2. **Confusing naming**: The `url_prefix` field name doesn't clearly indicate it's the service's public URL

### Current Implementation
- `CwtClaims` struct supports `audience: Option<String>` (claim 3)
- `server.url_prefix` is used for URL generation and allowed hosts
- No validation occurs between token audience and service configuration
- The field name `url_prefix` suggests it's just a prefix, not the full service URL

## Proposed Changes

### 1. Field Rename: `url_prefix` → `url`

**Configuration schema change:**
```toml
[server]
url = "https://api.example.com"  # Was: url_prefix
host = "0.0.0.0"
port = 8080
```

**Rationale:**
- `url` clearly indicates this is the service's public URL
- Simpler and more intuitive than `url_prefix`
- Aligns with common configuration patterns

### 2. Automatic Audience Claim Verification

When `server.url` is configured, automatically use it as the expected audience for CWT validation:

```rust
// During CWT verification
if let Some(service_url) = &config.server.url {
    match &claims.audience {
        Some(token_audience) if token_audience == service_url => {
            // Valid - token intended for this service
        }
        Some(token_audience) => {
            return Err(CwtError::InvalidAudience {
                expected: service_url.clone(),
                found: token_audience.clone(),
            });
        }
        None => {
            return Err(CwtError::MissingAudience {
                expected: service_url.clone(),
            });
        }
    }
}
// If server.url is not configured, skip audience validation (backward compatible)
```

## Implementation Details

### Files to Modify

1. **`y-sweet-core/src/config.rs`**:
   ```rust
   pub struct ServerConfig {
       pub url: Option<String>,  // Was: url_prefix
       // ... other fields
   }
   ```

2. **`y-sweet-core/src/cwt.rs`**:
   - Add new error variants for audience validation
   - Modify `verify_cwt()` methods to accept expected audience
   - Implement audience validation logic

3. **`y-sweet-core/src/auth.rs`**:
   - Update authentication functions to pass service URL to CWT verification

4. **`y-sweet/src/server.rs`**:
   - Update all references from `url_prefix` to `url`
   - Pass service URL to authentication layer

5. **`y-sweet/src/main.rs`**:
   - Update CLI parameter from `url_prefix` to `url`
   - Update configuration loading and validation

### New Error Types

```rust
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CwtError {
    // ... existing variants ...
    
    #[error("Invalid audience claim: expected '{expected}', found '{found}'")]
    InvalidAudience { expected: String, found: String },
    
    #[error("Missing audience claim: expected '{expected}'")]
    MissingAudience { expected: String },
}
```

### Environment Variables

No changes to environment variable names:
```bash
RELAY_SERVER_URL="https://api.example.com"  # Same as before
```

## Benefits

### Security Enhancements
- **Token scoping**: Prevents tokens intended for other services from being accepted
- **Automatic protection**: No additional configuration required beyond setting service URL
- **RFC 8392 compliance**: Proper validation of standard audience claim

### Usability Improvements
- **Clearer configuration**: `url` is more intuitive than `url_prefix`
- **Zero additional config**: Audience validation works automatically when service URL is set
- **Consistent behavior**: Same URL used for both URL generation and security validation

### Backward Compatibility
- **Graceful fallback**: If no service URL is configured, audience validation is skipped
- **Environment variables unchanged**: `RELAY_SERVER_URL` continues to work
- **Migration path**: Existing deployments can update TOML field name when convenient

## Example Configurations

### Before (Current)
```toml
[server]
url_prefix = "https://api.example.com"
```

### After (Proposed)
```toml
[server]
url = "https://api.example.com"  # Simpler name, same functionality + automatic audience validation
```

### Environment Variable (Unchanged)
```bash
export RELAY_SERVER_URL="https://api.example.com"
```

## Migration Strategy

### Phase 1: Implementation
1. Add new `url` field alongside existing `url_prefix` field
2. Implement audience validation using the `url` field
3. Add deprecation warnings for `url_prefix` usage

### Phase 2: Migration Period
1. Support both `url` and `url_prefix` fields (with `url` taking precedence)
2. Update documentation to use `url`
3. Add logging when deprecated `url_prefix` is used

### Phase 3: Cleanup (Future Release)
1. Remove support for `url_prefix` field
2. Make `url` the canonical field name

## Security Considerations

### Threat Model
- **Cross-service token reuse**: Tokens intended for `service-a.example.com` cannot be used on `service-b.example.com`
- **Environment isolation**: Tokens for `api.staging.example.com` cannot be used on `api.prod.example.com`
- **Lateral movement**: Compromised tokens have limited scope to their intended service

### Best Practices
- Service URLs should be specific: `https://api.relay.example.com` vs `https://example.com`
- Different environments should use different URLs
- Audience claims should be included in all production tokens

### Risk Assessment
- **Low risk**: Change is additive and backward-compatible
- **High value**: Significant security improvement with minimal configuration burden
- **Easy rollback**: Can disable by removing service URL configuration

## Testing Strategy

### Unit Tests
- Field rename functionality and backward compatibility
- Audience validation with various scenarios (valid, invalid, missing)
- Error handling and message clarity

### Integration Tests
- End-to-end token verification with audience claims
- Configuration loading with both old and new field names
- Environment variable override behavior

### Security Tests
- Cross-service token rejection
- Missing audience claim handling
- Invalid audience claim rejection

This change provides a significant security enhancement while simplifying configuration and maintaining full backward compatibility.