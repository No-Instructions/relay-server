# CWT Channel Claims

## Executive Summary

This document proposes adding a channel claim to CWT (CBOR Web Token) tokens to enable flexible event routing. This builds on the Event Envelope Architecture to allow document and file tokens to specify custom channels for event routing. The channel is stored in document metadata to ensure consistent routing regardless of which token is used to connect.

## Prerequisites

This specification assumes the Event Envelope Architecture has been implemented, providing:
- `EventEnvelope` with `channel` field for routing
- `DocumentUpdatedEvent` as business data payload
- Separation of routing logic from business logic

## Background

### Current Routing Behavior

Currently, events are routed based on the document ID:
- Document `user_alice_doc` routes to prefixes that match `user_`
- Document `admin_settings` routes to prefixes that match `admin_`

### Limitation

This tight coupling between document ID and routing prevents flexible event distribution scenarios like:
- All team documents routing to a shared `team-updates` channel
- Cross-cutting concerns like audit logging to dedicated channels
- Multi-tenant routing based on organization rather than document prefix

## Proposed Solution

### CWT Channel Claim

Add a channel claim (10) to CWT document and file tokens only (not prefix or server tokens):

```rust
// cwt.rs
#[derive(Debug, PartialEq)]
pub struct CwtClaims {
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Option<String>,
    pub expiration: Option<u64>,
    pub issued_at: Option<u64>,
    pub scope: String,           // Claim 9: Permission
    pub channel: Option<String>,  // Claim 10: Channel (NEW)
}

impl CwtAuthenticator {
    fn build_claims_map(&self, claims: CwtClaims) -> Result<ciborium::Value, CwtError> {
        let mut map = Vec::new();
        
        // ... existing standard claims (1-6) ...
        
        // Custom scope claim (9)
        map.push((
            ciborium::Value::Integer(9.into()),
            ciborium::Value::Text(claims.scope),
        ));
        
        // Custom channel claim (10) - NEW
        if let Some(channel) = claims.channel {
            map.push((
                ciborium::Value::Integer(10.into()),
                ciborium::Value::Text(channel),
            ));
        }
        
        Ok(ciborium::Value::Map(map))
    }
    
    fn parse_claims_map(&self, claims_map: ciborium::Value) -> Result<CwtClaims, CwtError> {
        // ... existing parsing ...
        let mut channel = None;
        
        for (key, value) in map {
            match (key, value) {
                (ciborium::Value::Integer(k), ciborium::Value::Text(s)) => {
                    match TryInto::<u64>::try_into(k) {
                        // ... existing claims ...
                        Ok(10) => channel = Some(s),  // NEW
                        _ => {}
                    }
                }
                // ... rest of parsing ...
            }
        }
        
        Ok(CwtClaims {
            // ... existing fields ...
            channel,
        })
    }
}
```

### Token Verification with Channel Extraction

Add new method to extract channel claims from CWT tokens:

```rust
// auth.rs - New method signature
impl Authenticator {
    /// Verify CWT token and extract channel claim
    pub fn verify_cwt_with_channel(&self, token: &str, current_time: u64) -> Result<(Permission, Option<String>), AuthError> {
        match detect_token_format(token) {
            TokenFormat::Custom => {
                let payload = self.verify(token, current_time)?;
                Ok((payload.payload, None)) // Custom tokens don't have channel claims
            }
            TokenFormat::Cwt => {
                let cwt_claims = self.verify_cwt_internal(token, current_time)?;
                let permission = scope_to_permission(&cwt_claims.scope)?;
                let channel = cwt_claims.channel;
                Ok((permission, channel))
            }
        }
    }
}
```

### Integration with Document Metadata and Event Generation

Store channel in document metadata and read from metadata for event routing:

```rust
// server.rs - Updated load_doc signature
pub async fn load_doc(&self, doc_id: &str, channel: Option<String>) -> Result<()> {
    // ... existing setup ...
    
    let dwskv = DocWithSyncKv::new(
        doc_id,
        self.store.clone(),
        // ... existing parameters
    ).await?;
    
    // If channel is provided in token, store it in document metadata
    if let Some(channel_name) = channel {
        dwskv.update_metadata("channel", &channel_name)?;
    }
    
    let event_callback = {
        let event_dispatcher = self.event_dispatcher.clone();
        let dwskv_for_callback = dwskv.clone();
        let doc_id_for_callback = doc_id.to_string();
        
        if let Some(dispatcher) = event_dispatcher {
            Some(Arc::new(move |event: DocumentUpdatedEvent| {
                // Read channel from document metadata for routing
                let routing_channel = dwskv_for_callback
                    .get_channel_metadata()
                    .unwrap_or_else(|| doc_id_for_callback.clone());
                
                // Create the envelope with routing channel from metadata
                let envelope = EventEnvelope::new(routing_channel, event);
                
                // Send via dispatcher
                dispatcher.send_event(envelope);
            }) as y_sweet_core::webhook::WebhookCallback)
        } else {
            None
        }
    };
    
    // ... rest of method ...
}
```

### Request Handler Integration

Extract channel during authentication and pass to document operations:

```rust
// server.rs - Updated request handlers
async fn handle_socket_upgrade(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    let token = params.token.as_deref();
    
    // Extract both authorization and channel from token
    let (authorization, channel) = if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token {
            let (permission, channel) = authenticator
                .verify_cwt_with_channel(token, current_time_epoch_millis())
                .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
            
            let authorization = match permission {
                Permission::Doc(doc_perm) => doc_perm.authorization,
                Permission::Server => Authorization::Full,
                // ... handle other permission types
            };
            
            (authorization, channel)
        } else {
            (Authorization::Full, None)
        }
    } else {
        (Authorization::Full, None)
    };

    // Load document with channel information (stores in metadata if provided)
    if !matches!(authorization, Authorization::Full) && !server_state.docs.contains_key(&doc_id) {
        return Err(AppError(StatusCode::NOT_FOUND, anyhow!("Doc {} not found", doc_id)));
    }

    // Pass channel to load_doc (will be stored in document metadata)
    let dwskv = server_state
        .get_or_create_doc(&doc_id, channel)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        
    // ... rest of handler
}
```

### Usage Examples

#### Example 1: Standard Document Update (No Channel Claim)
```rust
// Token has no channel claim (default behavior)
let token = authenticator.gen_doc_token_cwt(
    "user_alice_doc",
    Authorization::Full,
    expiration_time,
    Some("alice@example.com"),
    None  // No custom channel
);

// Verification returns no channel
let (permission, channel) = authenticator.verify_cwt_with_channel(&token, now)?;
// channel = None

// Document loads with doc_id as routing channel (current behavior)
server.load_doc("user_alice_doc", channel).await?;
// No channel stored in metadata, events route to "user_alice_doc"
```

#### Example 2: With Custom Channel from Token
```rust
// Token specifies custom channel
let token = authenticator.gen_doc_token_cwt(
    "user_alice_doc",
    Authorization::Full,
    expiration_time,
    Some("alice@example.com"),
    Some("team-updates".to_string())  // Custom channel
);

// Verification extracts channel claim
let (permission, channel) = authenticator.verify_cwt_with_channel(&token, now)?;
// channel = Some("team-updates")

// Document loads and stores channel in metadata
server.load_doc("user_alice_doc", channel).await?;
// "team-updates" stored in document metadata, all future events route to "team-updates"
```

### Backwards Compatibility

**Key Compatibility Requirements:**
- All existing CWT tokens will continue to work without the channel claim
- When a CWT token has no channel claim, the system falls back to using `doc_id` as the routing channel (exactly as it does today)  
- This ensures zero behavior change for existing tokens
- Only CWT document and file tokens support channel claims (custom format tokens and CWT prefix/server tokens continue to use doc_id routing)

### Security Considerations

1. **Channel Authorization**: Channel claims are protected within the signed CWT token, providing de facto permission to set the document's routing channel
2. **Scope Verification**: Channel claims do not bypass existing document/file scope restrictions
3. **Channel Validation**: Channel names must pass the same validation as document names (alphanumeric characters, hyphens, and underscores only)
4. **Token Scope**: Only document and file tokens can contain channel claims; prefix and server tokens cannot
5. **Metadata Persistence**: Channel is stored in document metadata, ensuring consistent routing regardless of subsequent connection tokens

### Testing Requirements

1. **Unit Tests**:
   - CWT channel claim parsing and serialization
   - Token verification with channel extraction
   - Fallback behavior when channel is unset

2. **Integration Tests**:
   - End-to-end routing with channel override
   - Backwards compatibility with existing tokens
   - Multiple documents with different channel overrides

## Token Generation API Updates

Add optional channel parameters to CWT token generation methods:

```rust
// Updated method signatures
impl Authenticator {
    pub fn gen_doc_token_cwt(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        user: Option<&str>,
        channel: Option<String>,  // NEW: Optional channel claim
    ) -> String
    
    pub fn gen_file_token_cwt(
        &self,
        file_hash: &str,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        content_type: Option<&str>,
        content_length: Option<u64>,
        user: Option<&str>,
        channel: Option<String>,  // NEW: Optional channel claim
    ) -> String
    
    // NO CHANGES to prefix or server token methods
    // NO CHANGES to any custom format token methods
}
```

### Channel Validation

Rename `validate_doc_name` to `validate_key` for generic use with documents and channels:

```rust
// api_types.rs
pub fn validate_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return false;
        }
    }
    true
}
```

## Implementation Plan

1. Rename `validate_doc_name` to `validate_key` and update all references
2. Add `channel` field to `CwtClaims` struct
3. Update CWT claim parsing/building to handle claim 10 with channel validation
4. Add optional `channel` parameter to `gen_doc_token_cwt` and `gen_file_token_cwt`
5. Add `verify_cwt_with_channel` method to Authenticator
6. Update `load_doc` to accept optional channel parameter and store in document metadata
7. Update event generation to read channel from document metadata for routing
8. Update WebSocket handlers to extract channel from CWT tokens
8. Add comprehensive tests for all scenarios

## Event Routing Scope

**Channel claims only affect event generation, not consumption:**
- Document/file tokens with channel claims set the document's routing channel in metadata
- Once set, all events from that document route to the specified channel regardless of connection token
- Event consumption via `/e/:prefix/ws` endpoints remains unchanged
- No channel claims are supported for event consumption tokens
- Multiple documents can have the same routing channel if their tokens specify it
- File tokens preserve channel claims for future file-related events (currently no file events exist)
- Channel persists in document metadata across server restarts and different user connections

## Conclusion

Adding channel claims to CWT document and file tokens provides a clean mechanism for flexible event routing without breaking existing functionality. Channel claims are completely optional and fall back to current behavior when not specified, ensuring seamless backwards compatibility. The feature is scoped specifically to document and file tokens, maintaining clear security boundaries while enabling powerful routing scenarios. By storing the channel in document metadata, routing remains consistent regardless of which tokens are used for subsequent connections.