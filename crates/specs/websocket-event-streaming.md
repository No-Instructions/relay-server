# Architecture Change Request: WebSocket Event Streaming for Webhook Events

## Problem Statement

Currently, webhook events in Y-Sweet are delivered via HTTP callbacks only. This creates limitations for real-time applications that need:

- **Low-latency event delivery** without polling or HTTP long-polling complexity
- **Persistent connection efficiency** for applications with high event frequency  
- **Prefix-scoped event streaming** where clients should only receive events for documents they have access to
- **Simplified client implementation** that doesn't require webhook endpoint setup and management

The existing webhook system provides robust HTTP delivery with prefix-based routing, debouncing, and metrics, but lacks a real-time streaming option for applications that can maintain persistent connections.

## Proposed Architecture Change

### Core Concept
Add a **WebSocket event streaming endpoint** that integrates with the existing webhook infrastructure by temporarily registering prefixes from active WebSocket connections. The system will:

1. **Reuse existing webhook prefix matching logic** - WebSocket connections temporarily register their prefix in the webhook system
2. **Use prefix tokens as the sole authorization mechanism** - Only prefix tokens supported, no server tokens
3. **Temporary prefix registration** - Active WebSocket connections add their prefix to the webhook dispatcher's active prefix list
4. **Unified event routing** - Document updates trigger events for ALL matching prefixes (both HTTP webhook configs AND temporarily registered WebSocket prefixes)

### Authentication Model
- **Prefix Tokens Only**: Only `Permission::Prefix(PrefixPermission)` tokens are supported
- **Automatic Prefix Registration**: Connecting with a prefix token temporarily registers that prefix in the webhook system
- **Token-as-Source-of-Truth**: No client subscription management - the token defines the prefix scope

### Temporary Prefix Integration
When a WebSocket client connects with a `user_alice_` prefix token:
1. The prefix `user_alice_` is temporarily added to the webhook system's active prefixes
2. Document updates matching `user_alice_*` now trigger events for ALL matching prefixes:
   - Configured HTTP webhooks (from `.config/webhooks.json`)
   - The connected WebSocket client(s)
   - Any other WebSocket clients with overlapping prefixes (e.g., `user_` prefix would also match)
3. When the WebSocket disconnects, the temporary prefix is removed

## Implementation Changes

### 1. Enhanced Webhook Dispatcher

#### Extend `WebhookDispatcher` for Temporary Prefixes
```rust
// In crates/y-sweet-core/src/webhook.rs

pub struct WebhookDispatcher {
    pub configs: Vec<WebhookConfig>, // Persistent config from file
    queues: HashMap<String, mpsc::UnboundedSender<String>>,
    shutdown_senders: Vec<mpsc::UnboundedSender<()>>,
    
    // NEW: Temporary prefix registrations from WebSocket connections
    temporary_prefixes: Arc<RwLock<HashMap<String, Vec<WebSocketConnection>>>>, // prefix -> list of connections
    
    metrics: Arc<WebhookMetrics>,
}

#[derive(Clone)]
struct WebSocketConnection {
    connection_id: String,
    sender: mpsc::UnboundedSender<ServerMessage>,
    authorization: Authorization,
}
```

#### Enhanced Prefix Matching (All Matching Prefixes)
```rust
impl WebhookDispatcher {
    pub fn find_matching_prefixes(&self, doc_id: &str) -> Vec<String> {
        let mut matches: Vec<String> = Vec::new();
        
        // Existing logic: check persistent config prefixes
        matches.extend(
            self.configs
                .iter()
                .filter(|config| doc_id.starts_with(&config.prefix))
                .map(|config| config.prefix.clone())
        );
        
        // NEW: check temporary WebSocket prefixes  
        let temp_guard = self.temporary_prefixes.read().unwrap();
        matches.extend(
            temp_guard
                .keys()
                .filter(|prefix| doc_id.starts_with(*prefix))
                .cloned()
        );
        
        // Remove duplicates and sort by prefix length (longest first) for consistent ordering
        matches.sort_by(|a, b| b.len().cmp(&a.len()));
        matches.dedup();
        matches
    }
    
    // NEW: Register temporary WebSocket prefix
    pub fn register_websocket_prefix(
        &self,
        prefix: String,
        connection_id: String,
        sender: mpsc::UnboundedSender<ServerMessage>,
        authorization: Authorization,
    ) {
        let mut temp_guard = self.temporary_prefixes.write().unwrap();
        let connections = temp_guard.entry(prefix.clone()).or_insert_with(Vec::new);
        connections.push(WebSocketConnection {
            connection_id: connection_id.clone(),
            sender,
            authorization,
        });
        
        // Update metrics
        self.metrics.set_websocket_connections(&prefix, connections.len());
    }
    
    // NEW: Unregister specific WebSocket connection
    pub fn unregister_websocket_connection(&self, prefix: &str, connection_id: &str) {
        let mut temp_guard = self.temporary_prefixes.write().unwrap();
        if let Some(connections) = temp_guard.get_mut(prefix) {
            connections.retain(|conn| conn.connection_id != connection_id);
            
            // Remove empty prefix entries
            if connections.is_empty() {
                temp_guard.remove(prefix);
                self.metrics.set_websocket_connections(prefix, 0);
            } else {
                self.metrics.set_websocket_connections(prefix, connections.len());
            }
        }
    }
}
```

#### Enhanced Event Broadcasting (All Matching Prefixes)
```rust
impl WebhookDispatcher {
    pub fn send_webhooks(&self, doc_id: String) {
        let matching_prefixes = self.find_matching_prefixes(&doc_id);
        
        for prefix in matching_prefixes {
            // Send to HTTP webhook queues (existing logic)
            if let Some(sender) = self.queues.get(&prefix) {
                if let Err(e) = sender.send(doc_id.clone()) {
                    error!("Failed to queue webhook for prefix '{}': {}", prefix, e);
                }
            }
            
            // NEW: Send to ALL WebSocket connections for this prefix
            let temp_guard = self.temporary_prefixes.read().unwrap();
            if let Some(connections) = temp_guard.get(&prefix) {
                let event = WebSocketEvent {
                    event_type: "document.updated".to_string(),
                    event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
                    doc_id: doc_id.clone(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    payload: serde_json::json!({
                        "doc_id": doc_id.clone(),
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    }),
                };
                
                let message = ServerMessage::Event(event);
                
                // Send to all connections for this prefix
                for conn in connections {
                    if let Err(e) = conn.sender.send(message.clone()) {
                        error!("Failed to send WebSocket event for prefix '{}' to connection '{}': {}", 
                               prefix, conn.connection_id, e);
                    }
                }
            }
        }
    }
}
```

### 2. WebSocket Event Types

#### Event Message Structure
```rust
// In crates/y-sweet-core/src/webhook.rs

#[derive(Serialize, Debug, Clone)]
pub struct WebSocketEvent {
    pub event_type: String, // "document.updated"
    pub event_id: String,
    pub doc_id: String,
    pub timestamp: String,
    pub payload: serde_json::Value,
}

#[derive(Serialize, Debug, Clone)]
pub enum ServerMessage {
    Connected { 
        prefix: String,
        level: Authorization,
    },
    Event(WebSocketEvent),
    Pong,
    Error { message: String },
}
```

### 3. WebSocket Endpoint

#### New Route: `/events/ws`
```rust
// In crates/y-sweet/src/server.rs - add to routes()
.route("/events/ws", get(handle_event_websocket_upgrade))
```

#### Prefix Token Authentication
```rust
async fn handle_event_websocket_upgrade(
    ws: WebSocketUpgrade,
    Query(params): Query<HandlerParams>, // token from query params
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = params.token.as_deref() {
            let payload = authenticator
                .decode_token(token)
                .map_err(|_| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token")))?;
                
            match payload.payload {
                Permission::Prefix(prefix_perm) => {
                    return Ok(ws.on_upgrade(move |socket| {
                        handle_prefix_event_stream(socket, server_state, prefix_perm)
                    }));
                }
                _ => return Err(AppError(StatusCode::FORBIDDEN, anyhow!("Only prefix tokens supported for event streaming"))),
            }
        } else {
            return Err(AppError(StatusCode::UNAUTHORIZED, anyhow!("No token provided")));
        }
    } else {
        return Err(AppError(StatusCode::UNAUTHORIZED, anyhow!("Authentication required")));
    }
}
```

#### WebSocket Connection Handler
```rust
async fn handle_prefix_event_stream(
    socket: WebSocket,
    server_state: Arc<Server>,
    prefix_perm: PrefixPermission,
) {
    let conn_id = nanoid::nanoid!();
    let (mut sink, mut stream) = socket.split();
    let (send, mut recv) = mpsc::unbounded_channel();
    
    // Register temporary prefix in webhook dispatcher
    if let Some(webhook_queue) = server_state.webhook_queue.read().unwrap().as_ref() {
        webhook_queue.dispatcher.register_websocket_prefix(
            prefix_perm.prefix.clone(),
            conn_id.clone(),
            send.clone(),
            prefix_perm.level,
        );
    }
    
    // Send welcome message
    let welcome = ServerMessage::Connected { 
        prefix: prefix_perm.prefix.clone(),
        level: prefix_perm.level,
    };
    if send.send(welcome).is_err() {
        return; // Connection closed immediately
    }
    
    // Handle outgoing messages (events)
    let outgoing_task = tokio::spawn(async move {
        while let Some(msg) = recv.recv().await {
            let json = serde_json::to_string(&msg).unwrap();
            if sink.send(Message::Text(json)).await.is_err() {
                break; // Connection closed
            }
        }
    });
    
    // Handle incoming messages (ping only)
    let prefix_for_cleanup = prefix_perm.prefix.clone();
    let conn_id_for_cleanup = conn_id.clone();
    let server_for_cleanup = server_state.clone();
    let incoming_task = tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    if text.trim() == "ping" {
                        if send.send(ServerMessage::Pong).is_err() {
                            break;
                        }
                    }
                    // Ignore all other messages
                }
                Ok(Message::Close(_)) => break,
                _ => continue,
            }
        }
    });
    
    // Wait for connection to close
    tokio::select! {
        _ = outgoing_task => {},
        _ = incoming_task => {},
    }
    
    // Cleanup: unregister this specific connection
    if let Some(webhook_queue) = server_state.webhook_queue.read().unwrap().as_ref() {
        webhook_queue.dispatcher.unregister_websocket_connection(&prefix_perm.prefix, &conn_id);
    }
}
```

### 4. Integration with Existing Systems

#### No Changes Required to Webhook Callback
The existing webhook callback in `Server::load_doc()` already calls `dispatcher.send_webhooks(doc_id)`, which will now automatically handle both HTTP webhooks and WebSocket events through the enhanced `find_matching_prefixes()` logic that includes temporary WebSocket prefixes.

#### Enhanced Metrics
```rust
// Add to WebhookMetrics
impl WebhookMetrics {
    pub fn set_websocket_connections(&self, prefix: &str, count: usize) {
        // Track active WebSocket connections per prefix
    }
}
```

## Implementation Steps

### Phase 1: Enhance Webhook Dispatcher
1. Add `temporary_prefixes` field to `WebhookDispatcher` as `HashMap<String, Vec<WebSocketConnection>>`
2. Create `WebSocketConnection` struct 
3. Implement `register_websocket_prefix()` and `unregister_websocket_connection()` methods
4. Enhance `find_matching_prefixes()` to include temporary prefixes with deduplication
5. Update `send_webhooks()` to send events to ALL WebSocket connections for matching prefixes

### Phase 2: WebSocket Event Types
1. Create `WebSocketEvent` and `ServerMessage` types
2. Add serialization support
3. Define simple message protocol (ping/pong only)

### Phase 3: WebSocket Endpoint
1. Add `/events/ws` route to server
2. Implement `handle_event_websocket_upgrade()` with prefix token validation
3. Create `handle_prefix_event_stream()` connection handler
4. Implement automatic prefix registration and connection-specific unregistration

### Phase 4: Testing and Integration
1. Add unit tests for enhanced webhook dispatcher with multiple connections per prefix
2. Test temporary prefix registration and cleanup for individual connections
3. Verify WebSocket event delivery to ALL matching connections alongside HTTP webhooks
4. Test connection lifecycle and error handling
5. Test scenarios with overlapping prefixes (e.g., `user_` and `user_admin_` both receiving events for `user_admin_123`)

## Security Considerations

### Authentication
- **Prefix Tokens Only**: Only prefix tokens are accepted, no server token access
- **Scope Enforcement**: WebSocket events are filtered by token prefix scope
- **Token Expiration**: Connections close when tokens expire

### Connection Management  
- **Automatic Cleanup**: Temporary prefixes are cleaned up when specific connections close
- **Multiple Connections**: Support multiple WebSocket connections per prefix
- **Resource Limits**: Consider connection limits per prefix to prevent abuse

### Input Validation
- **Minimal Protocol**: Only ping/pong messages accepted from client
- **No Client Control**: Clients cannot modify their prefix scope or subscription

## Dependencies

### Required Changes
- **Minimal changes** to existing `WebhookDispatcher` structure
- **No breaking changes** to HTTP webhook functionality  
- **Reuse of existing** authentication and routing logic

### Optional Enhancements
- Add WebSocket-specific metrics to `WebhookMetrics`
- Add configurable connection limits per prefix
- Add connection health monitoring and heartbeat

## API Specification

### WebSocket Endpoint
```
GET /events/ws?token=<prefix_token>
Upgrade: websocket
```

### Connection Flow
1. **Connect**: Client connects with prefix token in query parameter
2. **Registration**: Server temporarily registers the token's prefix in webhook system
3. **Welcome**: Server sends `Connected` message with prefix and authorization level
4. **Events**: Server automatically streams document events matching the prefix (alongside any other matching prefixes)
5. **Heartbeat**: Client can send `ping`, server responds with `Pong`
6. **Disconnect**: Connection closes, this specific connection is removed from the temporary prefix list

### Example Messages
```javascript
// Server -> Client on connection
{"Connected": {"prefix": "user_alice_", "level": "ReadOnly"}}

// Server -> Client on document event  
{"Event": {
  "event_type": "document.updated",
  "event_id": "evt_abc123",
  "doc_id": "user_alice_document_456", 
  "timestamp": "2024-01-01T12:00:00Z",
  "payload": {"doc_id": "user_alice_document_456", "timestamp": "2024-01-01T12:00:00Z"}
}}

// Client -> Server (ping)
"ping"

// Server -> Client (pong)  
{"Pong": null}
```

## Example Scenarios

### Multiple WebSocket Clients
If these connections are active:
- WebSocket client A: `user_` prefix token
- WebSocket client B: `user_alice_` prefix token  
- HTTP webhook: configured for `user_admin_` prefix

When document `user_alice_document_123` is updated:
- **WebSocket client A** receives the event (matches `user_` prefix)
- **WebSocket client B** receives the event (matches `user_alice_` prefix)
- **HTTP webhook** does NOT receive the event (doesn't match `user_admin_` prefix)

When document `user_admin_document_456` is updated:
- **WebSocket client A** receives the event (matches `user_` prefix)
- **WebSocket client B** does NOT receive the event (doesn't match `user_alice_` prefix)
- **HTTP webhook** receives the event (matches `user_admin_` prefix)

## Benefits

### Unified Event System
- **Single Event Source**: Both HTTP and WebSocket events use the same webhook callback mechanism
- **Consistent Prefix Matching**: WebSocket events use the same prefix matching logic as HTTP webhooks, including ALL matching prefixes
- **No Code Duplication**: Reuses existing webhook infrastructure

### Real-Time Capabilities
- **Low Latency**: Direct WebSocket delivery without HTTP overhead
- **Persistent Connections**: Efficient for high-frequency event scenarios
- **Automatic Filtering**: Events are automatically filtered by prefix scope
- **Multiple Subscribers**: Multiple WebSocket clients can subscribe to overlapping prefixes

### Operational Simplicity
- **No Client Configuration**: Token defines complete event scope
- **Automatic Cleanup**: Individual connections are cleaned up on disconnect
- **Backward Compatible**: Existing HTTP webhook system unchanged