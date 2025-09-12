# Architecture Change Request: Event Delivery via Document Sync Protocol

## Problem Statement

Currently, Y-Sweet provides two separate WebSocket protocols:
1. **Document Sync Protocol** (`/d/{doc_id}/ws/{doc_id}`): Binary Yjs protocol for real-time document collaboration
2. **Event Streaming Protocol** (`/e/{prefix}/ws`): JSON-based protocol for webhook-style event notifications

This separation creates several challenges:
- **Multiple connections**: Clients need two WebSocket connections for full functionality
- **Inconsistent formats**: Binary vs JSON creates complexity in client implementations
- **Separate authentication**: Different token types and validation paths
- **Network overhead**: Maintaining two persistent connections per client

## Proposed Architecture Change

### Core Concept

Extend the existing Yjs document sync protocol to support event delivery using CBOR serialization. Events will be delivered through the same WebSocket connection used for document synchronization, with the channel/prefix determined by the document connection itself.

### Protocol Extensions

#### New Message Types

Add three new message types to the sync protocol:

```rust
pub const MSG_EVENT: u8 = 4;           // Server->Client: Event delivery
pub const MSG_EVENT_SUBSCRIBE: u8 = 5;  // Client->Server: Subscribe to event types
pub const MSG_EVENT_UNSUBSCRIBE: u8 = 6; // Client->Server: Unsubscribe from event types
```

#### Message Definitions

```rust
#[derive(Debug, Eq, PartialEq)]
pub enum Message {
    // Existing messages
    Sync(SyncMessage),
    Auth(Option<String>),
    AwarenessQuery,
    Awareness(AwarenessUpdate),
    
    // New event messages
    Event(Vec<u8>),                    // CBOR-encoded EventMessage
    EventSubscribe(Vec<String>),       // List of event types to subscribe to
    EventUnsubscribe(Vec<String>),     // List of event types to unsubscribe from
    
    Custom(u8, Vec<u8>),
}
```

#### Event Message Structure

Events are serialized as CBOR with string keys for simplicity and forward compatibility:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMessage {
    pub event_id: String,      // Unique event identifier
    pub event_type: String,    // e.g., "document.updated", "file.uploaded"
    pub doc_id: String,        // Document that triggered the event
    pub timestamp: u64,        // Unix timestamp in milliseconds
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,  // User who triggered the event
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>, // Event-specific metadata
}
```

### Security Model

#### Channel Determination

The event channel/prefix is **determined by the document connection**, not by client subscription:
- Document tokens include channel information in their claims
- The channel defaults to the document ID if not specified
- Clients cannot subscribe to events outside their authorized channel

#### Event Type Filtering

Clients can select which **event types** they want to receive:
- Clients send `EventSubscribe` messages with a list of event type strings
- Only events matching both the channel AND subscribed types are delivered
- Reduces bandwidth by filtering unwanted event types client-side

### Implementation Details

#### Server-Side Changes

1. **Extend sync protocol handlers** in `y-sweet-core/src/sync/mod.rs`:
   - Add `Message::Event`, `Message::EventSubscribe`, `Message::EventUnsubscribe` variants
   - Implement CBOR encoding/decoding for event messages

2. **Update WebSocket handler** in `y-sweet/src/server.rs`:
   - Track event type subscriptions per connection
   - Filter events based on channel and subscribed types
   - Convert `EventEnvelope` to CBOR `EventMessage` for delivery

3. **Integrate with event dispatcher**:
   - Register sync protocol connections with the event system
   - Route events through existing `UnifiedEventDispatcher`
   - Maintain compatibility with HTTP webhook delivery

#### Client-Side Requirements

Clients need to:
1. Send `EventSubscribe` messages to opt into event delivery
2. Handle incoming `Event` messages containing CBOR data
3. Decode CBOR event payloads using appropriate libraries

#### Wire Format

Event subscription message:
```
[MSG_EVENT_SUBSCRIBE] [count] [type1] [type2] ...
```

Event delivery message:
```
[MSG_EVENT] [cbor_data_length] [cbor_data]
```

Where `cbor_data` deserializes to:
```json
{
  "event_id": "evt_abc123def456",
  "event_type": "document.updated",
  "doc_id": "user_alice_doc_123",
  "timestamp": 1704067200000,
  "user": "alice@example.com",
  "metadata": { "version": 2 }
}
```

### Supported Event Types

Currently implemented event types:
- `document.updated` - Document content changed

**Note**: Other event types like `user.joined`, `user.left`, `file.uploaded`, `file.deleted`, `awareness.changed`, `document.saved`, and `metadata.changed` are potential future additions but are not currently implemented. Only `document.updated` events are supported in this initial implementation.

Additional event types can be added as strings without protocol changes when implemented.

## Benefits

### Unified Protocol
- Single WebSocket connection for both document sync and events
- Consistent binary protocol using existing Yjs encoding
- Simplified client implementation

### Efficient Delivery
- CBOR encoding is more compact than JSON
- Events share the existing connection and authentication
- Client-controlled filtering reduces unnecessary traffic

### Security
- Channel/prefix determined by server based on authentication
- No privilege escalation possible through subscriptions
- Consistent authorization model with document access

### Forward Compatibility
- CBOR naturally handles unknown fields
- Event types are strings, allowing easy extension
- Optional dictionary compression can be added later

## Migration Path

### Phase 1: Protocol Implementation
- Add new message types to sync protocol
- Implement CBOR serialization for events
- Update server-side message handlers

### Phase 2: Event Routing
- Integrate with existing event dispatcher
- Add subscription tracking per connection
- Implement channel-based filtering

### Phase 3: Client Support
- Update client libraries to handle new message types
- Add event subscription APIs
- Provide CBOR decoding utilities

### Backwards Compatibility

- Existing clients that don't send `EventSubscribe` messages won't receive events
- The separate event streaming endpoint (`/e/{prefix}/ws`) remains available
- HTTP webhooks continue to work unchanged

## Testing Strategy

### Unit Tests
- CBOR serialization/deserialization of event messages
- Message encoding/decoding in sync protocol
- Event filtering by channel and type

### Integration Tests
- Event delivery through document sync connection
- Multiple clients with different subscriptions
- Channel isolation between documents

### End-to-End Tests
- Real document updates triggering events
- Event delivery latency measurements
- Connection failure and recovery scenarios

## Documentation Requirements

### Protocol Specification
- Update Yjs sync protocol documentation with new message types
- Document CBOR event message schema
- Provide examples of event subscription and handling

### Client Library Updates
- Add event subscription methods to client SDKs
- Provide CBOR decoding examples
- Document event type constants

### Migration Guide
- Instructions for transitioning from separate event endpoint
- Code examples for updating client applications
- Performance comparison with previous approach