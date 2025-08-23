# Event Envelope Architecture

## Executive Summary

This document proposes restructuring the Y-Sweet event system to cleanly separate the event envelope (routing metadata) from the event payload (business data). Events and envelopes are constructed explicitly and separately, maintaining clear architectural boundaries.

## Background

### Current Event Structure

The current Event struct (event.rs:14-19) conflates routing with business data:

```rust
pub struct Event {
    pub event_type: EventType,
    pub doc_id: String,      // Used for both routing AND business data
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_id: String,
}
```

## Problem Statement

1. **Conflated Concerns**: Routing logic is mixed with business data
2. **Inflexible Routing**: Cannot route events independently of their content
3. **Poor Extensibility**: Adding new event types requires modifying core routing logic

## Proposed Solution

### Core Architecture: Explicit Envelope and Payload Construction

Separate events into two distinct layers that are constructed independently:

1. **EventPayload**: Business data (what happened)
2. **EventEnvelope**: Routing metadata (where it goes)

### New Event Structure

```rust
// event.rs

/// Event payloads contain only business data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentUpdatedEvent {
    pub doc_id: String,
    pub user: Option<String>,
}

impl DocumentUpdatedEvent {
    /// Create a new document updated event payload
    pub fn new(doc_id: String) -> Self {
        Self {
            doc_id,
            user: None,
        }
    }
    
    /// Builder method to add user
    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }
    
    /// Get the event type identifier
    pub fn event_type() -> &'static str {
        "document.updated"
    }
}

/// The envelope contains only routing and transport metadata
#[derive(Clone, Debug, Serialize)]
pub struct EventEnvelope {
    #[serde(rename = "eventId")]
    pub event_id: String,
    
    #[serde(rename = "eventType")]
    pub event_type: String,
    
    pub channel: String,      // Routing channel
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    pub payload: serde_json::Value,  // Serialized payload
}

impl EventEnvelope {
    /// Create an envelope for a document updated event
    /// Channel and payload are provided separately
    pub fn new(channel: String, payload: DocumentUpdatedEvent) -> Self {
        Self {
            event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
            event_type: DocumentUpdatedEvent::event_type().to_string(),
            channel,
            timestamp: chrono::Utc::now(),
            payload: serde_json::to_value(payload)
                .expect("DocumentUpdatedEvent should always serialize"),
        }
    }
    
    /// Create an envelope with explicit timestamp (for testing)
    pub fn new_with_timestamp(
        channel: String,
        payload: DocumentUpdatedEvent,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
            event_type: DocumentUpdatedEvent::event_type().to_string(),
            channel,
            timestamp,
            payload: serde_json::to_value(payload)
                .expect("DocumentUpdatedEvent should always serialize"),
        }
    }
}
```

### Event Generation with Envelope Separation

The callback signature changes to accept the event payload:

```rust
// webhook.rs - Updated callback signature
pub type WebhookCallback = Arc<dyn Fn(DocumentUpdatedEvent) + Send + Sync>;
```

Events are constructed with clear separation between payload creation and envelope creation:

```rust
// server.rs - in load_doc
pub async fn load_doc(&self, doc_id: &str) -> Result<()> {
    // ... existing setup ...
    
    let event_callback = {
        let event_dispatcher = self.event_dispatcher.clone();
        
        let routing_channel = doc_id.to_string();
        
        if let Some(dispatcher) = event_dispatcher {
            Some(Arc::new(move |event: DocumentUpdatedEvent| {
                // Step 1: Create the envelope with routing channel and payload
                let envelope = EventEnvelope::new(routing_channel.clone(), event);
                
                // Step 2: Send via dispatcher
                dispatcher.send_event(envelope);
            }) as y_sweet_core::webhook::WebhookCallback)
        } else {
            None
        }
    };
    
    // ... rest of method ...
}
```

In the document observer (where the event is actually fired):

```rust
// doc_sync.rs - where Yjs observer triggers
doc.observe_update_v1(move |_, update_event| {
    // ... sync_kv operations ...
    
    // Trigger webhook if callback is configured
    if let Some(ref callback) = webhook_callback {
        // Step 1: Create the event payload with business data
        let event = DocumentUpdatedEvent::new(doc_key.clone());
        
        // Step 2: Callback handles envelope creation and dispatch
        callback(event);
    }
})
```

### Event Routing

The EventDispatcher and EventSender traits work with envelopes:

```rust
// event.rs
pub trait EventDispatcher: Send + Sync {
    /// Send an event envelope to all registered listeners
    fn send_event(&self, envelope: EventEnvelope);
    
    /// Gracefully shutdown the dispatcher
    fn shutdown(&self);
}

pub trait EventSender: Send + Sync {
    /// Send an event envelope using this transport
    fn send_event(&self, envelope: EventEnvelope);
    
    /// Gracefully shutdown this sender
    fn shutdown(&self);
}
```

Route based on envelope channel, not payload content:

```rust
// event.rs
impl EventSender for WebSocketSender {
    fn send_event(&self, envelope: EventEnvelope) {
        // Route based on envelope channel only
        let matching_prefixes = self.find_matching_prefixes(&envelope.channel);
        
        if let Ok(connections_guard) = self.temporary_prefixes.try_read() {
            for prefix in matching_prefixes {
                if let Some(connections) = connections_guard.get(&prefix) {
                    let message = ServerMessage::from(envelope.clone());
                    
                    for conn in connections {
                        if let Err(e) = conn.sender.send(message.clone()) {
                            error!("Failed to send WebSocket event: {}", e);
                        }
                    }
                }
            }
        }
    }
}

impl EventSender for WebhookSender {
    fn send_event(&self, envelope: EventEnvelope) {
        // Route webhooks based on channel
        let matching_prefixes = self.find_matching_prefixes(&envelope.channel);
        
        for prefix in matching_prefixes {
            if let Some(queue) = self.queues.get(&prefix) {
                if let Err(e) = queue.send(envelope.clone()) {
                    error!("Failed to queue webhook for prefix '{}': {}", prefix, e);
                }
            }
        }
    }
}
```

### WebSocket Message Format

```rust
// event.rs
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "event")]
    Event {
        #[serde(rename = "eventId")]
        event_id: String,
        
        #[serde(rename = "eventType")]
        event_type: String,
        
        channel: String,
        timestamp: String,
        
        payload: serde_json::Value,  // The serialized DocumentUpdatedEvent
    },
    
    #[serde(rename = "pong")]
    Pong,
    
    #[serde(rename = "error")]
    Error { message: String },
}

impl From<EventEnvelope> for ServerMessage {
    fn from(envelope: EventEnvelope) -> Self {
        ServerMessage::Event {
            event_id: envelope.event_id,
            event_type: envelope.event_type,
            channel: envelope.channel,
            timestamp: envelope.timestamp.to_rfc3339(),
            payload: envelope.payload,
        }
    }
}
```

### Usage Examples

#### Standard Document Update
```rust
// Create the business event
let event = DocumentUpdatedEvent::new("doc-123".to_string())
    .with_user("user@example.com".to_string());

// Use doc_id as channel (current behavior)
let envelope = EventEnvelope::new("doc-123".to_string(), event);

// Send it
dispatcher.send_event(envelope);
```

### Benefits of This Design

1. **Clear Separation**: Envelope and payload are constructed independently
2. **Explicit Construction**: No hidden coupling between routing and business data
3. **Simple Mental Model**: Channel is just a routing key, payload is just data
4. **Type Safety**: DocumentUpdatedEvent is strongly typed
5. **Testability**: Can test envelope and payload logic separately
6. **Future-Proof**: Ready for channel override functionality to be added later

### Backwards Compatibility

- Existing webhook configurations continue to work
- WebSocket message format changes (no backwards compatibility requirements)
- Channel routing uses doc_id (same behavior as current system)
- We are implementing the pattern to support future event types, but adding more events is not in scope for this work

### Testing Requirements

1. **Unit Tests**:
   - DocumentUpdatedEvent construction and serialization
   - EventEnvelope construction with different channels
   - WebSocket message format conversion
   - Webhook payload format conversion

2. **Integration Tests**:
   - End-to-end event flow from document update to delivery
   - Prefix matching with envelope channels
   - Event dispatcher fanout behavior

## Implementation Plan

1. Create new `DocumentUpdatedEvent` and `EventEnvelope` structures
2. Update `WebhookCallback` signature to accept `DocumentUpdatedEvent`
3. Modify event dispatchers and senders to work with envelopes
4. Update WebSocket message format
5. Update all event creation sites to use new structures
6. Add comprehensive tests

## Conclusion

By explicitly constructing events and envelopes separately, we achieve clean separation of concerns. The envelope handles routing via its channel field, while the payload contains self-contained business data. This design is simple, explicit, and maintainable, and sets the foundation for future channel override functionality.
