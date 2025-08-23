# Event Architecture Refactor

## Summary

This proposal refactors the webhook/event system to separate event creation from dispatch, providing a cleaner architecture that supports multiple event delivery mechanisms (HTTP webhooks, WebSockets, and future transports).

## Motivation

Currently, event creation is tightly coupled with dispatch inside the `send_webhooks` function. This creates several issues:

1. **Tight Coupling**: The dispatcher knows about event formats for each delivery mechanism
2. **Inconsistency**: Different event types (HTTP vs WebSocket) are created in different places
3. **Limited Extensibility**: Adding new event types or delivery mechanisms requires modifying the dispatcher
4. **Testing Complexity**: Cannot test event creation separately from dispatch

## Proposed Architecture

### Core Concepts

1. **Event**: A transport-agnostic representation of something that happened
2. **Event Dispatcher**: Routes events to appropriate delivery mechanisms based on configuration
3. **Event Sender**: Transport-specific implementations that format and deliver events

### Event Types

```rust
#[derive(Clone, Debug)]
pub struct Event {
    pub event_type: EventType,
    pub doc_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_id: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub enum EventType {
    DocumentCreated,
    DocumentUpdated,
    DocumentDeleted,
    // Future event types
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::DocumentCreated => "document.created",
            EventType::DocumentUpdated => "document.updated",
            EventType::DocumentDeleted => "document.deleted",
        }
    }
}
```

### Event Dispatcher Interface

```rust
pub trait EventDispatcher {
    /// Send an event to all registered listeners
    fn send_event(&self, event: Event);
}

pub struct UnifiedEventDispatcher {
    webhook_sender: Arc<WebhookSender>,
    websocket_sender: Arc<WebSocketSender>,
    // Future: other senders
}

impl EventDispatcher for UnifiedEventDispatcher {
    fn send_event(&self, event: Event) {
        // Fanout to all delivery mechanisms
        self.webhook_sender.send_event(event.clone());
        self.websocket_sender.send_event(event.clone());
    }
}
```

### Transport-Specific Senders

```rust
pub trait EventSender {
    fn send_event(&self, event: Event);
}

pub struct WebhookSender {
    configs: Vec<WebhookConfig>,
    queues: HashMap<String, mpsc::UnboundedSender<Event>>,
    metrics: Arc<WebhookMetrics>,
}

impl EventSender for WebhookSender {
    fn send_event(&self, event: Event) {
        let matching_prefixes = self.find_matching_prefixes(&event.doc_id);
        
        for prefix in matching_prefixes {
            if let Some(queue) = self.queues.get(&prefix) {
                let _ = queue.send(event.clone());
            }
        }
    }
}

pub struct WebSocketSender {
    temporary_prefixes: Arc<RwLock<HashMap<String, Vec<WebSocketConnection>>>>,
}

impl EventSender for WebSocketSender {
    fn send_event(&self, event: Event) {
        if let Ok(connections_guard) = self.temporary_prefixes.read() {
            for (prefix, connections) in connections_guard.iter() {
                if event.doc_id.starts_with(prefix) {
                    let message = self.format_event(&event);
                    for conn in connections {
                        let _ = conn.sender.send(message.clone());
                    }
                }
            }
        }
    }
}
```

### Event Creation

Events are created at the point where the action occurs, not in the dispatcher:

```rust
// In Server::load_doc or wherever document updates happen
let event = Event {
    event_type: EventType::DocumentUpdated,
    doc_id: doc_id.clone(),
    timestamp: chrono::Utc::now(),
    event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
    metadata: None,
};

// Send to unified dispatcher
if let Some(dispatcher) = &self.event_dispatcher {
    dispatcher.send_event(event);
}
```

### Fanout Strategy

The fanout happens at two levels:

1. **Transport Level**: UnifiedEventDispatcher fans out to all transport-specific senders
2. **Prefix Level**: Each sender fans out to all matching prefixes/connections

This ensures:
- Events reach all interested parties
- Each transport can apply its own filtering/routing logic
- New transports can be added without modifying existing code

### Benefits

1. **Separation of Concerns**: Event creation, routing, and delivery are separate
2. **Testability**: Each component can be tested independently
3. **Extensibility**: New event types and transports can be added easily
4. **Consistency**: All events follow the same flow regardless of delivery mechanism
5. **Type Safety**: Event types are explicitly defined rather than using strings

### Migration Path

1. **Phase 1**: Create new Event types and EventDispatcher trait
2. **Phase 2**: Implement UnifiedEventDispatcher with existing WebhookDispatcher wrapped
3. **Phase 3**: Refactor WebhookDispatcher to implement EventSender
4. **Phase 4**: Extract WebSocket event sending into WebSocketSender
5. **Phase 5**: Update all event creation sites to use new Event type
6. **Phase 6**: Remove old send_webhooks method

## Implementation Considerations

### Backward Compatibility

- Existing webhook configurations continue to work
- Event format for HTTP webhooks remains unchanged

### Performance

- Event cloning is cheap (Arc for large data)
- Fanout is parallel across transports
- No additional serialization overhead

### Error Handling

- Each transport handles its own errors
- Failed delivery to one transport doesn't affect others
- Metrics track per-transport success/failure

## Conclusion

This refactoring provides a cleaner, more maintainable architecture for the event system while preserving existing functionality and enabling future growth.
