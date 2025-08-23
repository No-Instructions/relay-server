use crate::api_types::{Authorization, NANOID_ALPHABET};
use crate::webhook::WebhookConfig;
use crate::webhook_metrics::WebhookMetrics;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Event payloads contain only business data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentUpdatedEvent {
    pub doc_id: String,
    pub user: Option<String>,
}

impl DocumentUpdatedEvent {
    /// Create a new document updated event payload
    pub fn new(doc_id: String) -> Self {
        Self { doc_id, user: None }
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

    pub channel: String, // Routing channel
    pub timestamp: chrono::DateTime<chrono::Utc>,

    pub payload: serde_json::Value, // Serialized payload
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

/// Trait for dispatching events to registered listeners
pub trait EventDispatcher: Send + Sync {
    /// Send an event envelope to all registered listeners
    fn send_event(&self, envelope: EventEnvelope);

    /// Gracefully shutdown the dispatcher
    fn shutdown(&self);
}

/// Transport-specific event senders
pub trait EventSender: Send + Sync {
    /// Send an event envelope using this transport
    fn send_event(&self, envelope: EventEnvelope);

    /// Gracefully shutdown this sender
    fn shutdown(&self);
}

/// WebSocket connection for event streaming
#[derive(Clone)]
pub struct WebSocketConnection {
    pub connection_id: String,
    pub sender: mpsc::UnboundedSender<ServerMessage>,
    pub authorization: Authorization,
}

/// Messages sent to WebSocket clients
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

        payload: serde_json::Value, // The serialized DocumentUpdatedEvent
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

/// Unified event dispatcher that fans out events to all transport-specific senders
pub struct UnifiedEventDispatcher {
    senders: Vec<Arc<dyn EventSender>>,
}

impl UnifiedEventDispatcher {
    /// Create a new unified dispatcher with the given senders
    pub fn new(senders: Vec<Arc<dyn EventSender>>) -> Self {
        debug!(
            "Created UnifiedEventDispatcher with {} senders",
            senders.len()
        );
        Self { senders }
    }
}

impl EventDispatcher for UnifiedEventDispatcher {
    fn send_event(&self, envelope: EventEnvelope) {
        debug!(
            "Dispatching event {} for channel {} to {} senders",
            envelope.event_id,
            envelope.channel,
            self.senders.len()
        );

        // Fanout to all delivery mechanisms
        for sender in &self.senders {
            sender.send_event(envelope.clone());
        }
    }

    fn shutdown(&self) {
        debug!(
            "Shutting down UnifiedEventDispatcher with {} senders",
            self.senders.len()
        );
        for sender in &self.senders {
            sender.shutdown();
        }
    }
}

/// HTTP webhook payload format
#[derive(Serialize, Debug, Clone)]
pub struct WebhookPayload {
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    pub payload: serde_json::Value,
}

impl From<EventEnvelope> for WebhookPayload {
    fn from(envelope: EventEnvelope) -> Self {
        WebhookPayload {
            event_type: envelope.event_type,
            event_id: envelope.event_id,
            payload: envelope.payload,
        }
    }
}

/// HTTP webhook event sender
pub struct WebhookSender {
    configs: Vec<WebhookConfig>,
    queues: HashMap<String, mpsc::UnboundedSender<EventEnvelope>>,
    shutdown_senders: Vec<mpsc::UnboundedSender<()>>,
    metrics: Arc<WebhookMetrics>,
}

impl WebhookSender {
    pub fn new(
        configs: Vec<WebhookConfig>,
        metrics: Arc<WebhookMetrics>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut queues = HashMap::new();
        let mut shutdown_senders = Vec::new();

        for config in &configs {
            let (tx, rx) = mpsc::unbounded_channel();
            let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel();

            queues.insert(config.prefix.clone(), tx);
            shutdown_senders.push(shutdown_tx);

            // Set initial metrics
            metrics.set_active_dispatchers(&config.prefix, 1);
            metrics.set_queue_length(&config.prefix, 0);

            // Spawn worker task for this prefix
            let config_clone = config.clone();
            let metrics_clone = metrics.clone();
            tokio::spawn(async move {
                Self::webhook_worker(config_clone, rx, shutdown_rx, metrics_clone).await;
            });
        }

        Ok(WebhookSender {
            configs,
            queues,
            shutdown_senders,
            metrics,
        })
    }

    /// Get access to the metrics instance
    pub fn metrics(&self) -> &Arc<WebhookMetrics> {
        &self.metrics
    }

    fn find_matching_prefixes(&self, channel: &str) -> Vec<String> {
        let mut matches: Vec<String> = self
            .configs
            .iter()
            .filter(|config| channel.starts_with(&config.prefix))
            .map(|config| config.prefix.clone())
            .collect();

        // Sort by prefix length (longest first) for consistent ordering
        matches.sort_by(|a, b| b.len().cmp(&a.len()));
        matches.dedup();
        matches
    }

    async fn webhook_worker(
        config: WebhookConfig,
        mut rx: mpsc::UnboundedReceiver<EventEnvelope>,
        mut shutdown_rx: mpsc::UnboundedReceiver<()>,
        metrics: Arc<WebhookMetrics>,
    ) {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .pool_max_idle_per_host(5)
            .user_agent("y-sweet-webhook/1.0.0")
            .build()
            .unwrap_or_else(|e| {
                error!(
                    "Failed to create HTTP client for prefix '{}': {}",
                    config.prefix, e
                );
                panic!("HTTP client creation failed");
            });

        loop {
            // Check shutdown first
            if shutdown_rx.try_recv().is_ok() {
                info!("Webhook worker shutting down for prefix: {}", config.prefix);
                break;
            }

            // Then check for events with timeout
            match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(envelope)) => {
                    if let Err(e) =
                        Self::send_single_webhook(&client, &config, &envelope, &metrics).await
                    {
                        error!(
                            "Failed to send webhook for event {} with prefix '{}': {}",
                            envelope.event_id, config.prefix, e
                        );
                    }
                }
                Ok(None) => {
                    break; // Channel closed
                }
                Err(_) => {
                    // Timeout - continue loop to check shutdown again
                    continue;
                }
            }
        }
    }

    async fn send_single_webhook(
        client: &Client,
        config: &WebhookConfig,
        envelope: &EventEnvelope,
        metrics: &WebhookMetrics,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = Instant::now();

        let payload: WebhookPayload = envelope.clone().into();

        debug!(
            "Sending webhook for event {} (channel {}) to prefix '{}'",
            envelope.event_id, envelope.channel, config.prefix
        );

        let mut request = client
            .post(&config.url)
            .header("Content-Type", "application/json");

        if let Some(auth_token) = &config.auth_token {
            request = request.header("Authorization", format!("Bearer {}", auth_token));
        }

        let request = request.json(&payload);

        let result = timeout(Duration::from_millis(config.timeout_ms), request.send())
            .await
            .map_err(|_| format!("Webhook request timed out after {}ms", config.timeout_ms))?
            .map_err(|e| e.to_string());

        let duration = start_time.elapsed().as_secs_f64();

        // Extract doc_id from payload for metrics
        let doc_id = envelope
            .payload
            .get("doc_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&envelope.channel);

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    metrics.record_webhook_request(&config.prefix, doc_id, "success", duration);
                    info!(
                        "Webhook sent successfully for event {} (channel {}) to prefix '{}'",
                        envelope.event_id, envelope.channel, config.prefix
                    );
                    Ok(())
                } else {
                    let status_code = response.status().as_u16().to_string();
                    metrics.record_webhook_request(&config.prefix, doc_id, &status_code, duration);
                    let error_msg = format!("Webhook failed with status {}", response.status());
                    error!(
                        "Webhook failed for event {} (channel {}) to prefix '{}': {}",
                        envelope.event_id, envelope.channel, config.prefix, error_msg
                    );
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                metrics.record_webhook_request(&config.prefix, doc_id, "error", duration);
                Err(e.into())
            }
        }
    }
}

impl EventSender for WebhookSender {
    fn send_event(&self, envelope: EventEnvelope) {
        let matching_prefixes = self.find_matching_prefixes(&envelope.channel);

        for prefix in matching_prefixes {
            if let Some(queue) = self.queues.get(&prefix) {
                if let Err(e) = queue.send(envelope.clone()) {
                    error!("Failed to queue webhook for prefix '{}': {}", prefix, e);
                }
            }
        }
    }

    fn shutdown(&self) {
        debug!(
            "Shutting down WebhookSender with {} workers",
            self.shutdown_senders.len()
        );
        for sender in &self.shutdown_senders {
            let _ = sender.send(()); // Ignore errors if receiver already dropped
        }
    }
}

/// WebSocket event sender
pub struct WebSocketSender {
    temporary_prefixes: Arc<RwLock<HashMap<String, Vec<WebSocketConnection>>>>,
}

impl WebSocketSender {
    pub fn new() -> Self {
        Self {
            temporary_prefixes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_websocket_prefix(
        &self,
        prefix: String,
        connection_id: String,
        sender: mpsc::UnboundedSender<ServerMessage>,
        authorization: Authorization,
    ) {
        if let Ok(mut temp_guard) = self.temporary_prefixes.try_write() {
            let connections = temp_guard.entry(prefix.clone()).or_insert_with(Vec::new);
            connections.push(WebSocketConnection {
                connection_id: connection_id.clone(),
                sender,
                authorization,
            });

            debug!(
                "Registered WebSocket connection {} for prefix: {} (total: {})",
                connection_id,
                prefix,
                connections.len()
            );
        }
    }

    pub fn unregister_websocket_connection(&self, prefix: &str, connection_id: &str) {
        if let Ok(mut temp_guard) = self.temporary_prefixes.try_write() {
            if let Some(connections) = temp_guard.get_mut(prefix) {
                connections.retain(|conn| conn.connection_id != connection_id);

                if connections.is_empty() {
                    temp_guard.remove(prefix);
                    debug!("Removed empty WebSocket prefix: {}", prefix);
                } else {
                    debug!(
                        "Unregistered WebSocket connection {} from prefix: {} (remaining: {})",
                        connection_id,
                        prefix,
                        connections.len()
                    );
                }
            }
        }
    }

    fn find_matching_prefixes(&self, channel: &str) -> Vec<String> {
        if let Ok(temp_guard) = self.temporary_prefixes.try_read() {
            temp_guard
                .keys()
                .filter(|prefix| channel.starts_with(*prefix))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl EventSender for WebSocketSender {
    fn send_event(&self, envelope: EventEnvelope) {
        let matching_prefixes = self.find_matching_prefixes(&envelope.channel);

        if let Ok(connections_guard) = self.temporary_prefixes.try_read() {
            for prefix in matching_prefixes {
                if let Some(connections) = connections_guard.get(&prefix) {
                    let message: ServerMessage = envelope.clone().into();
                    for conn in connections {
                        if let Err(e) = conn.sender.send(message.clone()) {
                            error!(
                                "Failed to send WebSocket event for prefix '{}' to connection '{}': {}",
                                prefix, conn.connection_id, e
                            );
                        }
                    }
                }
            }
        }
    }

    fn shutdown(&self) {
        debug!("Shutting down WebSocketSender");
        // WebSocket connections will be closed by their respective handlers
        // We just need to clear our registry
        if let Ok(mut temp_guard) = self.temporary_prefixes.try_write() {
            temp_guard.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_updated_event_creation() {
        let doc_id = "test_doc_123".to_string();
        let event = DocumentUpdatedEvent::new(doc_id.clone());

        assert_eq!(event.doc_id, doc_id);
        assert_eq!(event.user, None);
        assert_eq!(DocumentUpdatedEvent::event_type(), "document.updated");
    }

    #[test]
    fn test_document_updated_event_with_user() {
        let doc_id = "test_doc_123".to_string();
        let user = "user@example.com".to_string();
        let event = DocumentUpdatedEvent::new(doc_id.clone()).with_user(user.clone());

        assert_eq!(event.doc_id, doc_id);
        assert_eq!(event.user, Some(user));
    }

    #[test]
    fn test_event_envelope_creation() {
        let doc_id = "test_doc_123".to_string();
        let event = DocumentUpdatedEvent::new(doc_id.clone());
        let channel = doc_id.clone();

        let envelope = EventEnvelope::new(channel.clone(), event);

        assert_eq!(envelope.channel, channel);
        assert_eq!(envelope.event_type, "document.updated");
        assert!(envelope.event_id.starts_with("evt_"));
        assert_eq!(envelope.event_id.len(), 25); // "evt_" + 21 chars

        // Check payload structure
        let payload_obj = envelope.payload.as_object().unwrap();
        assert_eq!(payload_obj["doc_id"], doc_id);
        assert_eq!(payload_obj["user"], serde_json::Value::Null);
    }

    #[test]
    fn test_server_message_from_envelope() {
        let doc_id = "test_doc_123".to_string();
        let event = DocumentUpdatedEvent::new(doc_id.clone());
        let envelope = EventEnvelope::new(doc_id.clone(), event);

        let message: ServerMessage = envelope.clone().into();

        match message {
            ServerMessage::Event {
                event_type,
                event_id,
                channel,
                timestamp: _,
                payload,
            } => {
                assert_eq!(event_type, "document.updated");
                assert_eq!(event_id, envelope.event_id);
                assert_eq!(channel, envelope.channel);
                assert_eq!(payload["doc_id"], doc_id);
            }
            _ => panic!("Expected Event message"),
        }
    }

    #[test]
    fn test_webhook_payload_from_envelope() {
        let doc_id = "test_doc_123".to_string();
        let event = DocumentUpdatedEvent::new(doc_id.clone());
        let envelope = EventEnvelope::new(doc_id.clone(), event);

        let payload: WebhookPayload = envelope.clone().into();

        assert_eq!(payload.event_type, "document.updated");
        assert_eq!(payload.event_id, envelope.event_id);

        // Check payload structure
        let payload_obj = payload.payload.as_object().unwrap();
        assert_eq!(payload_obj["doc_id"], doc_id);
    }

    #[tokio::test]
    async fn test_unified_event_dispatcher() {
        // Create mock event senders
        struct MockEventSender {
            envelopes: Arc<RwLock<Vec<EventEnvelope>>>,
        }

        impl EventSender for MockEventSender {
            fn send_event(&self, envelope: EventEnvelope) {
                self.envelopes.write().unwrap().push(envelope);
            }

            fn shutdown(&self) {}
        }

        let sender1_envelopes = Arc::new(RwLock::new(Vec::new()));
        let sender2_envelopes = Arc::new(RwLock::new(Vec::new()));

        let sender1 = Arc::new(MockEventSender {
            envelopes: sender1_envelopes.clone(),
        });
        let sender2 = Arc::new(MockEventSender {
            envelopes: sender2_envelopes.clone(),
        });

        let dispatcher = UnifiedEventDispatcher::new(vec![sender1, sender2]);

        let event = DocumentUpdatedEvent::new("test_doc".to_string());
        let envelope = EventEnvelope::new("test_doc".to_string(), event);
        dispatcher.send_event(envelope.clone());

        // Both senders should have received the envelope
        assert_eq!(sender1_envelopes.read().unwrap().len(), 1);
        assert_eq!(sender2_envelopes.read().unwrap().len(), 1);
        assert_eq!(
            sender1_envelopes.read().unwrap()[0].channel,
            envelope.channel
        );
        assert_eq!(
            sender2_envelopes.read().unwrap()[0].channel,
            envelope.channel
        );
    }

    #[tokio::test]
    async fn test_websocket_sender() {
        let sender = WebSocketSender::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Register a WebSocket connection
        sender.register_websocket_prefix(
            "test_".to_string(),
            "conn_123".to_string(),
            tx,
            Authorization::Full,
        );

        // Send an event
        let event = DocumentUpdatedEvent::new("test_document".to_string());
        let envelope = EventEnvelope::new("test_document".to_string(), event);
        sender.send_event(envelope.clone());

        // Should receive the event as a ServerMessage
        let message = rx.recv().await.unwrap();
        match message {
            ServerMessage::Event {
                event_type,
                event_id,
                channel,
                timestamp: _,
                payload,
            } => {
                assert_eq!(event_type, "document.updated");
                assert_eq!(event_id, envelope.event_id);
                assert_eq!(channel, envelope.channel);
                assert_eq!(payload["doc_id"], "test_document");
            }
            _ => panic!("Expected Event message"),
        }
    }

    #[tokio::test]
    async fn test_websocket_sender_prefix_matching() {
        let sender = WebSocketSender::new();
        let (tx1, mut rx1) = tokio::sync::mpsc::unbounded_channel();
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();

        // Register connections for different prefixes
        sender.register_websocket_prefix(
            "user_".to_string(),
            "conn_1".to_string(),
            tx1,
            Authorization::Full,
        );
        sender.register_websocket_prefix(
            "admin_".to_string(),
            "conn_2".to_string(),
            tx2,
            Authorization::Full,
        );

        // Send event that matches first prefix
        let event1 = DocumentUpdatedEvent::new("user_alice_doc".to_string());
        let envelope1 = EventEnvelope::new("user_alice_doc".to_string(), event1);
        sender.send_event(envelope1.clone());

        // Only first connection should receive it
        let message1 = rx1.recv().await.unwrap();
        if let ServerMessage::Event { channel, .. } = message1 {
            assert_eq!(channel, envelope1.channel);
        } else {
            panic!("Expected Event message");
        }

        // Second connection should not receive anything
        assert!(rx2.try_recv().is_err());

        // Send event that matches second prefix
        let event2 = DocumentUpdatedEvent::new("admin_settings".to_string());
        let envelope2 = EventEnvelope::new("admin_settings".to_string(), event2);
        sender.send_event(envelope2.clone());

        // Only second connection should receive it
        let message2 = rx2.recv().await.unwrap();
        if let ServerMessage::Event { channel, .. } = message2 {
            assert_eq!(channel, envelope2.channel);
        } else {
            panic!("Expected Event message");
        }
    }

    #[tokio::test]
    async fn test_websocket_sender_connection_lifecycle() {
        let sender = WebSocketSender::new();
        let (tx1, _rx1) = tokio::sync::mpsc::unbounded_channel();
        let (tx2, _rx2) = tokio::sync::mpsc::unbounded_channel();

        let prefix = "test_".to_string();

        // Register two connections for the same prefix
        sender.register_websocket_prefix(
            prefix.clone(),
            "conn1".to_string(),
            tx1,
            Authorization::Full,
        );
        sender.register_websocket_prefix(
            prefix.clone(),
            "conn2".to_string(),
            tx2,
            Authorization::ReadOnly,
        );

        // Both connections should be registered
        {
            let temp_guard = sender.temporary_prefixes.read().unwrap();
            let connections = temp_guard.get(&prefix).unwrap();
            assert_eq!(connections.len(), 2);
        }

        // Unregister one connection
        sender.unregister_websocket_connection(&prefix, "conn1");

        // Should have one connection left
        {
            let temp_guard = sender.temporary_prefixes.read().unwrap();
            let connections = temp_guard.get(&prefix).unwrap();
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].connection_id, "conn2");
        }

        // Unregister the last connection - prefix should be removed
        sender.unregister_websocket_connection(&prefix, "conn2");

        {
            let temp_guard = sender.temporary_prefixes.read().unwrap();
            assert!(!temp_guard.contains_key(&prefix));
        }
    }

    #[tokio::test]
    async fn test_webhook_sender_prefix_matching() {
        use crate::webhook::WebhookConfig;

        let configs = vec![
            WebhookConfig {
                prefix: "user_".to_string(),
                url: "https://example.com/user".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "admin_".to_string(),
                url: "https://example.com/admin".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
        ];

        let metrics = crate::webhook_metrics::WebhookMetrics::new_for_test().unwrap();
        let sender = WebhookSender::new(configs, metrics).unwrap();

        // Test prefix matching
        let matches = sender.find_matching_prefixes("user_alice_doc");
        assert_eq!(matches, vec!["user_"]);

        let matches = sender.find_matching_prefixes("admin_settings");
        assert_eq!(matches, vec!["admin_"]);

        let matches = sender.find_matching_prefixes("public_doc");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let event = DocumentUpdatedEvent::new("test_doc".to_string());
        let envelope = EventEnvelope::new("test_doc".to_string(), event);

        let payload: WebhookPayload = envelope.into();
        let json = serde_json::to_string(&payload).unwrap();

        // Verify JSON structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["eventType"], "document.updated");
        assert!(parsed["eventId"].as_str().unwrap().starts_with("evt_"));
        assert_eq!(parsed["payload"]["doc_id"], "test_doc");
    }
}
