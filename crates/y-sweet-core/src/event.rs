use crate::api_types::{Authorization, NANOID_ALPHABET};
use crate::sync::EventMessage;
use crate::sync_kv::SyncKv;
use crate::webhook::WebhookConfig;
use crate::webhook_metrics::WebhookMetrics;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Convert CBOR metadata values to JSON values for event serialization
fn cbor_metadata_to_json(
    cbor_metadata: &BTreeMap<String, ciborium::value::Value>,
) -> Result<BTreeMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
    let mut json_metadata = BTreeMap::new();

    for (key, cbor_value) in cbor_metadata {
        let json_value = cbor_value_to_json_value(cbor_value)?;
        json_metadata.insert(key.clone(), json_value);
    }

    Ok(json_metadata)
}

/// Convert a single CBOR value to a JSON value
fn cbor_value_to_json_value(
    cbor_value: &ciborium::value::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    match cbor_value {
        ciborium::value::Value::Integer(i) => {
            // CBOR integers can be larger than i64, so we need to handle the conversion carefully
            if let Ok(i64_val) = TryInto::<i64>::try_into(*i) {
                Ok(serde_json::Value::Number(serde_json::Number::from(i64_val)))
            } else if let Ok(u64_val) = TryInto::<u64>::try_into(*i) {
                // Try to convert to u64 if i64 fails
                if let Some(num) = serde_json::Number::from_f64(u64_val as f64) {
                    Ok(serde_json::Value::Number(num))
                } else {
                    Ok(serde_json::Value::Null)
                }
            } else {
                // If conversion fails, convert to null
                Ok(serde_json::Value::Null)
            }
        }
        ciborium::value::Value::Text(s) => Ok(serde_json::Value::String(s.clone())),
        ciborium::value::Value::Bool(b) => Ok(serde_json::Value::Bool(*b)),
        ciborium::value::Value::Null => Ok(serde_json::Value::Null),
        ciborium::value::Value::Array(arr) => {
            let json_array: Result<Vec<_>, _> = arr.iter().map(cbor_value_to_json_value).collect();
            Ok(serde_json::Value::Array(json_array?))
        }
        ciborium::value::Value::Map(map) => {
            let mut json_obj = serde_json::Map::new();
            for (k, v) in map {
                if let ciborium::value::Value::Text(key_str) = k {
                    let json_val = cbor_value_to_json_value(v)?;
                    json_obj.insert(key_str.clone(), json_val);
                } else {
                    return Err("Map keys must be strings for JSON conversion".into());
                }
            }
            Ok(serde_json::Value::Object(json_obj))
        }
        ciborium::value::Value::Float(f) => {
            if let Some(num) = serde_json::Number::from_f64(*f) {
                Ok(serde_json::Value::Number(num))
            } else {
                Err("Invalid floating point number for JSON".into())
            }
        }
        _ => Ok(serde_json::Value::Null),
    }
}

/// Event payloads contain only business data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentUpdatedEvent {
    pub doc_id: String,
    pub user: Option<String>,
    pub metadata: BTreeMap<String, serde_json::Value>,
    #[serde(skip)] // Don't serialize the raw update data to JSON
    pub update: Option<Vec<u8>>,
}

impl DocumentUpdatedEvent {
    /// Create a new document updated event payload
    pub fn new(doc_id: String) -> Self {
        Self {
            doc_id,
            user: None,
            metadata: BTreeMap::new(),
            update: None,
        }
    }

    /// Builder method to add user
    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    /// Builder method to add Yjs update data
    pub fn with_update(mut self, update: Vec<u8>) -> Self {
        self.update = Some(update);
        self
    }

    /// Builder method to add metadata from SyncKv
    pub fn with_metadata(mut self, sync_kv: &SyncKv) -> Self {
        if let Some(cbor_metadata) = sync_kv.get_metadata() {
            match cbor_metadata_to_json(&cbor_metadata) {
                Ok(json_metadata) => {
                    self.metadata = json_metadata;
                }
                Err(e) => {
                    error!("Failed to convert CBOR metadata to JSON: {}", e);
                }
            }
        }
        self
    }

    /// Get the event type identifier
    pub fn event_type() -> &'static str {
        "document.updated"
    }
}

/// The envelope contains only routing and transport metadata
#[derive(Clone, Debug)]
pub struct EventEnvelope {
    pub event_id: String,
    pub event_type: String,
    pub channel: String, // Routing channel
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event: DocumentUpdatedEvent, // Raw event data - serialize at dispatch time
}

impl EventEnvelope {
    /// Create an envelope for a document updated event
    /// Channel and event are provided separately  
    pub fn new(channel: String, event: DocumentUpdatedEvent) -> Self {
        Self {
            event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
            event_type: DocumentUpdatedEvent::event_type().to_string(),
            channel,
            timestamp: chrono::Utc::now(),
            event,
        }
    }

    /// Create an envelope with explicit timestamp (for testing)
    pub fn new_with_timestamp(
        channel: String,
        event: DocumentUpdatedEvent,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
            event_type: DocumentUpdatedEvent::event_type().to_string(),
            channel,
            timestamp,
            event,
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
pub trait EventSender: Send + Sync + std::any::Any {
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
            payload: serde_json::to_value(envelope.event)
                .expect("DocumentUpdatedEvent should always serialize"),
        }
    }
}

/// Unified event dispatcher that fans out events to all transport-specific senders
pub struct UnifiedEventDispatcher {
    senders: Vec<Arc<dyn EventSender>>,
    metrics: Arc<WebhookMetrics>,
}

impl UnifiedEventDispatcher {
    /// Create a new unified dispatcher with the given senders
    pub fn new(senders: Vec<Arc<dyn EventSender>>, metrics: Arc<WebhookMetrics>) -> Self {
        debug!(
            "Created UnifiedEventDispatcher with {} senders",
            senders.len()
        );
        Self { senders, metrics }
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

        // Record event dispatch metrics
        for sender in &self.senders {
            let sender_type = if sender.type_id() == std::any::TypeId::of::<WebhookSender>() {
                "webhook"
            } else if sender.type_id() == std::any::TypeId::of::<WebSocketSender>() {
                "websocket"
            } else if sender.type_id() == std::any::TypeId::of::<SyncProtocolEventSender>() {
                "sync_protocol"
            } else if sender.type_id() == std::any::TypeId::of::<DebouncedSyncProtocolEventSender>()
            {
                "debounced_sync_protocol"
            } else {
                "unknown"
            };

            self.metrics
                .record_event_dispatched(&envelope.event_type, sender_type);
        }

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
            payload: serde_json::to_value(envelope.event)
                .expect("DocumentUpdatedEvent should always serialize"),
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

        // Extract doc_id from event for metrics
        let _doc_id = &envelope.event.doc_id;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    metrics.record_webhook_request(&config.prefix, "success", duration);
                    info!(
                        "Webhook sent successfully for event {} (channel {}) to prefix '{}'",
                        envelope.event_id, envelope.channel, config.prefix
                    );
                    Ok(())
                } else {
                    let status_code = response.status().as_u16().to_string();
                    metrics.record_webhook_request(&config.prefix, &status_code, duration);
                    let error_msg = format!("Webhook failed with status {}", response.status());
                    error!(
                        "Webhook failed for event {} (channel {}) to prefix '{}': {}",
                        envelope.event_id, envelope.channel, config.prefix, error_msg
                    );
                    Err(error_msg.into())
                }
            }
            Err(e) => {
                metrics.record_webhook_request(&config.prefix, "error", duration);
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

/// Debounced sync protocol event sender that batches events per user per document
pub struct DebouncedSyncProtocolEventSender {
    inner_sender: Arc<SyncProtocolEventSender>,
    user_queues: Arc<tokio::sync::RwLock<HashMap<String, Arc<UserEventQueue>>>>,
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
    metrics: Arc<WebhookMetrics>,
}

struct UserEventQueue {
    pending_updates: Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
    base_event: Arc<tokio::sync::Mutex<Option<EventEnvelope>>>,
    last_sent: Arc<tokio::sync::Mutex<Option<tokio::time::Instant>>>,
    debounce_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl UserEventQueue {
    fn new() -> Self {
        Self {
            pending_updates: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            base_event: Arc::new(tokio::sync::Mutex::new(None)),
            last_sent: Arc::new(tokio::sync::Mutex::new(None)),
            debounce_handle: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn should_send_immediately(&self) -> bool {
        let last_sent = self.last_sent.lock().await;
        match *last_sent {
            Some(last) => last.elapsed() >= tokio::time::Duration::from_secs(1),
            None => true,
        }
    }

    async fn mark_sent(&self) {
        let mut last_sent = self.last_sent.lock().await;
        *last_sent = Some(tokio::time::Instant::now());
    }

    async fn cancel_pending_task(&self) {
        let mut handle = self.debounce_handle.lock().await;
        if let Some(task) = handle.take() {
            task.abort();
        }
    }
}

impl DebouncedSyncProtocolEventSender {
    pub fn new(inner_sender: Arc<SyncProtocolEventSender>, metrics: Arc<WebhookMetrics>) -> Self {
        let user_queues = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let cleanup_interval = tokio::time::Duration::from_secs(60);

        // Start cleanup task
        let queues_for_cleanup = user_queues.clone();
        let cleanup_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_idle_queues(&queues_for_cleanup).await;
            }
        }));

        Self {
            inner_sender,
            user_queues,
            cleanup_handle,
            metrics,
        }
    }

    /// Create a unique key for the user-document combination
    fn create_queue_key(doc_id: &str, user: Option<&str>) -> String {
        match user {
            Some(u) => format!("{}:{}", doc_id, u),
            None => format!("{}:__anonymous__", doc_id),
        }
    }

    async fn get_or_create_queue(&self, doc_id: &str, user: Option<&str>) -> Arc<UserEventQueue> {
        let key = Self::create_queue_key(doc_id, user);
        let mut queues = self.user_queues.write().await;
        queues
            .entry(key)
            .or_insert_with(|| Arc::new(UserEventQueue::new()))
            .clone()
    }

    async fn cleanup_idle_queues(
        queues: &Arc<tokio::sync::RwLock<HashMap<String, Arc<UserEventQueue>>>>,
    ) {
        let idle_threshold = tokio::time::Duration::from_secs(300); // 5 minutes
        let mut to_remove = Vec::new();

        let queues_guard = queues.read().await;
        for (queue_key, queue) in queues_guard.iter() {
            if let Some(last_sent) = *queue.last_sent.lock().await {
                if last_sent.elapsed() > idle_threshold {
                    to_remove.push(queue_key.clone());
                }
            }
        }
        drop(queues_guard);

        if !to_remove.is_empty() {
            let mut queues_guard = queues.write().await;
            for queue_key in to_remove {
                queues_guard.remove(&queue_key);
                tracing::debug!("Cleaned up idle event queue for {}", queue_key);
            }
        }
    }

    pub async fn queue_event(&self, envelope: EventEnvelope) {
        let doc_id = &envelope.channel;

        // Extract user from event
        let user = envelope.event.user.as_deref();

        // Get the queue for this specific user-document combination
        let queue = self.get_or_create_queue(doc_id, user).await;

        // Extract update data directly from the event
        let update_data = envelope.event.update.clone();

        // Cancel any existing debounce timer for this user
        queue.cancel_pending_task().await;

        // Store the base event template and add the update to pending updates
        {
            let mut base_event = queue.base_event.lock().await;
            if base_event.is_none() {
                *base_event = Some(envelope.clone());
            }

            if let Some(update) = update_data {
                let mut pending_updates = queue.pending_updates.lock().await;
                pending_updates.push(update);
            }
        }

        // Check if we can send immediately (rate limit allows it)
        if queue.should_send_immediately().await {
            // Merge all pending updates and send immediately
            self.send_merged_event(&queue).await;
            queue.mark_sent().await;
        } else {
            // Schedule debounced send
            let delay = {
                let last_sent = queue.last_sent.lock().await;
                match *last_sent {
                    Some(last) => {
                        let elapsed = last.elapsed();
                        if elapsed < tokio::time::Duration::from_secs(1) {
                            tokio::time::Duration::from_secs(1) - elapsed
                        } else {
                            tokio::time::Duration::from_millis(0)
                        }
                    }
                    None => tokio::time::Duration::from_millis(0),
                }
            };

            let inner_sender = self.inner_sender.clone();
            let queue_clone = queue.clone();
            let metrics = self.metrics.clone();

            let task = tokio::spawn(async move {
                tokio::time::sleep(delay).await;

                // Create a temporary sender to call send_merged_event
                let temp_sender = DebouncedSyncProtocolEventSender {
                    inner_sender,
                    user_queues: Default::default(), // Not used in send_merged_event
                    cleanup_handle: None,
                    metrics,
                };

                temp_sender.send_merged_event(&queue_clone).await;
                queue_clone.mark_sent().await;
            });

            // Store the task handle
            let mut handle = queue.debounce_handle.lock().await;
            *handle = Some(task);
        }
    }

    async fn send_merged_event(&self, queue: &UserEventQueue) {
        let (base_event, updates) = {
            let mut base_event = queue.base_event.lock().await;
            let mut pending_updates = queue.pending_updates.lock().await;

            let event = base_event.take();
            let updates = std::mem::take(&mut *pending_updates);
            (event, updates)
        };

        if let Some(event) = base_event {
            if !updates.is_empty() {
                // Merge all updates using yrs::merge_updates_v1
                match yrs::merge_updates_v1(&updates) {
                    Ok(merged_update) => {
                        // Create a new event with the merged update data
                        let mut new_event = event.clone();
                        new_event.event.update = Some(merged_update);

                        // Record metrics for update merging
                        let _user = new_event.event.user.as_deref().unwrap_or("__anonymous__");
                        self.metrics.record_updates_merged(updates.len());

                        tracing::debug!("Merged {} updates for user-document", updates.len());
                        self.inner_sender.send_event(new_event);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to merge updates: {}, sending latest event", e);
                        self.inner_sender.send_event(event);
                    }
                }
            } else {
                // No updates to merge, send the base event
                self.inner_sender.send_event(event);
            }
        }
    }
}

impl EventSender for DebouncedSyncProtocolEventSender {
    fn send_event(&self, envelope: EventEnvelope) {
        // Clone necessary fields for the async task
        let inner_sender = self.inner_sender.clone();
        let user_queues = self.user_queues.clone();

        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            let temp_sender = DebouncedSyncProtocolEventSender {
                inner_sender,
                user_queues,
                cleanup_handle: None, // Don't clone the cleanup handle
                metrics,
            };
            temp_sender.queue_event(envelope).await;
        });
    }

    fn shutdown(&self) {
        // Cancel cleanup task
        if let Some(handle) = &self.cleanup_handle {
            handle.abort();
        }

        // Shutdown inner sender
        self.inner_sender.shutdown();
    }
}

/// Sync protocol event sender using weak references to avoid circular dependencies
pub struct SyncProtocolEventSender {
    // Map from document ID to list of weak references to DocConnections
    doc_connections:
        Arc<RwLock<HashMap<String, Vec<std::sync::Weak<crate::doc_connection::DocConnection>>>>>,
    metrics: Option<Arc<WebhookMetrics>>,
}

impl SyncProtocolEventSender {
    pub fn new() -> Self {
        Self {
            doc_connections: Arc::new(RwLock::new(HashMap::new())),
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<WebhookMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Register a DocConnection for a document
    pub fn register_doc_connection(
        &self,
        doc_id: String,
        connection: std::sync::Weak<crate::doc_connection::DocConnection>,
    ) {
        if let Ok(mut connections) = self.doc_connections.write() {
            let doc_connections = connections.entry(doc_id.clone()).or_insert_with(Vec::new);
            doc_connections.push(connection);

            // Clean up any dead weak references while we're here
            doc_connections.retain(|weak_conn| weak_conn.strong_count() > 0);

            // Update metrics
            if let Some(ref metrics) = self.metrics {
                metrics.set_sync_protocol_connections(doc_connections.len());
            }

            tracing::debug!(
                "Registered DocConnection for document {}. Total connections: {}",
                doc_id,
                doc_connections.len()
            );
        }
    }

    /// Unregister all connections for a document (called when document is dropped)
    pub fn unregister_document(&self, doc_id: &str) {
        if let Ok(mut connections) = self.doc_connections.write() {
            connections.remove(doc_id);

            // Update metrics
            if let Some(ref metrics) = self.metrics {
                metrics.set_sync_protocol_connections(0);
            }

            tracing::debug!("Unregistered all DocConnections for document {}", doc_id);
        }
    }

    /// Convert DocumentUpdatedEvent to EventMessage
    fn convert_to_event_message(
        &self,
        envelope: &EventEnvelope,
    ) -> Result<EventMessage, Box<dyn std::error::Error>> {
        let timestamp = envelope.timestamp.timestamp_millis() as u64;

        // Extract user from event
        let user = envelope.event.user.clone();

        // Convert metadata to JSON value
        let metadata = if envelope.event.metadata.is_empty() {
            None
        } else {
            Some(serde_json::to_value(&envelope.event.metadata)?)
        };

        Ok(EventMessage {
            event_id: envelope.event_id.clone(),
            event_type: envelope.event_type.clone(),
            doc_id: envelope.event.doc_id.clone(),
            timestamp,
            user,
            metadata,
            update: envelope.event.update.clone(),
        })
    }
}

impl EventSender for SyncProtocolEventSender {
    fn send_event(&self, envelope: EventEnvelope) {
        // Use the channel for routing (where connections are registered)
        // but the EventMessage will contain the correct doc_id from the event
        let routing_key = &envelope.channel;

        if let Ok(connections) = self.doc_connections.read() {
            if let Some(doc_connections) = connections.get(routing_key) {
                // Convert EventEnvelope to EventMessage
                match self.convert_to_event_message(&envelope) {
                    Ok(event_message) => {
                        let mut sent_count = 0;
                        let mut failed_count = 0;

                        for weak_conn in doc_connections {
                            if let Some(connection) = weak_conn.upgrade() {
                                match connection.send_event(&event_message) {
                                    Ok(()) => {
                                        sent_count += 1;
                                        // Record successful delivery
                                        if let Some(ref metrics) = self.metrics {
                                            metrics.record_event_delivered(
                                                &envelope.event_type,
                                                "sync_protocol",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to send event to DocConnection: {}",
                                            e
                                        );
                                        failed_count += 1;
                                    }
                                }
                            }
                        }

                        tracing::debug!(
                            "Sent event {} to {} DocConnections for routing_key {} ({} failed)",
                            event_message.event_id,
                            sent_count,
                            routing_key,
                            failed_count
                        );
                    }
                    Err(e) => {
                        tracing::error!("Failed to convert EventEnvelope to EventMessage: {}", e);
                    }
                }
            } else {
                tracing::debug!(
                    "No DocConnections registered for routing_key {}",
                    routing_key
                );
            }
        } else {
            tracing::warn!("Failed to acquire DocConnections read lock");
        }

        // Clean up dead weak references periodically
        if let Ok(mut connections) = self.doc_connections.write() {
            for doc_connections in connections.values_mut() {
                doc_connections.retain(|weak_conn| weak_conn.strong_count() > 0);
            }
            connections.retain(|_, doc_connections| !doc_connections.is_empty());
        }
    }

    fn shutdown(&self) {
        tracing::debug!("Shutting down SyncProtocolEventSender");
        if let Ok(mut connections) = self.doc_connections.write() {
            connections.clear();
        }
    }
}

#[cfg(test)]
mod debounced_sync_tests {
    use super::*;

    #[test]
    fn test_create_queue_key_with_user() {
        let key = DebouncedSyncProtocolEventSender::create_queue_key("doc123", Some("alice"));
        assert_eq!(key, "doc123:alice");
    }

    #[test]
    fn test_create_queue_key_without_user() {
        let key = DebouncedSyncProtocolEventSender::create_queue_key("doc123", None);
        assert_eq!(key, "doc123:__anonymous__");
    }

    #[tokio::test]
    async fn test_per_user_queuing() {
        let metrics = crate::webhook_metrics::WebhookMetrics::new_for_test().unwrap();
        let sender = DebouncedSyncProtocolEventSender {
            inner_sender: Arc::new(SyncProtocolEventSender::new()),
            user_queues: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            cleanup_handle: None,
            metrics,
        };

        // Get queues for different users on same document
        let alice_queue = sender.get_or_create_queue("doc1", Some("alice")).await;
        let bob_queue = sender.get_or_create_queue("doc1", Some("bob")).await;
        let anon_queue = sender.get_or_create_queue("doc1", None).await;

        // Should be different queues
        assert!(!Arc::ptr_eq(&alice_queue, &bob_queue));
        assert!(!Arc::ptr_eq(&alice_queue, &anon_queue));
        assert!(!Arc::ptr_eq(&bob_queue, &anon_queue));

        // Same user should get same queue
        let alice_queue2 = sender.get_or_create_queue("doc1", Some("alice")).await;
        assert!(Arc::ptr_eq(&alice_queue, &alice_queue2));
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
        assert!(event.metadata.is_empty());
        assert_eq!(DocumentUpdatedEvent::event_type(), "document.updated");
    }

    #[test]
    fn test_document_updated_event_with_user() {
        let doc_id = "test_doc_123".to_string();
        let user = "user@example.com".to_string();
        let event = DocumentUpdatedEvent::new(doc_id.clone()).with_user(user.clone());

        assert_eq!(event.doc_id, doc_id);
        assert_eq!(event.user, Some(user));
        assert!(event.metadata.is_empty());
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

        // Check event structure
        assert_eq!(envelope.event.doc_id, doc_id);
        assert_eq!(envelope.event.user, None);
        assert!(envelope.event.metadata.is_empty());
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
                assert_eq!(
                    payload["metadata"],
                    serde_json::Value::Object(serde_json::Map::new())
                );
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
        assert_eq!(
            payload_obj["metadata"],
            serde_json::Value::Object(serde_json::Map::new())
        );
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

        let metrics = crate::webhook_metrics::WebhookMetrics::new_for_test().unwrap();
        let dispatcher = UnifiedEventDispatcher::new(vec![sender1, sender2], metrics);

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
        assert_eq!(
            parsed["payload"]["metadata"],
            serde_json::Value::Object(serde_json::Map::new())
        );
    }

    #[test]
    fn test_cbor_to_json_conversion() {
        use std::collections::BTreeMap;

        // Create CBOR metadata
        let mut cbor_metadata = BTreeMap::new();
        cbor_metadata.insert(
            "channel".to_string(),
            ciborium::value::Value::Text("test-channel".to_string()),
        );
        cbor_metadata.insert(
            "max_users".to_string(),
            ciborium::value::Value::Integer(10.into()),
        );
        cbor_metadata.insert("is_active".to_string(), ciborium::value::Value::Bool(true));

        // Convert to JSON
        let json_result = cbor_metadata_to_json(&cbor_metadata).unwrap();

        assert_eq!(json_result.len(), 3);
        assert_eq!(
            json_result["channel"],
            serde_json::Value::String("test-channel".to_string())
        );
        assert_eq!(
            json_result["max_users"],
            serde_json::Value::Number(serde_json::Number::from(10))
        );
        assert_eq!(json_result["is_active"], serde_json::Value::Bool(true));
    }

    #[test]
    fn test_document_event_with_metadata_method() {
        use crate::store::Store;
        use async_trait::async_trait;
        use dashmap::DashMap;
        use std::sync::Arc;

        #[derive(Default, Clone)]
        struct TestStore {
            data: Arc<DashMap<String, Vec<u8>>>,
        }

        #[cfg_attr(not(feature = "single-threaded"), async_trait)]
        #[cfg_attr(feature = "single-threaded", async_trait(?Send))]
        impl Store for TestStore {
            async fn init(&self) -> crate::store::Result<()> {
                Ok(())
            }
            async fn get(&self, key: &str) -> crate::store::Result<Option<Vec<u8>>> {
                Ok(self.data.get(key).map(|v| v.clone()))
            }
            async fn set(&self, key: &str, value: Vec<u8>) -> crate::store::Result<()> {
                self.data.insert(key.to_owned(), value);
                Ok(())
            }
            async fn remove(&self, key: &str) -> crate::store::Result<()> {
                self.data.remove(key);
                Ok(())
            }
            async fn exists(&self, key: &str) -> crate::store::Result<bool> {
                Ok(self.data.contains_key(key))
            }
        }

        // This test should use a runtime to be async, but for now we'll test the sync parts
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = TestStore::default();
            let sync_kv =
                crate::sync_kv::SyncKv::new(Some(Arc::new(Box::new(store))), "test_doc", || ())
                    .await
                    .unwrap();

            // Add metadata to sync_kv
            sync_kv.update_metadata(
                "doc_type".to_string(),
                ciborium::value::Value::Text("collaborative".to_string()),
            );
            sync_kv.update_metadata(
                "version".to_string(),
                ciborium::value::Value::Integer(2.into()),
            );

            // Create event with metadata
            let event = DocumentUpdatedEvent::new("test_doc".to_string()).with_metadata(&sync_kv);

            // Verify metadata was included
            assert_eq!(event.metadata.len(), 2);
            assert_eq!(
                event.metadata["doc_type"],
                serde_json::Value::String("collaborative".to_string())
            );
            assert_eq!(
                event.metadata["version"],
                serde_json::Value::Number(serde_json::Number::from(2))
            );
        });
    }
}
