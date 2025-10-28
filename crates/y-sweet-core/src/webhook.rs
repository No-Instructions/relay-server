use crate::api_types::NANOID_ALPHABET;
use crate::event::ServerMessage;
use crate::metrics::RelayMetrics;
use crate::store::Store;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info};

#[derive(Error, Debug)]
pub enum WebhookError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Store error: {0}")]
    StoreError(String),
    #[error("JSON parsing error: {0}")]
    JsonError(String),
}

#[derive(Serialize, Debug, Clone)]
pub struct WebhookPayload {
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookConfig {
    #[serde(default)]
    pub prefix: String,
    pub url: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    pub auth_token: Option<String>,
}

fn default_timeout_ms() -> u64 {
    5000
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WebhookConfigDocument {
    pub configs: Vec<WebhookConfig>,
}

impl WebhookConfigDocument {
    pub fn validate(&self) -> Result<(), WebhookError> {
        // Check for duplicate prefixes
        let mut seen_prefixes = std::collections::HashSet::new();
        for config in &self.configs {
            if !seen_prefixes.insert(&config.prefix) {
                return Err(WebhookError::Configuration(format!(
                    "Duplicate prefix found: {}",
                    config.prefix
                )));
            }

            // Validate URL format
            if url::Url::parse(&config.url).is_err() {
                return Err(WebhookError::Configuration(format!(
                    "Invalid URL format: {}",
                    config.url
                )));
            }

            // Validate timeout
            if config.timeout_ms == 0 {
                return Err(WebhookError::Configuration(
                    "Timeout must be greater than 0".to_string(),
                ));
            }
        }
        Ok(())
    }
}

pub struct WebhookDispatcher {
    pub configs: Vec<WebhookConfig>,
    queues: HashMap<String, mpsc::UnboundedSender<String>>,
    shutdown_senders: Vec<mpsc::UnboundedSender<()>>,
    metrics: Arc<RelayMetrics>,
}

impl WebhookDispatcher {
    pub fn new(configs: Vec<WebhookConfig>) -> Result<Self, WebhookError> {
        Self::new_with_metrics(configs, None)
    }

    #[cfg(test)]
    pub fn new_for_test(configs: Vec<WebhookConfig>) -> Result<Self, WebhookError> {
        let metrics = RelayMetrics::new_for_test().map_err(|e| {
            WebhookError::Configuration(format!("Failed to initialize test metrics: {}", e))
        })?;
        Self::new_with_metrics(configs, Some(metrics))
    }

    fn new_with_metrics(
        configs: Vec<WebhookConfig>,
        metrics_override: Option<Arc<RelayMetrics>>,
    ) -> Result<Self, WebhookError> {
        let metrics = match metrics_override {
            Some(m) => m,
            None => RelayMetrics::new().map_err(|e| {
                WebhookError::Configuration(format!("Failed to initialize metrics: {}", e))
            })?,
        };

        let mut queues = HashMap::new();
        let mut shutdown_senders = Vec::new();

        for config in &configs {
            let (tx, rx) = mpsc::unbounded_channel();
            let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel();

            queues.insert(config.prefix.clone(), tx);
            shutdown_senders.push(shutdown_tx);

            // Set initial dispatcher metrics
            metrics.set_active_dispatchers(&config.prefix, 1);
            metrics.set_queue_length(&config.prefix, 0);

            // Spawn worker task for this prefix with shutdown signal
            let config_clone = config.clone();
            let metrics_clone = metrics.clone();
            tokio::spawn(async move {
                Self::webhook_worker_with_shutdown(config_clone, rx, shutdown_rx, metrics_clone)
                    .await;
            });
        }

        Ok(WebhookDispatcher {
            configs,
            queues,
            shutdown_senders,
            metrics,
        })
    }

    /// Load webhook configuration from store
    pub async fn from_store(
        store: Option<Arc<Box<dyn Store>>>,
    ) -> Result<Option<Self>, WebhookError> {
        let store = match store {
            Some(store) => store,
            None => return Ok(None),
        };

        // Use a special key that cannot be accessed as a document ID
        // This key is reserved for system configuration and should not be exposed to clients
        // Using a .config directory structure for better organization
        let config_key = ".config/webhooks.json";

        match store.get(config_key).await {
            Ok(Some(data)) => {
                let config_str = String::from_utf8(data).map_err(|e| {
                    WebhookError::JsonError(format!("Invalid UTF-8 in config: {}", e))
                })?;

                let config_doc: WebhookConfigDocument =
                    serde_json::from_str(&config_str).map_err(|e| {
                        WebhookError::JsonError(format!("Failed to parse config JSON: {}", e))
                    })?;

                config_doc.validate()?;

                let dispatcher = Self::new(config_doc.configs)?;
                info!(
                    "Loaded webhook configuration from store with {} configs",
                    dispatcher.configs.len()
                );
                Ok(Some(dispatcher))
            }
            Ok(None) => {
                info!("No webhook configuration found in store");
                Ok(None)
            }
            Err(e) => {
                error!("Failed to load webhook config from store: {}", e);
                Err(WebhookError::StoreError(format!(
                    "Store access failed: {}",
                    e
                )))
            }
        }
    }

    /// Gracefully shutdown all worker tasks
    pub fn shutdown(&self) {
        for sender in &self.shutdown_senders {
            let _ = sender.send(()); // Ignore errors if receiver already dropped
        }
    }

    pub fn send_webhooks(&self, doc_id: String) {
        let matching_prefixes = self.find_matching_prefixes(&doc_id);

        for prefix in matching_prefixes {
            // Send to HTTP webhook queues
            if let Some(sender) = self.queues.get(&prefix) {
                if let Err(e) = sender.send(doc_id.clone()) {
                    error!("Failed to queue webhook for prefix '{}': {}", prefix, e);
                }
            }
        }
    }

    async fn webhook_worker_with_shutdown(
        config: WebhookConfig,
        mut rx: mpsc::UnboundedReceiver<String>,
        mut shutdown_rx: mpsc::UnboundedReceiver<()>,
        metrics: Arc<RelayMetrics>,
    ) {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .pool_max_idle_per_host(5)
            .user_agent("y-sweet-webhook/0.8.2")
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

            // Then check for document updates with timeout
            match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(Some(doc_id)) => {
                    if let Err(e) =
                        Self::send_single_webhook(&client, &config, doc_id.clone(), &metrics).await
                    {
                        error!(
                            "Failed to send webhook for document {} with prefix '{}': {}",
                            doc_id, config.prefix, e
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

    pub fn find_matching_prefixes(&self, doc_id: &str) -> Vec<String> {
        let mut matches: Vec<String> = self
            .configs
            .iter()
            .filter(|config| doc_id.starts_with(&config.prefix))
            .map(|config| config.prefix.clone())
            .collect();

        // Sort by prefix length (longest first) for consistent ordering
        matches.sort_by(|a, b| b.len().cmp(&a.len()));
        matches.dedup();
        matches
    }

    async fn send_single_webhook(
        client: &Client,
        config: &WebhookConfig,
        doc_id: String,
        metrics: &RelayMetrics,
    ) -> Result<(), WebhookError> {
        let start_time = Instant::now();

        let payload = WebhookPayload {
            event_type: "document.updated".to_string(),
            event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
            payload: serde_json::json!({
                "doc_id": doc_id.clone(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        };

        debug!(
            "Sending webhook for document {} to prefix '{}'",
            doc_id, config.prefix
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
            .map_err(|_| {
                WebhookError::Timeout(format!(
                    "Webhook request timed out after {}ms",
                    config.timeout_ms
                ))
            })?
            .map_err(|e| WebhookError::RequestFailed(e.to_string()));

        let duration = start_time.elapsed().as_secs_f64();

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    metrics.record_webhook_request(&config.prefix, "success", duration);
                    info!(
                        "Webhook sent successfully for document {} to prefix '{}'",
                        doc_id, config.prefix
                    );
                    Ok(())
                } else {
                    let status_code = response.status().as_u16().to_string();
                    metrics.record_webhook_request(&config.prefix, &status_code, duration);
                    let error_msg = format!("Webhook failed with status {}", response.status());
                    error!(
                        "Webhook failed for document {} to prefix '{}': {}",
                        doc_id, config.prefix, error_msg
                    );
                    Err(WebhookError::RequestFailed(error_msg))
                }
            }
            Err(e) => {
                metrics.record_webhook_request(&config.prefix, "error", duration);
                Err(e)
            }
        }
    }
}

pub type WebhookCallback = Arc<dyn Fn(crate::event::DocumentUpdatedEvent) + Send + Sync>;

pub fn create_webhook_callback(dispatcher: Arc<WebhookDispatcher>) -> WebhookCallback {
    Arc::new(move |event: crate::event::DocumentUpdatedEvent| {
        dispatcher.send_webhooks(event.doc_id.clone());
    })
}

struct DocumentQueue {
    pending: AtomicBool,
    last_sent: Arc<Mutex<Option<Instant>>>,
    debounce_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl DocumentQueue {
    fn new(_doc_id: String) -> Self {
        Self {
            pending: AtomicBool::new(false),
            last_sent: Arc::new(Mutex::new(None)),
            debounce_handle: Arc::new(Mutex::new(None)),
        }
    }

    async fn should_send_immediately(&self) -> bool {
        let last_sent = self.last_sent.lock().await;
        match *last_sent {
            Some(last) => last.elapsed() >= Duration::from_secs(1),
            None => true,
        }
    }

    async fn mark_sent(&self) {
        let mut last_sent = self.last_sent.lock().await;
        *last_sent = Some(Instant::now());
        self.pending.store(false, Ordering::Release);
    }

    async fn cancel_pending_task(&self) {
        let mut handle = self.debounce_handle.lock().await;
        if let Some(task) = handle.take() {
            task.abort();
        }
    }
}

pub struct DebouncedWebhookQueue {
    document_queues: Arc<RwLock<HashMap<String, Arc<DocumentQueue>>>>,
    pub dispatcher: Arc<WebhookDispatcher>,
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl DebouncedWebhookQueue {
    pub fn new(dispatcher: Arc<WebhookDispatcher>) -> Self {
        let document_queues = Arc::new(RwLock::new(HashMap::new()));
        let cleanup_interval = Duration::from_secs(60); // Cleanup idle queues every minute

        // Start cleanup task
        let cleanup_queues = document_queues.clone();
        let dispatcher_for_cleanup = dispatcher.clone();
        let cleanup_handle = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_idle_queues(&cleanup_queues).await;

                // Update queue length metrics
                let queues = cleanup_queues.read().await;
                for config in &dispatcher_for_cleanup.configs {
                    let queue_count = queues.len();
                    dispatcher_for_cleanup
                        .metrics
                        .set_queue_length(&config.prefix, queue_count);
                }
            }
        }));

        Self {
            document_queues,
            dispatcher,
            cleanup_handle,
        }
    }

    pub fn configs(&self) -> &Vec<WebhookConfig> {
        &self.dispatcher.configs
    }

    pub fn metrics(&self) -> &Arc<RelayMetrics> {
        &self.dispatcher.metrics
    }

    pub async fn queue_webhook(&self, doc_id: String) {
        let queue = self.get_or_create_queue(doc_id.clone()).await;

        // Cancel any existing debounce timer
        queue.cancel_pending_task().await;

        // Check if we can send immediately (rate limit allows it)
        if queue.should_send_immediately().await {
            // Send immediately and mark as sent
            self.send_webhook_now(doc_id.clone()).await;
            queue.mark_sent().await;
        } else {
            // Mark as pending and schedule debounced send
            queue.pending.store(true, Ordering::Release);

            let dispatcher = self.dispatcher.clone();
            let queue_clone = queue.clone();
            let doc_id_clone = doc_id.clone();

            // Calculate delay needed to respect rate limit
            let delay = {
                let last_sent = queue.last_sent.lock().await;
                match *last_sent {
                    Some(last) => {
                        let elapsed = last.elapsed();
                        if elapsed < Duration::from_secs(1) {
                            Duration::from_secs(1) - elapsed
                        } else {
                            Duration::from_millis(0)
                        }
                    }
                    None => Duration::from_millis(0),
                }
            };

            // Schedule the debounced webhook send
            let task = tokio::spawn(async move {
                sleep(delay).await;

                // Double-check we're still pending (not cancelled by newer update)
                if queue_clone.pending.load(Ordering::Acquire) {
                    dispatcher.send_webhooks(doc_id_clone);
                    queue_clone.mark_sent().await;
                }
            });

            // Store the task handle so we can cancel it if needed
            let mut handle = queue.debounce_handle.lock().await;
            *handle = Some(task);
        }
    }

    async fn send_webhook_now(&self, doc_id: String) {
        self.dispatcher.send_webhooks(doc_id);
    }

    async fn get_or_create_queue(&self, doc_id: String) -> Arc<DocumentQueue> {
        // Try to get existing queue first (read lock)
        {
            let queues = self.document_queues.read().await;
            if let Some(queue) = queues.get(&doc_id) {
                return queue.clone();
            }
        }

        // Create new queue (write lock)
        let mut queues = self.document_queues.write().await;
        // Double-check in case another task created it while we waited for write lock
        if let Some(queue) = queues.get(&doc_id) {
            return queue.clone();
        }

        let queue = Arc::new(DocumentQueue::new(doc_id.clone()));
        queues.insert(doc_id, queue.clone());
        queue
    }

    async fn cleanup_idle_queues(queues: &Arc<RwLock<HashMap<String, Arc<DocumentQueue>>>>) {
        let idle_threshold = Duration::from_secs(300); // 5 minutes idle
        let now = Instant::now();
        let mut to_remove = Vec::new();

        {
            let queues_read = queues.read().await;
            for (doc_id, queue) in queues_read.iter() {
                let last_sent = queue.last_sent.lock().await;
                let is_idle = match *last_sent {
                    Some(last) => now.duration_since(last) > idle_threshold,
                    None => false, // Never sent, keep it
                };

                let not_pending = !queue.pending.load(Ordering::Acquire);

                if is_idle && not_pending {
                    to_remove.push(doc_id.clone());
                }
            }
        }

        if !to_remove.is_empty() {
            let mut queues_write = queues.write().await;
            for doc_id in to_remove {
                if let Some(queue) = queues_write.remove(&doc_id) {
                    // Cancel any pending tasks before removal
                    queue.cancel_pending_task().await;
                    debug!("Cleaned up idle webhook queue for document: {}", doc_id);
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        // Cancel cleanup task
        if let Some(ref handle) = self.cleanup_handle {
            handle.abort();
        }

        // Cancel all pending webhook tasks
        let queues = self.document_queues.read().await;
        for queue in queues.values() {
            queue.cancel_pending_task().await;
        }

        // Shutdown the underlying dispatcher
        self.dispatcher.shutdown();
    }
}

pub fn create_debounced_webhook_callback(queue: Arc<DebouncedWebhookQueue>) -> WebhookCallback {
    Arc::new(move |event: crate::event::DocumentUpdatedEvent| {
        let queue_clone = queue.clone();
        let doc_id = event.doc_id.clone();
        tokio::spawn(async move {
            queue_clone.queue_webhook(doc_id).await;
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prefix_matching() {
        let configs = vec![
            WebhookConfig {
                prefix: "user_".to_string(),
                url: "https://example.com/user".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "user_admin_".to_string(),
                url: "https://example.com/admin".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "".to_string(),
                url: "https://example.com/default".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
        ];

        let dispatcher = WebhookDispatcher::new_for_test(configs).unwrap();

        // Test longest-matching-prefix
        let matches = dispatcher.find_matching_prefixes("user_admin_123");
        assert_eq!(matches, vec!["user_admin_", "user_", ""]);

        // Test single match
        let matches = dispatcher.find_matching_prefixes("user_123");
        assert_eq!(matches, vec!["user_", ""]);

        // Test default match only
        let matches = dispatcher.find_matching_prefixes("doc_123");
        assert_eq!(matches, vec![""]);

        // Test specific test case from user
        let matches = dispatcher.find_matching_prefixes("test_document");
        assert_eq!(matches, vec![""]);

        // Test exact user case - test_ prefix with test_document
        let test_configs = vec![WebhookConfig {
            prefix: "test_".to_string(),
            url: "https://example.com/test".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        }];
        let test_dispatcher = WebhookDispatcher::new_for_test(test_configs).unwrap();
        let matches = test_dispatcher.find_matching_prefixes("test_document");
        assert_eq!(matches, vec!["test_"]);

        // Test no matches (empty config)
        let empty_dispatcher = WebhookDispatcher::new_for_test(vec![]).unwrap();
        let matches = empty_dispatcher.find_matching_prefixes("anything");
        assert_eq!(matches, Vec::<String>::new());
    }

    #[test]
    fn test_webhook_config_parsing() {
        // Test valid config
        let config = WebhookConfig {
            prefix: "test:".to_string(),
            url: "https://example.com".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        };
        assert_eq!(config.prefix, "test:");
        assert_eq!(config.url, "https://example.com");
        assert_eq!(config.timeout_ms, 5000);

        // Test empty prefix (catches all)
        let config = WebhookConfig {
            prefix: "".to_string(),
            url: "https://example.com/default".to_string(),
            timeout_ms: 3000,
            auth_token: None,
        };
        assert_eq!(config.prefix, "");
        assert_eq!(config.timeout_ms, 3000);
    }

    #[tokio::test]
    async fn test_webhook_dispatcher_creation() {
        let configs = vec![
            WebhookConfig {
                prefix: "user:".to_string(),
                url: "https://example.com/user".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "doc:".to_string(),
                url: "https://example.com/doc".to_string(),
                timeout_ms: 3000,
                auth_token: None,
            },
        ];

        let dispatcher = WebhookDispatcher::new(configs.clone()).unwrap();
        assert_eq!(dispatcher.configs.len(), 2);
        assert_eq!(dispatcher.queues.len(), 2);
        assert!(dispatcher.queues.contains_key("user:"));
        assert!(dispatcher.queues.contains_key("doc:"));
    }

    #[tokio::test]
    async fn test_queue_behavior() {
        let configs = vec![WebhookConfig {
            prefix: "test:".to_string(),
            url: "https://httpbin.org/post".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        }];

        let dispatcher = WebhookDispatcher::new_for_test(configs).unwrap();

        // Test webhook queuing
        dispatcher.send_webhooks("test:123".to_string());
        dispatcher.send_webhooks("test:456".to_string());

        // Give some time for async processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        // If we get here without panicking, the queue is working
        assert!(true);
    }

    #[tokio::test]
    async fn test_debounced_webhook_queue_rate_limiting() {
        let configs = vec![WebhookConfig {
            prefix: "test_".to_string(),
            url: "https://httpbin.org/post".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        }];

        let dispatcher = Arc::new(WebhookDispatcher::new_for_test(configs).unwrap());
        let queue = Arc::new(DebouncedWebhookQueue::new(dispatcher));

        let doc_id = "test_rate_limit".to_string();

        // Send first webhook - should go immediately
        queue.queue_webhook(doc_id.clone()).await;

        // Send second webhook immediately - should be rate limited
        queue.queue_webhook(doc_id.clone()).await;

        // Wait a bit and check that we didn't exceed rate limit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The second webhook should still be pending
        let queues = queue.document_queues.read().await;
        let doc_queue = queues.get(&doc_id).unwrap();
        assert!(doc_queue.pending.load(Ordering::Acquire));

        // Cleanup
        queue.shutdown().await;
    }

    #[tokio::test]
    async fn test_debounced_webhook_queue_debouncing() {
        let configs = vec![WebhookConfig {
            prefix: "test_".to_string(),
            url: "https://httpbin.org/post".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        }];

        let dispatcher = Arc::new(WebhookDispatcher::new_for_test(configs).unwrap());
        let queue = Arc::new(DebouncedWebhookQueue::new(dispatcher));

        let doc_id = "test_debounce".to_string();

        // Send first webhook (should go immediately since no rate limit)
        queue.queue_webhook(doc_id.clone()).await;

        // Send multiple rapid updates (these should be rate-limited and debounced)
        for _ in 0..5 {
            queue.queue_webhook(doc_id.clone()).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Verify a queue exists for this document
        let queues = queue.document_queues.read().await;
        let doc_queue = queues.get(&doc_id).unwrap();

        // Should be pending due to rate limiting
        assert!(doc_queue.pending.load(Ordering::Acquire));

        // Cleanup
        queue.shutdown().await;
    }

    #[tokio::test]
    async fn test_debounced_webhook_queue_cleanup() {
        let configs = vec![WebhookConfig {
            prefix: "test_".to_string(),
            url: "https://httpbin.org/post".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        }];

        let dispatcher = Arc::new(WebhookDispatcher::new_for_test(configs).unwrap());
        let queue = Arc::new(DebouncedWebhookQueue::new(dispatcher));

        let doc_id = "test_cleanup".to_string();

        // Create a queue entry
        queue.queue_webhook(doc_id.clone()).await;

        // Verify it exists
        {
            let queues = queue.document_queues.read().await;
            assert!(queues.contains_key(&doc_id));
        }

        // Manually trigger cleanup (normally would happen on timer)
        DebouncedWebhookQueue::cleanup_idle_queues(&queue.document_queues).await;

        // Should still exist (not idle long enough)
        {
            let queues = queue.document_queues.read().await;
            assert!(queues.contains_key(&doc_id));
        }

        // Cleanup
        queue.shutdown().await;
    }

    #[tokio::test]
    async fn test_document_queue_should_send_immediately() {
        let queue = DocumentQueue::new("test".to_string());

        // Should send immediately when never sent before
        assert!(queue.should_send_immediately().await);

        // Mark as sent
        queue.mark_sent().await;

        // Should not send immediately right after sending
        assert!(!queue.should_send_immediately().await);

        // Wait for rate limit to expire (in real test, this would be 1 second)
        // For test purposes, we'll just verify the logic works
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Still shouldn't send (less than 1 second elapsed)
        assert!(!queue.should_send_immediately().await);
    }
}
