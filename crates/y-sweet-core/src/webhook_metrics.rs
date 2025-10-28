use prometheus::{CounterVec, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry};
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub struct WebhookMetrics {
    // Webhook-specific metrics
    pub webhook_requests_total: CounterVec,
    pub webhook_request_duration_seconds: HistogramVec,
    pub webhook_queue_length: GaugeVec,
    pub webhook_retry_attempts_total: CounterVec,
    pub webhook_active_dispatchers: GaugeVec,
    pub webhook_config_reloads_total: CounterVec,

    // WebSocket metrics
    pub websocket_connections: GaugeVec,

    // Event system metrics
    pub events_created_total: CounterVec,
    pub events_dispatched_total: CounterVec,
    pub events_delivered_total: CounterVec,
    pub event_updates_merged_total: CounterVec,
    pub sync_protocol_connections: GaugeVec,
    pub sync_protocol_subscriptions_by_channel: GaugeVec,
    pub debounced_queue_length: GaugeVec,

    // Authentication & Security metrics
    pub auth_failures_total: CounterVec,
    pub token_expired_total: CounterVec,
    pub permission_denied_total: CounterVec,
    pub missing_token_total: CounterVec,
}

static WEBHOOK_METRICS: OnceLock<Result<Arc<WebhookMetrics>, prometheus::Error>> = OnceLock::new();

impl WebhookMetrics {
    pub fn new() -> Result<Arc<Self>, prometheus::Error> {
        match WEBHOOK_METRICS
            .get_or_init(|| Self::new_with_registry(prometheus::default_registry()))
        {
            Ok(metrics) => Ok(metrics.clone()),
            Err(e) => Err(prometheus::Error::Msg(e.to_string())),
        }
    }

    pub fn new_with_registry(registry: &Registry) -> Result<Arc<Self>, prometheus::Error> {
        let webhook_requests_total = CounterVec::new(
            Opts::new(
                "relay_server_webhook_requests_total",
                "Total number of webhook requests sent",
            ),
            &["prefix", "status"],
        )?;
        registry.register(Box::new(webhook_requests_total.clone()))?;

        let webhook_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "relay_server_webhook_request_duration_seconds",
                "Duration of webhook HTTP requests in seconds",
            ),
            &["prefix", "status"],
        )?;
        registry.register(Box::new(webhook_request_duration_seconds.clone()))?;

        let webhook_queue_length = GaugeVec::new(
            Opts::new(
                "relay_server_webhook_queue_length",
                "Current number of documents in webhook queues",
            ),
            &["prefix"],
        )?;
        registry.register(Box::new(webhook_queue_length.clone()))?;

        let webhook_retry_attempts_total = CounterVec::new(
            Opts::new(
                "relay_server_webhook_retry_attempts_total",
                "Total number of webhook retry attempts",
            ),
            &["prefix"],
        )?;
        registry.register(Box::new(webhook_retry_attempts_total.clone()))?;

        let webhook_active_dispatchers = GaugeVec::new(
            Opts::new(
                "relay_server_webhook_active_dispatchers",
                "Number of active webhook dispatchers",
            ),
            &["prefix"],
        )?;
        registry.register(Box::new(webhook_active_dispatchers.clone()))?;

        let webhook_config_reloads_total = CounterVec::new(
            Opts::new(
                "relay_server_webhook_config_reloads_total",
                "Total number of webhook configuration reloads",
            ),
            &["status"],
        )?;
        registry.register(Box::new(webhook_config_reloads_total.clone()))?;

        let websocket_connections = GaugeVec::new(
            Opts::new(
                "relay_server_websocket_connections",
                "Number of active WebSocket connections for event streaming",
            ),
            &["prefix", "channel"],
        )?;
        registry.register(Box::new(websocket_connections.clone()))?;

        // Event system metrics
        let events_created_total = CounterVec::new(
            Opts::new(
                "relay_server_events_created_total",
                "Total number of events created",
            ),
            &["event_type"],
        )?;
        registry.register(Box::new(events_created_total.clone()))?;

        let events_dispatched_total = CounterVec::new(
            Opts::new(
                "relay_server_events_dispatched_total",
                "Total number of events dispatched to senders",
            ),
            &["event_type", "sender_type"],
        )?;
        registry.register(Box::new(events_dispatched_total.clone()))?;

        let events_delivered_total = CounterVec::new(
            Opts::new(
                "relay_server_events_delivered_total",
                "Total number of events successfully delivered",
            ),
            &["event_type", "transport"],
        )?;
        registry.register(Box::new(events_delivered_total.clone()))?;

        let event_updates_merged_total = CounterVec::new(
            Opts::new(
                "relay_server_event_updates_merged_total",
                "Total number of Yjs updates merged in events",
            ),
            &[], // No labels to avoid high cardinality
        )?;
        registry.register(Box::new(event_updates_merged_total.clone()))?;

        let sync_protocol_connections = GaugeVec::new(
            Opts::new(
                "relay_server_sync_protocol_connections_total",
                "Total number of active sync protocol connections across all documents",
            ),
            &[], // Aggregate across all documents
        )?;
        registry.register(Box::new(sync_protocol_connections.clone()))?;

        let sync_protocol_subscriptions_by_channel = GaugeVec::new(
            Opts::new(
                "relay_server_sync_protocol_subscriptions_by_channel",
                "Number of sync protocol event subscriptions per channel",
            ),
            &["channel"], // Track subscriptions per channel/document
        )?;
        registry.register(Box::new(sync_protocol_subscriptions_by_channel.clone()))?;

        let debounced_queue_length = GaugeVec::new(
            Opts::new(
                "relay_server_debounced_queue_length",
                "Number of documents with pending debounced events",
            ),
            &["queue_type"],
        )?;
        registry.register(Box::new(debounced_queue_length.clone()))?;

        // Authentication & Security metrics
        let auth_failures_total = CounterVec::new(
            Opts::new(
                "relay_server_auth_failures_total",
                "Total number of authentication failures",
            ),
            &["error_type", "endpoint", "method"],
        )?;
        registry.register(Box::new(auth_failures_total.clone()))?;

        let token_expired_total = CounterVec::new(
            Opts::new(
                "relay_server_token_expired_total",
                "Total number of token expiration events",
            ),
            &["token_type", "endpoint"],
        )?;
        registry.register(Box::new(token_expired_total.clone()))?;

        let permission_denied_total = CounterVec::new(
            Opts::new(
                "relay_server_permission_denied_total",
                "Total number of authorization failures after successful token verification",
            ),
            &["resource_type", "action", "endpoint"],
        )?;
        registry.register(Box::new(permission_denied_total.clone()))?;

        let missing_token_total = CounterVec::new(
            Opts::new(
                "relay_server_missing_token_total",
                "Total number of requests with missing authentication tokens",
            ),
            &["endpoint", "auth_required"],
        )?;
        registry.register(Box::new(missing_token_total.clone()))?;

        Ok(Arc::new(Self {
            webhook_requests_total,
            webhook_request_duration_seconds,
            webhook_queue_length,
            webhook_retry_attempts_total,
            webhook_active_dispatchers,
            webhook_config_reloads_total,
            websocket_connections,
            events_created_total,
            events_dispatched_total,
            events_delivered_total,
            event_updates_merged_total,
            sync_protocol_connections,
            sync_protocol_subscriptions_by_channel,
            debounced_queue_length,
            auth_failures_total,
            token_expired_total,
            permission_denied_total,
            missing_token_total,
        }))
    }

    #[cfg(test)]
    pub fn new_for_test() -> Result<Arc<Self>, prometheus::Error> {
        let registry = Registry::new();
        Self::new_with_registry(&registry)
    }

    pub fn record_webhook_request(&self, prefix: &str, status: &str, duration_seconds: f64) {
        self.webhook_requests_total
            .with_label_values(&[prefix, status])
            .inc();

        self.webhook_request_duration_seconds
            .with_label_values(&[prefix, status])
            .observe(duration_seconds);
    }

    pub fn set_queue_length(&self, prefix: &str, length: usize) {
        self.webhook_queue_length
            .with_label_values(&[prefix])
            .set(length as f64);
    }

    pub fn record_retry_attempt(&self, prefix: &str) {
        self.webhook_retry_attempts_total
            .with_label_values(&[prefix])
            .inc();
    }

    pub fn set_active_dispatchers(&self, prefix: &str, count: usize) {
        self.webhook_active_dispatchers
            .with_label_values(&[prefix])
            .set(count as f64);
    }

    pub fn record_config_reload(&self, status: &str) {
        self.webhook_config_reloads_total
            .with_label_values(&[status])
            .inc();
    }

    pub fn set_websocket_connections(&self, prefix: &str, channel: &str, count: usize) {
        self.websocket_connections
            .with_label_values(&[prefix, channel])
            .set(count as f64);
    }

    // Event system metrics methods
    pub fn record_event_created(&self, event_type: &str) {
        self.events_created_total
            .with_label_values(&[event_type])
            .inc();
    }

    pub fn record_event_dispatched(&self, event_type: &str, sender_type: &str) {
        self.events_dispatched_total
            .with_label_values(&[event_type, sender_type])
            .inc();
    }

    pub fn record_event_delivered(&self, event_type: &str, transport: &str) {
        self.events_delivered_total
            .with_label_values(&[event_type, transport])
            .inc();
    }

    pub fn record_updates_merged(&self, count: usize) {
        self.event_updates_merged_total
            .with_label_values(&[])
            .inc_by(count as f64);
    }

    pub fn set_sync_protocol_connections(&self, count: usize) {
        self.sync_protocol_connections
            .with_label_values(&[])
            .set(count as f64);
    }

    pub fn set_sync_protocol_subscriptions_by_channel(&self, channel: &str, count: usize) {
        self.sync_protocol_subscriptions_by_channel
            .with_label_values(&[channel])
            .set(count as f64);
    }

    pub fn set_debounced_queue_length(&self, queue_type: &str, length: usize) {
        self.debounced_queue_length
            .with_label_values(&[queue_type])
            .set(length as f64);
    }

    // Authentication & Security metrics methods
    pub fn record_auth_failure(&self, error_type: &str, endpoint: &str, method: &str) {
        self.auth_failures_total
            .with_label_values(&[error_type, endpoint, method])
            .inc();
    }

    pub fn record_token_expired(&self, token_type: &str, endpoint: &str) {
        self.token_expired_total
            .with_label_values(&[token_type, endpoint])
            .inc();
    }

    pub fn record_permission_denied(&self, resource_type: &str, action: &str, endpoint: &str) {
        self.permission_denied_total
            .with_label_values(&[resource_type, action, endpoint])
            .inc();
    }

    pub fn record_missing_token(&self, endpoint: &str, auth_required: &str) {
        self.missing_token_total
            .with_label_values(&[endpoint, auth_required])
            .inc();
    }
}

impl Default for WebhookMetrics {
    fn default() -> Self {
        Self::new()
            .expect("Failed to create webhook metrics")
            .as_ref()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_protocol_subscription_metrics() {
        let metrics = WebhookMetrics::new_for_test().unwrap();

        // Test setting subscriptions for different channels
        metrics.set_sync_protocol_subscriptions_by_channel("doc_123", 2);
        metrics.set_sync_protocol_subscriptions_by_channel("doc_456", 1);
        metrics.set_sync_protocol_subscriptions_by_channel("doc_789", 3);

        // Test removing subscriptions (setting to 0)
        metrics.set_sync_protocol_subscriptions_by_channel("doc_456", 0);

        // Test that we can call the metric method without panicking
        // (In real usage, these would be retrieved by Prometheus)
        assert!(true);
    }

    #[test]
    fn test_auth_failure_metrics() {
        let metrics = WebhookMetrics::new_for_test().unwrap();

        // Record some auth failures
        metrics.record_auth_failure("invalid_signature", "websocket_upgrade", "GET");
        metrics.record_auth_failure("expired", "document_access", "POST");

        // Verify metrics were recorded
        let auth_failures = metrics
            .auth_failures_total
            .with_label_values(&["invalid_signature", "websocket_upgrade", "GET"])
            .get();
        assert_eq!(auth_failures, 1.0);

        let expired_failures = metrics
            .auth_failures_total
            .with_label_values(&["expired", "document_access", "POST"])
            .get();
        assert_eq!(expired_failures, 1.0);
    }

    #[test]
    fn test_token_expired_metrics() {
        let metrics = WebhookMetrics::new_for_test().unwrap();

        // Record token expiration
        metrics.record_token_expired("websocket_connection", "websocket_upgrade");
        metrics.record_token_expired("api_token", "file_download");

        // Verify metrics were recorded
        let websocket_expired = metrics
            .token_expired_total
            .with_label_values(&["websocket_connection", "websocket_upgrade"])
            .get();
        assert_eq!(websocket_expired, 1.0);

        let api_expired = metrics
            .token_expired_total
            .with_label_values(&["api_token", "file_download"])
            .get();
        assert_eq!(api_expired, 1.0);
    }

    #[test]
    fn test_permission_denied_metrics() {
        let metrics = WebhookMetrics::new_for_test().unwrap();

        // Record permission denied events
        metrics.record_permission_denied("document", "write", "document_upload");
        metrics.record_permission_denied("file", "read", "file_download");

        // Verify metrics were recorded
        let doc_denied = metrics
            .permission_denied_total
            .with_label_values(&["document", "write", "document_upload"])
            .get();
        assert_eq!(doc_denied, 1.0);

        let file_denied = metrics
            .permission_denied_total
            .with_label_values(&["file", "read", "file_download"])
            .get();
        assert_eq!(file_denied, 1.0);
    }

    #[test]
    fn test_missing_token_metrics() {
        let metrics = WebhookMetrics::new_for_test().unwrap();

        // Record missing token events
        metrics.record_missing_token("websocket_upgrade", "true");
        metrics.record_missing_token("document_access", "false");

        // Verify metrics were recorded
        let required_missing = metrics
            .missing_token_total
            .with_label_values(&["websocket_upgrade", "true"])
            .get();
        assert_eq!(required_missing, 1.0);

        let optional_missing = metrics
            .missing_token_total
            .with_label_values(&["document_access", "false"])
            .get();
        assert_eq!(optional_missing, 1.0);
    }

    #[test]
    fn test_auth_error_metric_labels() {
        use crate::auth::AuthError;

        // Test that AuthError to_metric_label method works correctly
        assert_eq!(AuthError::InvalidToken.to_metric_label(), "invalid_format");
        assert_eq!(AuthError::Expired.to_metric_label(), "expired");
        assert_eq!(
            AuthError::InvalidSignature.to_metric_label(),
            "invalid_signature"
        );
        assert_eq!(AuthError::KeyMismatch.to_metric_label(), "key_mismatch");
        assert_eq!(
            AuthError::InvalidResource.to_metric_label(),
            "invalid_resource"
        );
    }
}
