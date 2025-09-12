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
    pub debounced_queue_length: GaugeVec,
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

        let debounced_queue_length = GaugeVec::new(
            Opts::new(
                "relay_server_debounced_queue_length",
                "Number of documents with pending debounced events",
            ),
            &["queue_type"],
        )?;
        registry.register(Box::new(debounced_queue_length.clone()))?;

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
            debounced_queue_length,
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

    pub fn set_debounced_queue_length(&self, queue_type: &str, length: usize) {
        self.debounced_queue_length
            .with_label_values(&[queue_type])
            .set(length as f64);
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
