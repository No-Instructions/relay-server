use prometheus::{CounterVec, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry};
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub struct WebhookMetrics {
    pub webhook_requests_total: CounterVec,
    pub webhook_request_duration_seconds: HistogramVec,
    pub webhook_queue_length: GaugeVec,
    pub webhook_retry_attempts_total: CounterVec,
    pub webhook_active_dispatchers: GaugeVec,
    pub webhook_config_reloads_total: CounterVec,
    pub websocket_connections: GaugeVec,
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
            &["prefix", "status", "doc_id"],
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
            &["prefix", "doc_id"],
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
            &["prefix"],
        )?;
        registry.register(Box::new(websocket_connections.clone()))?;

        Ok(Arc::new(Self {
            webhook_requests_total,
            webhook_request_duration_seconds,
            webhook_queue_length,
            webhook_retry_attempts_total,
            webhook_active_dispatchers,
            webhook_config_reloads_total,
            websocket_connections,
        }))
    }

    #[cfg(test)]
    pub fn new_for_test() -> Result<Arc<Self>, prometheus::Error> {
        let registry = Registry::new();
        Self::new_with_registry(&registry)
    }

    pub fn record_webhook_request(
        &self,
        prefix: &str,
        doc_id: &str,
        status: &str,
        duration_seconds: f64,
    ) {
        self.webhook_requests_total
            .with_label_values(&[prefix, status, doc_id])
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

    pub fn record_retry_attempt(&self, prefix: &str, doc_id: &str) {
        self.webhook_retry_attempts_total
            .with_label_values(&[prefix, doc_id])
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

    pub fn set_websocket_connections(&self, prefix: &str, count: usize) {
        self.websocket_connections
            .with_label_values(&[prefix])
            .set(count as f64);
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
