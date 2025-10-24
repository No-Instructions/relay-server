use std::{env, sync::Arc};
use y_sweet_core::{
    store::Store,
    webhook::{WebhookConfig, WebhookConfigDocument, WebhookDispatcher},
};

/// Load webhook configs from environment variable
pub fn load_webhook_configs() -> Option<Vec<WebhookConfig>> {
    let config_json = env::var("RELAY_SERVER_WEBHOOK_CONFIG").ok()?;

    let configs: Vec<WebhookConfig> = serde_json::from_str(&config_json)
        .map_err(|e| {
            tracing::error!("Failed to parse webhook config: {}", e);
            e
        })
        .ok()?;

    Some(configs)
}

/// Load webhook configs from store or environment variable fallback
pub async fn load_webhook_configs_from_store(
    store: Option<Arc<Box<dyn Store>>>,
) -> Result<Option<Vec<WebhookConfig>>, Box<dyn std::error::Error>> {
    // First try to load from store
    if let Some(store) = store {
        let config_key = ".config/webhooks.json";

        match store.get(config_key).await {
            Ok(Some(data)) => {
                let config_str = String::from_utf8(data)?;
                let config_doc: WebhookConfigDocument = serde_json::from_str(&config_str)?;
                config_doc
                    .validate()
                    .map_err(|e| format!("Invalid webhook config: {}", e))?;
                return Ok(Some(config_doc.configs));
            }
            Ok(None) => {
                tracing::info!("No webhook configuration found in store");
            }
            Err(e) => {
                tracing::error!("Failed to load webhook config from store: {}", e);
                return Err(e.into());
            }
        }
    }

    // Fallback to environment variable
    Ok(load_webhook_configs())
}

#[deprecated(note = "Use load_webhook_configs() instead")]
pub fn create_webhook_dispatcher() -> Option<WebhookDispatcher> {
    let configs = load_webhook_configs()?;

    WebhookDispatcher::new(configs)
        .map_err(|e| {
            tracing::error!("Failed to create webhook dispatcher: {}", e);
            e
        })
        .ok()
}

/// Set webhook configuration in the store
pub async fn set_webhook_config_in_store(
    store: Arc<Box<dyn Store>>,
    configs: Vec<WebhookConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_doc = WebhookConfigDocument { configs };
    let config_json = serde_json::to_string(&config_doc)?;

    // Use the same key as the loader
    let config_key = ".config/webhooks.json";

    store.set(config_key, config_json.into_bytes()).await?;
    println!("Webhook configuration saved to store");
    Ok(())
}
