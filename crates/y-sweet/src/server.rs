use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket},
        Path, Query, Request, State, WebSocketUpgrade,
    },
    http::{
        header::{HeaderMap, HeaderName, HeaderValue},
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, head, post},
    Json, Router,
};
use axum_extra::typed_header::TypedHeader;
use dashmap::{mapref::one::MappedRef, DashMap};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::mpsc::{channel, Receiver},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{span, Instrument, Level};
use url::Url;
use y_sweet_core::{
    api_types::{
        validate_doc_name, validate_file_hash, AuthDocRequest, Authorization, ClientToken,
        DocCreationRequest, DocumentVersionEntry, DocumentVersionResponse, FileDownloadUrlResponse,
        FileHistoryEntry, FileHistoryResponse, FileUploadUrlResponse, NewDocResponse,
    },
    auth::{
        Authenticator, ExpirationTimeEpochMillis, Permission, PrefixPermission,
        DEFAULT_EXPIRATION_SECONDS,
    },
    doc_connection::DocConnection,
    doc_sync::DocWithSyncKv,
    event::{
        DocumentUpdatedEvent, EventDispatcher, EventEnvelope, EventSender, ServerMessage,
        UnifiedEventDispatcher, WebSocketSender, WebhookSender,
    },
    store::Store,
    sync::awareness::Awareness,
    sync_kv::SyncKv,
    webhook::WebhookConfig,
    webhook_metrics::WebhookMetrics,
};

const PLANE_VERIFIED_USER_DATA_HEADER: &str = "x-verified-user-data";
const RELAY_SERVER_VERSION: &str = env!("GIT_VERSION");

#[derive(Clone, Debug)]
pub struct AllowedHost {
    pub host: String,
    pub scheme: String, // "http" or "https"
}

fn current_time_epoch_millis() -> u64 {
    let now = std::time::SystemTime::now();
    let duration_since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    duration_since_epoch.as_millis() as u64
}

#[derive(Debug)]
pub struct AppError(StatusCode, anyhow::Error);
impl std::error::Error for AppError {}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("Something went wrong: {}", self.1)).into_response()
    }
}
impl<E> From<(StatusCode, E)> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from((status_code, err): (StatusCode, E)) -> Self {
        Self(status_code, err.into())
    }
}
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status code: {} {}", self.0, self.1)?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct FileDownloadQueryParams {
    hash: Option<String>,
}

pub struct Server {
    docs: Arc<DashMap<String, DocWithSyncKv>>,
    doc_worker_tracker: TaskTracker,
    store: Option<Arc<Box<dyn Store>>>,
    checkpoint_freq: Duration,
    authenticator: Option<Authenticator>,
    url_prefix: Option<Url>,
    allowed_hosts: Vec<AllowedHost>,
    cancellation_token: CancellationToken,
    /// Whether to garbage collect docs that are no longer in use.
    /// Disabled for single-doc mode, since we only have one doc.
    doc_gc: bool,
    event_dispatcher: Option<Arc<dyn EventDispatcher>>,
    websocket_sender: Arc<WebSocketSender>,
}

impl Server {
    pub async fn new(
        store: Option<Box<dyn Store>>,
        checkpoint_freq: Duration,
        authenticator: Option<Authenticator>,
        url_prefix: Option<Url>,
        allowed_hosts: Vec<AllowedHost>,
        cancellation_token: CancellationToken,
        doc_gc: bool,
        webhook_configs: Option<Vec<WebhookConfig>>,
    ) -> Result<Self> {
        let websocket_sender = Arc::new(WebSocketSender::new());

        let event_dispatcher = if let Some(configs) = webhook_configs {
            let metrics = WebhookMetrics::new()
                .map_err(|e| anyhow!("Failed to initialize webhook metrics: {}", e))?;

            let webhook_sender = Arc::new(
                WebhookSender::new(configs.clone(), metrics)
                    .map_err(|e| anyhow!("Failed to create webhook sender: {}", e))?,
            );

            let senders: Vec<Arc<dyn EventSender>> = vec![webhook_sender, websocket_sender.clone()];

            Some(Arc::new(UnifiedEventDispatcher::new(senders)) as Arc<dyn EventDispatcher>)
        } else {
            tracing::info!("No webhook configs provided, creating WebSocket-only event dispatcher");
            let senders: Vec<Arc<dyn EventSender>> = vec![websocket_sender.clone()];
            Some(Arc::new(UnifiedEventDispatcher::new(senders)) as Arc<dyn EventDispatcher>)
        };

        tracing::info!("Event dispatcher created successfully");

        Ok(Self {
            docs: Arc::new(DashMap::new()),
            doc_worker_tracker: TaskTracker::new(),
            store: store.map(Arc::new),
            checkpoint_freq,
            authenticator,
            url_prefix,
            allowed_hosts,
            cancellation_token,
            doc_gc,
            event_dispatcher,
            websocket_sender,
        })
    }

    pub async fn doc_exists(&self, doc_id: &str) -> bool {
        // Reject system keys
        if Self::validate_doc_id(doc_id).is_err() {
            return false;
        }
        if self.docs.contains_key(doc_id) {
            return true;
        }
        if let Some(store) = &self.store {
            store
                .exists(&format!("{}/data.ysweet", doc_id))
                .await
                .unwrap_or_default()
        } else {
            false
        }
    }

    pub async fn create_doc(&self) -> Result<String> {
        let doc_id = nanoid::nanoid!();
        self.load_doc(&doc_id, None).await?;
        tracing::info!(doc_id=?doc_id, "Created doc");
        Ok(doc_id)
    }

    pub async fn reload_webhook_config(&self) -> Result<String, anyhow::Error> {
        // For now, webhook configuration reloading is not supported with the new event system
        // This would require a more complex architecture to hot-reload the event dispatcher
        // In the meantime, server restart is required to change webhook configuration
        Err(anyhow::anyhow!(
            "Webhook configuration reloading is not yet supported with the new event system. Please restart the server to load new configuration."
        ))
    }

    fn validate_doc_id(doc_id: &str) -> Result<()> {
        // Reject system configuration paths that are reserved for internal use
        if doc_id.starts_with(".config/") || doc_id == ".config" {
            return Err(anyhow::anyhow!(
                "Document ID cannot access system configuration directory '.config'"
            ));
        }
        Ok(())
    }

    pub async fn load_doc(&self, doc_id: &str, routing_channel: Option<String>) -> Result<()> {
        Self::validate_doc_id(doc_id)?;
        let (send, recv) = channel(1024);

        // Determine routing channel: use provided channel or fallback to doc_id
        let routing_channel_name = routing_channel
            .clone()
            .unwrap_or_else(|| doc_id.to_string());

        // Create event callback with the determined routing channel
        let event_callback = {
            let event_dispatcher = self.event_dispatcher.clone();
            let routing_channel_for_callback = routing_channel_name.clone();

            if let Some(dispatcher) = event_dispatcher {
                Some(Arc::new(move |event: DocumentUpdatedEvent| {
                    // Step 1: Create the envelope with predetermined routing channel
                    let envelope = EventEnvelope::new(routing_channel_for_callback.clone(), event);

                    // Step 2: Send via dispatcher
                    dispatcher.send_event(envelope);
                }) as y_sweet_core::webhook::WebhookCallback)
            } else {
                None
            }
        };

        let dwskv = DocWithSyncKv::new(
            doc_id,
            self.store.clone(),
            move || {
                send.try_send(()).unwrap();
            },
            event_callback,
        )
        .await?;

        // If channel is provided in token, store it in document metadata
        if let Some(channel_name) = routing_channel {
            dwskv.set_channel(&channel_name);
        }

        dwskv
            .sync_kv()
            .persist()
            .await
            .map_err(|e| anyhow!("Error persisting: {:?}", e))?;

        {
            let sync_kv = dwskv.sync_kv();
            let checkpoint_freq = self.checkpoint_freq;
            let doc_id = doc_id.to_string();
            let cancellation_token = self.cancellation_token.clone();

            // Spawn a task to save the document to the store when it changes.
            self.doc_worker_tracker.spawn(
                Self::doc_persistence_worker(
                    recv,
                    sync_kv,
                    checkpoint_freq,
                    doc_id.clone(),
                    cancellation_token.clone(),
                )
                .instrument(span!(Level::INFO, "save_loop", doc_id=?doc_id)),
            );

            if self.doc_gc {
                self.doc_worker_tracker.spawn(
                    Self::doc_gc_worker(
                        self.docs.clone(),
                        doc_id.clone(),
                        checkpoint_freq,
                        cancellation_token,
                    )
                    .instrument(span!(Level::INFO, "gc_loop", doc_id=?doc_id)),
                );
            }
        }

        self.docs.insert(doc_id.to_string(), dwskv);
        Ok(())
    }

    async fn doc_gc_worker(
        docs: Arc<DashMap<String, DocWithSyncKv>>,
        doc_id: String,
        checkpoint_freq: Duration,
        cancellation_token: CancellationToken,
    ) {
        let mut checkpoints_without_refs = 0;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(checkpoint_freq) => {
                    if let Some(doc) = docs.get(&doc_id) {
                        let awareness = Arc::downgrade(&doc.awareness());
                        if awareness.strong_count() > 1 {
                            checkpoints_without_refs = 0;
                            tracing::debug!("doc is still alive - it has {} references", awareness.strong_count());
                        } else {
                            checkpoints_without_refs += 1;
                            tracing::info!("doc has only one reference, candidate for GC. checkpoints_without_refs: {}", checkpoints_without_refs);
                        }
                    } else {
                        break;
                    }

                    if checkpoints_without_refs >= 2 {
                        tracing::info!("GCing doc");
                        docs.remove(&doc_id);
                        break;
                    }
                }
                _ = cancellation_token.cancelled() => {
                    break;
                }
            };
        }
        tracing::info!("Exiting gc_loop");
    }

    async fn doc_persistence_worker(
        mut recv: Receiver<()>,
        sync_kv: Arc<SyncKv>,
        checkpoint_freq: Duration,
        doc_id: String,
        cancellation_token: CancellationToken,
    ) {
        let mut last_save = std::time::Instant::now();

        loop {
            let is_done = tokio::select! {
                v = recv.recv() => v.is_none(),
                _ = cancellation_token.cancelled() => true,
            };

            tracing::info!("Received signal. done: {}", is_done);
            let now = std::time::Instant::now();
            if !is_done && now - last_save < checkpoint_freq {
                let sleep = tokio::time::sleep(checkpoint_freq - (now - last_save));
                tokio::pin!(sleep);
                tracing::info!("Throttling.");

                loop {
                    tokio::select! {
                        _ = &mut sleep => {
                            break;
                        }
                        v = recv.recv() => {
                            tracing::info!("Received dirty while throttling.");
                            if v.is_none() {
                                break;
                            }
                        }
                        _ = cancellation_token.cancelled() => {
                            tracing::info!("Received cancellation while throttling.");
                            break;
                        }

                    }
                    tracing::info!("Done throttling.");
                }
            }
            tracing::info!("Persisting.");
            if let Err(e) = sync_kv.persist().await {
                tracing::error!(?e, "Error persisting.");
            } else {
                tracing::info!("Done persisting.");
            }
            last_save = std::time::Instant::now();

            if is_done {
                break;
            }
        }
        tracing::info!("Terminating loop for {}", doc_id);
    }

    pub async fn get_or_create_doc(
        &self,
        doc_id: &str,
    ) -> Result<MappedRef<String, DocWithSyncKv, DocWithSyncKv>> {
        if !self.docs.contains_key(doc_id) {
            tracing::info!(doc_id=?doc_id, "Loading doc");
            self.load_doc(doc_id, None).await?;
        }

        Ok(self
            .docs
            .get(doc_id)
            .ok_or_else(|| anyhow!("Failed to get-or-create doc"))?
            .map(|d| d))
    }

    pub async fn get_or_create_doc_with_channel(
        &self,
        doc_id: &str,
        routing_channel: Option<String>,
    ) -> Result<MappedRef<String, DocWithSyncKv, DocWithSyncKv>> {
        if !self.docs.contains_key(doc_id) {
            tracing::info!(doc_id=?doc_id, channel=?routing_channel, "Loading doc with channel");
            self.load_doc(doc_id, routing_channel).await?;
        }

        Ok(self
            .docs
            .get(doc_id)
            .ok_or_else(|| anyhow!("Failed to get-or-create doc"))?
            .map(|d| d))
    }

    pub fn check_auth(
        &self,
        auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    ) -> Result<(), AppError> {
        if let Some(auth) = &self.authenticator {
            if let Some(TypedHeader(headers::Authorization(bearer))) = auth_header {
                if let Ok(()) =
                    auth.verify_server_token(bearer.token(), current_time_epoch_millis())
                {
                    return Ok(());
                }
            }
            Err((StatusCode::UNAUTHORIZED, anyhow!("Unauthorized.")))?
        } else {
            Ok(())
        }
    }

    pub async fn redact_error_middleware(req: Request, next: Next) -> impl IntoResponse {
        let resp = next.run(req).await;
        if resp.status().is_server_error() || resp.status().is_client_error() {
            // If we should redact errors, copy over only the status code and
            // not the response body.
            return resp.status().into_response();
        }
        resp
    }

    pub async fn version_header_middleware(req: Request, next: Next) -> impl IntoResponse {
        let mut resp = next.run(req).await;
        resp.headers_mut().insert(
            HeaderName::from_static("relay-server-version"),
            HeaderValue::from_static(RELAY_SERVER_VERSION),
        );
        resp
    }

    pub fn routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ready", get(ready))
            .route("/check_store", post(check_store))
            .route("/check_store", get(check_store_deprecated))
            .route("/doc/ws/:doc_id", get(handle_socket_upgrade_deprecated))
            .route("/doc/new", post(new_doc))
            .route("/doc/:doc_id/auth", post(auth_doc))
            .route("/doc/:doc_id/as-update", get(get_doc_as_update_deprecated))
            .route("/doc/:doc_id/update", post(update_doc_deprecated))
            .route("/d/:doc_id/as-update", get(get_doc_as_update))
            .route("/d/:doc_id/update", post(update_doc))
            .route("/d/:doc_id/versions", get(handle_doc_versions))
            .route(
                "/d/:doc_id/ws/:doc_id2",
                get(handle_socket_upgrade_full_path),
            )
            // File endpoints with doc_id in path
            .route("/f/:doc_id/upload-url", post(handle_file_upload_url))
            .route("/f/:doc_id/download-url", get(handle_file_download_url))
            .route("/f/:doc_id/history", get(handle_file_history))
            .route("/f/:doc_id", delete(handle_file_delete))
            .route("/f/:doc_id/:hash", delete(handle_file_delete_by_hash))
            .route("/f/:doc_id", head(handle_file_head))
            .route("/webhook/reload", post(reload_webhook_config_endpoint))
            .route("/e/:prefix/ws", get(handle_event_websocket_upgrade))
            .with_state(self.clone())
    }

    pub fn single_doc_routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ws/:doc_id", get(handle_socket_upgrade_single))
            .route("/as-update", get(get_doc_as_update_single))
            .route("/update", post(update_doc_single))
            .with_state(self.clone())
    }

    pub fn metrics_routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/metrics", get(metrics_endpoint))
            .with_state(self.clone())
    }

    async fn serve_internal(
        self: Arc<Self>,
        listener: TcpListener,
        redact_errors: bool,
        routes: Router,
    ) -> Result<()> {
        let token = self.cancellation_token.clone();

        let app = routes.layer(middleware::from_fn(Self::version_header_middleware));
        let app = if redact_errors {
            app
        } else {
            app.layer(middleware::from_fn(Self::redact_error_middleware))
        };

        tracing::info!("Starting HTTP server...");
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move {
                tracing::info!("Waiting for cancellation token...");
                token.cancelled().await;
                tracing::info!("Cancellation token triggered, starting graceful shutdown");
            })
            .await?;

        tracing::info!("HTTP server stopped, shutting down event dispatcher...");

        // Explicitly shutdown event dispatcher before waiting on doc workers
        if let Some(event_dispatcher) = &self.event_dispatcher {
            tracing::info!("Shutting down event dispatcher...");
            event_dispatcher.shutdown();
            tracing::info!("Event dispatcher shutdown complete");
        }

        tracing::info!("Closing doc worker tracker...");
        self.doc_worker_tracker.close();
        tracing::info!("Waiting for doc workers to finish...");
        self.doc_worker_tracker.wait().await;
        tracing::info!("All doc workers stopped");

        Ok(())
    }

    pub async fn serve(self, listener: TcpListener, redact_errors: bool) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.routes();
        s.serve_internal(listener, redact_errors, routes).await
    }

    pub async fn serve_doc(self, listener: TcpListener, redact_errors: bool) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.single_doc_routes();
        s.serve_internal(listener, redact_errors, routes).await
    }

    pub async fn serve_metrics(self, listener: TcpListener) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.metrics_routes();
        s.serve_internal(listener, false, routes).await
    }

    fn verify_doc_token(&self, token: Option<&str>, doc: &str) -> Result<Authorization, AppError> {
        if let Some(authenticator) = &self.authenticator {
            if let Some(token) = token {
                let authorization = authenticator
                    .verify_doc_token(token, doc, current_time_epoch_millis())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
                Ok(authorization)
            } else {
                Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
            }
        } else {
            Ok(Authorization::Full)
        }
    }

    fn get_single_doc_id(&self) -> Result<String, AppError> {
        self.docs
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, anyhow!("No document found")))
    }
}

#[derive(Deserialize)]
struct HandlerParams {
    token: Option<String>,
}

#[derive(Deserialize)]
struct EventWebSocketPath {
    prefix: String,
}

async fn get_doc_as_update(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    // All authorization types allow reading the document.
    let token = get_token_from_header(auth_header);
    let _ = server_state.verify_doc_token(token.as_deref(), &doc_id)?;

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let update = dwskv.as_update();
    tracing::debug!("update: {:?}", update);
    Ok(update.into_response())
}

async fn get_doc_as_update_deprecated(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    tracing::warn!("/doc/:doc_id/as-update is deprecated; call /doc/:doc_id/auth instead and then call as-update on the returned base URL.");
    get_doc_as_update(State(server_state), Path(doc_id), auth_header).await
}

async fn update_doc_deprecated(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    body: Bytes,
) -> Result<Response, AppError> {
    tracing::warn!("/doc/:doc_id/update is deprecated; call /doc/:doc_id/auth instead and then call update on the returned base URL.");
    update_doc(Path(doc_id), State(server_state), auth_header, body).await
}

async fn get_doc_as_update_single(
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    let doc_id = server_state.get_single_doc_id()?;
    get_doc_as_update(State(server_state), Path(doc_id), auth_header).await
}

async fn update_doc(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    body: Bytes,
) -> Result<Response, AppError> {
    let token = get_token_from_header(auth_header);
    let authorization = server_state.verify_doc_token(token.as_deref(), &doc_id)?;
    update_doc_inner(doc_id, server_state, authorization, body).await
}

async fn update_doc_inner(
    doc_id: String,
    server_state: Arc<Server>,
    authorization: Authorization,
    body: Bytes,
) -> Result<Response, AppError> {
    if !matches!(authorization, Authorization::Full) {
        return Err(AppError(StatusCode::FORBIDDEN, anyhow!("Unauthorized.")));
    }

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if let Err(err) = dwskv.apply_update(&body) {
        tracing::error!(?err, "Failed to apply update");
        return Err(AppError(StatusCode::INTERNAL_SERVER_ERROR, err));
    }

    Ok(StatusCode::OK.into_response())
}

async fn update_doc_single(
    State(server_state): State<Arc<Server>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let doc_id = server_state.get_single_doc_id()?;
    // the doc server is meant to be run in Plane, so we expect verified plane
    // headers to be used for authorization.
    let authorization = get_authorization_from_plane_header(headers)?;
    update_doc_inner(doc_id, server_state, authorization, body).await
}

async fn handle_socket_upgrade(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    authorization: Authorization,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    handle_socket_upgrade_with_channel(ws, Path(doc_id), authorization, None, State(server_state))
        .await
}

async fn handle_socket_upgrade_with_channel(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    authorization: Authorization,
    routing_channel: Option<String>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    if !matches!(authorization, Authorization::Full) && !server_state.docs.contains_key(&doc_id) {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Doc {} not found", doc_id),
        ));
    }

    let dwskv = server_state
        .get_or_create_doc_with_channel(&doc_id, routing_channel)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let awareness = dwskv.awareness();
    let cancellation_token = server_state.cancellation_token.clone();

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, awareness, authorization, cancellation_token)
    }))
}

async fn handle_socket_upgrade_deprecated(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    tracing::warn!(
        "/doc/ws/:doc_id is deprecated; call /doc/:doc_id/auth instead and use the returned URL."
    );
    let (permission, channel) = if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = params.token.as_deref() {
            authenticator
                .verify_token_with_channel(token, current_time_epoch_millis())
                .map_err(|e| (StatusCode::UNAUTHORIZED, e))?
        } else {
            (y_sweet_core::auth::Permission::Server, None)
        }
    } else {
        (y_sweet_core::auth::Permission::Server, None)
    };

    let authorization = match permission {
        y_sweet_core::auth::Permission::Doc(doc_perm) => {
            if doc_perm.doc_id != doc_id {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Token not valid for this document"),
                ));
            }
            doc_perm.authorization
        }
        y_sweet_core::auth::Permission::Server => Authorization::Full,
        y_sweet_core::auth::Permission::Prefix(prefix_perm) => {
            if !doc_id.starts_with(&prefix_perm.prefix) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Token not valid for this document"),
                ));
            }
            prefix_perm.authorization
        }
        y_sweet_core::auth::Permission::File(_) => {
            return Err(AppError(
                StatusCode::FORBIDDEN,
                anyhow!("File token not valid for document access"),
            ));
        }
    };

    handle_socket_upgrade_with_channel(
        ws,
        Path(doc_id),
        authorization,
        channel,
        State(server_state),
    )
    .await
}

async fn handle_socket_upgrade_full_path(
    ws: WebSocketUpgrade,
    Path((doc_id, doc_id2)): Path<(String, String)>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    tracing::debug!("WebSocket upgrade request for doc: {}", doc_id);

    if doc_id != doc_id2 {
        tracing::debug!("Doc ID mismatch: {} != {}", doc_id, doc_id2);
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            anyhow!("For Yjs compatibility, the doc_id appears twice in the URL. It must be the same in both places, but we got {} and {}.", doc_id, doc_id2),
        ));
    }

    let (permission, channel) = if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = params.token.as_deref() {
            let current_time = current_time_epoch_millis();

            authenticator
                .verify_token_with_channel(token, current_time)
                .map_err(|e| {
                    tracing::debug!("Token verification failed: {:?}", e);
                    (StatusCode::UNAUTHORIZED, e)
                })?
        } else {
            (y_sweet_core::auth::Permission::Server, None)
        }
    } else {
        (y_sweet_core::auth::Permission::Server, None)
    };

    let authorization = match permission {
        y_sweet_core::auth::Permission::Doc(doc_perm) => {
            if doc_perm.doc_id != doc_id {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Token not valid for this document"),
                ));
            }
            doc_perm.authorization
        }
        y_sweet_core::auth::Permission::Server => Authorization::Full,
        y_sweet_core::auth::Permission::Prefix(prefix_perm) => {
            if !doc_id.starts_with(&prefix_perm.prefix) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Token not valid for this document"),
                ));
            }
            prefix_perm.authorization
        }
        y_sweet_core::auth::Permission::File(_) => {
            return Err(AppError(
                StatusCode::FORBIDDEN,
                anyhow!("File token not valid for document access"),
            ));
        }
    };

    handle_socket_upgrade_with_channel(
        ws,
        Path(doc_id),
        authorization,
        channel,
        State(server_state),
    )
    .await
}

async fn handle_socket_upgrade_single(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    headers: HeaderMap,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    let single_doc_id = server_state.get_single_doc_id()?;
    if doc_id != single_doc_id {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Document not found"),
        ));
    }

    // the doc server is meant to be run in Plane, so we expect verified plane
    // headers to be used for authorization.
    let authorization = get_authorization_from_plane_header(headers)?;
    handle_socket_upgrade(ws, Path(single_doc_id), authorization, State(server_state)).await
}

async fn handle_socket(
    socket: WebSocket,
    awareness: Arc<RwLock<Awareness>>,
    authorization: Authorization,
    cancellation_token: CancellationToken,
) {
    let (mut sink, mut stream) = socket.split();
    let (send, mut recv) = channel(1024);

    tokio::spawn(async move {
        while let Some(msg) = recv.recv().await {
            let _ = sink.send(Message::Binary(msg)).await;
        }
    });

    let connection = DocConnection::new(awareness, authorization, move |bytes| {
        if let Err(e) = send.try_send(bytes.to_vec()) {
            tracing::warn!(?e, "Error sending message");
        }
    });

    loop {
        tokio::select! {
            Some(msg) = stream.next() => {
                let msg = match msg {
                    Ok(Message::Binary(bytes)) => bytes,
                    Ok(Message::Close(_)) => break,
                    Err(_e) => {
                        // The stream will complain about things like
                        // connections being lost without handshake.
                        continue;
                    }
                    msg => {
                        tracing::warn!(?msg, "Received non-binary message");
                        continue;
                    }
                };

                if let Err(e) = connection.send(&msg).await {
                    tracing::warn!(?e, "Error handling message");
                }
            }
            _ = cancellation_token.cancelled() => {
                tracing::debug!("Closing doc connection due to server cancel...");
                break;
            }
        }
    }
}

async fn check_store(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
) -> Result<Json<Value>, AppError> {
    server_state.check_auth(auth_header)?;

    if server_state.store.is_none() {
        return Ok(Json(json!({"ok": false, "error": "No store set."})));
    };

    // The check_store endpoint for the native server is kind of moot, since
    // the server will not start if store is not ok.
    Ok(Json(json!({"ok": true})))
}

async fn check_store_deprecated(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
) -> Result<Json<Value>, AppError> {
    tracing::warn!(
        "GET check_store is deprecated, use POST check_store with an empty body instead."
    );
    check_store(auth_header, State(server_state)).await
}

/// Always returns a 200 OK response, as long as we are listening.
async fn ready() -> Result<Json<Value>, AppError> {
    Ok(Json(json!({"ok": true})))
}

async fn new_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
    Json(body): Json<DocCreationRequest>,
) -> Result<Json<NewDocResponse>, AppError> {
    let token = get_token_from_header(auth_header);

    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // First try server token
            if authenticator
                .verify_server_token(token, current_time_epoch_millis())
                .is_ok()
            {
                // Server token allows creating any document
            } else {
                // Try prefix token - we need to check if the doc_id matches the prefix
                if let Some(doc_id) = &body.doc_id {
                    let permission = authenticator
                        .verify_token_auto(token, current_time_epoch_millis())
                        .map_err(|e| {
                            AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e))
                        })?;

                    match permission {
                        Permission::Prefix(prefix_perm) => {
                            // Check if the document ID starts with the prefix
                            if !doc_id.starts_with(&prefix_perm.prefix) {
                                return Err(AppError(
                                    StatusCode::FORBIDDEN,
                                    anyhow!(
                                        "Document ID '{}' does not match prefix '{}'",
                                        doc_id,
                                        prefix_perm.prefix
                                    ),
                                ));
                            }
                            // Check if we have Full permissions (needed for creation)
                            if prefix_perm.authorization != Authorization::Full {
                                return Err(AppError(
                                    StatusCode::FORBIDDEN,
                                    anyhow!("Prefix token requires Full authorization to create documents")
                                ));
                            }
                        }
                        _ => {
                            return Err(AppError(
                                StatusCode::FORBIDDEN,
                                anyhow!("Only server or prefix tokens can create documents"),
                            ));
                        }
                    }
                } else {
                    // No doc_id provided - only server tokens can create with auto-generated ID
                    return Err(AppError(
                        StatusCode::FORBIDDEN,
                        anyhow!("Prefix tokens must specify a docId that matches their prefix"),
                    ));
                }
            }
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    }

    let doc_id = if let Some(doc_id) = body.doc_id {
        if !validate_doc_name(doc_id.as_str()) {
            Err((StatusCode::BAD_REQUEST, anyhow!("Invalid document name")))?
        }

        server_state
            .get_or_create_doc(doc_id.as_str())
            .await
            .map_err(|e| {
                tracing::error!(?e, "Failed to create doc");
                (StatusCode::INTERNAL_SERVER_ERROR, e)
            })?;

        doc_id
    } else {
        server_state.create_doc().await.map_err(|d| {
            tracing::error!(?d, "Failed to create doc");
            (StatusCode::INTERNAL_SERVER_ERROR, d)
        })?
    };

    Ok(Json(NewDocResponse { doc_id }))
}

fn generate_context_aware_urls(
    url_prefix: &Option<Url>,
    allowed_hosts: &[AllowedHost],
    request_host: &str,
    doc_id: &str,
) -> Result<(String, String), AppError> {
    // Priority 1: Explicit URL prefix
    if let Some(prefix) = url_prefix {
        let ws_scheme = if prefix.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        let mut ws_url = prefix.clone();
        ws_url.set_scheme(ws_scheme).unwrap();
        let ws_url = ws_url
            .join(&format!("/d/{}/ws", doc_id))
            .unwrap()
            .to_string();

        let base_url = format!("{}/d/{}", prefix.as_str().trim_end_matches('/'), doc_id);
        return Ok((ws_url, base_url));
    }

    // Priority 2: Context-derived URL from Host header
    if let Some(allowed) = allowed_hosts.iter().find(|h| h.host == request_host) {
        let ws_scheme = if allowed.scheme == "https" {
            "wss"
        } else {
            "ws"
        };
        let ws_url = format!("{}://{}/d/{}/ws", ws_scheme, request_host, doc_id);
        let base_url = format!("{}://{}/d/{}", allowed.scheme, request_host, doc_id);
        return Ok((ws_url, base_url));
    }

    // Priority 3: Fallback to old behavior for backward compatibility
    // This handles the case where no URL prefix and no allowed hosts are set
    if allowed_hosts.is_empty() {
        let ws_url = format!("ws://{}/d/{}/ws", request_host, doc_id);
        let base_url = format!("http://{}/d/{}", request_host, doc_id);
        return Ok((ws_url, base_url));
    }

    // Reject unknown hosts when allowed_hosts is configured
    Err(AppError(
        StatusCode::BAD_REQUEST,
        anyhow!("Host '{}' not in allowed hosts list", request_host),
    ))
}

async fn auth_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    TypedHeader(host): TypedHeader<headers::Host>,
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    body: Option<Json<AuthDocRequest>>,
) -> Result<Json<ClientToken>, AppError> {
    server_state.check_auth(auth_header)?;

    let Json(AuthDocRequest {
        authorization,
        valid_for_seconds,
        ..
    }) = body.unwrap_or_default();

    if !server_state.doc_exists(&doc_id).await {
        Err((StatusCode::NOT_FOUND, anyhow!("Doc {} not found", doc_id)))?;
    }

    let valid_for_seconds = valid_for_seconds.unwrap_or(DEFAULT_EXPIRATION_SECONDS);
    let expiration_time =
        ExpirationTimeEpochMillis(current_time_epoch_millis() + valid_for_seconds * 1000);

    let token = if let Some(auth) = &server_state.authenticator {
        let token = auth.gen_doc_token(&doc_id, authorization, expiration_time, None);
        Some(token)
    } else {
        None
    };

    let (url, base_url) = generate_context_aware_urls(
        &server_state.url_prefix,
        &server_state.allowed_hosts,
        &host.to_string(),
        &doc_id,
    )?;

    Ok(Json(ClientToken {
        url,
        base_url: Some(base_url),
        doc_id,
        token,
        authorization,
    }))
}

fn get_token_from_header(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Option<String> {
    if let Some(TypedHeader(headers::Authorization(bearer))) = auth_header {
        Some(bearer.token().to_string())
    } else {
        None
    }
}

async fn handle_file_upload_url(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Json<FileUploadUrlResponse>, AppError> {
    // Get token and extract metadata
    let token = get_token_from_header(auth_header);

    // Verify that the token is for the requested document and extract file hash from token
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Verify token is for this doc_id
            let auth = authenticator
                .verify_file_token_for_doc(token, &doc_id, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;

            // Only allow Full permission to upload
            if !matches!(auth, Authorization::Full) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Insufficient permissions to upload files"),
                ));
            }

            // Verify the token and get the file metadata
            let permission = authenticator
                .verify_token_auto(token, current_time_epoch_millis())
                .map_err(|_| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token")))?;

            if let Permission::File(file_permission) = permission {
                let file_hash = file_permission.file_hash;

                // Validate the file hash
                if !validate_file_hash(&file_hash) {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        anyhow!("Invalid file hash format in token"),
                    ));
                }

                // Check if we have a store configured
                if server_state.store.is_none() {
                    return Err(AppError(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        anyhow!("No store configured for file uploads"),
                    ));
                }

                // Get metadata from token
                let content_type = file_permission.content_type.as_deref();
                let content_length = file_permission.content_length;

                // Generate the upload URL - organize files by doc_id/file_hash
                let key = format!("files/{}/{}", doc_id, file_hash);
                let upload_url = server_state
                    .store
                    .as_ref()
                    .unwrap()
                    .generate_upload_url(&key, content_type, content_length)
                    .await
                    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

                if let Some(url) = upload_url {
                    return Ok(Json(FileUploadUrlResponse { upload_url: url }));
                } else {
                    return Err(AppError(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        anyhow!("Failed to generate upload URL"),
                    ));
                }
            } else {
                return Err(AppError(
                    StatusCode::BAD_REQUEST,
                    anyhow!("Token is not a file token"),
                ));
            }
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    } else {
        // No auth configured, anyone can upload
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("Authentication is required for file operations"),
        ));
    }
}

async fn handle_file_download_url(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    Query(params): Query<FileDownloadQueryParams>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Json<FileDownloadUrlResponse>, AppError> {
    // Get token
    let token = get_token_from_header(auth_header);

    // Check if we have authentication configured
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Extract hash from query parameter if present
            let query_hash = params.hash;

            // Verify the token and determine its type
            let permission = authenticator
                .verify_token_auto(token, current_time_epoch_millis())
                .map_err(|_| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token")))?;

            match permission {
                Permission::File(file_permission) => {
                    // Check if file token is for this doc_id
                    if file_permission.doc_id != doc_id {
                        return Err(AppError(
                            StatusCode::UNAUTHORIZED,
                            anyhow!("Token not valid for this document"),
                        ));
                    }

                    // Both ReadOnly and Full can download files
                    if !matches!(
                        file_permission.authorization,
                        Authorization::ReadOnly | Authorization::Full
                    ) {
                        return Err(AppError(
                            StatusCode::FORBIDDEN,
                            anyhow!("Insufficient permissions to download file"),
                        ));
                    }

                    let file_hash = file_permission.file_hash;

                    // Validate the file hash
                    if !validate_file_hash(&file_hash) {
                        return Err(AppError(
                            StatusCode::BAD_REQUEST,
                            anyhow!("Invalid file hash format in token"),
                        ));
                    }

                    // Generate download URL using hash from token
                    return generate_file_download_url(&server_state, &doc_id, &file_hash).await;
                }
                Permission::Server => {
                    // Server token is valid, use hash from query parameter
                    if let Some(hash) = query_hash {
                        // Validate the file hash from query parameter
                        if !validate_file_hash(&hash) {
                            return Err(AppError(
                                StatusCode::BAD_REQUEST,
                                anyhow!("Invalid file hash format in query parameter"),
                            ));
                        }

                        // Generate download URL using hash from query parameter
                        return generate_file_download_url(&server_state, &doc_id, &hash).await;
                    } else {
                        return Err(AppError(
                            StatusCode::BAD_REQUEST,
                            anyhow!("Hash query parameter required when using server token"),
                        ));
                    }
                }
                Permission::Doc(_) => {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        anyhow!("Document tokens cannot be used for file operations"),
                    ));
                }
                Permission::Prefix(prefix_perm) => {
                    // Check if doc_id matches the prefix
                    if !doc_id.starts_with(&prefix_perm.prefix) {
                        return Err(AppError(
                            StatusCode::FORBIDDEN,
                            anyhow!("Token not valid for this document"),
                        ));
                    }

                    // Both ReadOnly and Full can download files
                    if !matches!(
                        prefix_perm.authorization,
                        Authorization::ReadOnly | Authorization::Full
                    ) {
                        return Err(AppError(
                            StatusCode::FORBIDDEN,
                            anyhow!("Insufficient permissions to download file"),
                        ));
                    }

                    // Use hash from query parameter for prefix tokens
                    if let Some(hash) = query_hash {
                        // Validate the file hash from query parameter
                        if !validate_file_hash(&hash) {
                            return Err(AppError(
                                StatusCode::BAD_REQUEST,
                                anyhow!("Invalid file hash format in query parameter"),
                            ));
                        }

                        // Generate download URL using hash from query parameter
                        return generate_file_download_url(&server_state, &doc_id, &hash).await;
                    } else {
                        return Err(AppError(
                            StatusCode::BAD_REQUEST,
                            anyhow!("Hash query parameter required when using prefix token"),
                        ));
                    }
                }
            }
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    } else {
        // No auth configured
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("Authentication is required for file operations"),
        ));
    }
}

async fn generate_file_download_url(
    server_state: &Arc<Server>,
    doc_id: &str,
    file_hash: &str,
) -> Result<Json<FileDownloadUrlResponse>, AppError> {
    // Check if we have a store configured
    if server_state.store.is_none() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            anyhow!("No store configured for file downloads"),
        ));
    }

    // Generate the download URL - using doc_id/file_hash path structure
    let key = format!("files/{}/{}", doc_id, file_hash);
    let download_url = server_state
        .store
        .as_ref()
        .unwrap()
        .generate_download_url(&key)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

    if let Some(url) = download_url {
        Ok(Json(FileDownloadUrlResponse { download_url: url }))
    } else {
        Err(AppError(StatusCode::NOT_FOUND, anyhow!("File not found")))
    }
}

/// Delete all files for a document
///
/// This endpoint accepts either:
/// - A file token with the doc_id (hash not required)
/// - A doc token with the doc_id
/// - A server token
///
/// Returns 204 No Content on success
async fn handle_file_delete(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<StatusCode, AppError> {
    // Get token
    let token = get_token_from_header(auth_header);

    // Verify token is for this doc_id and has required permission
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Verify token is for this doc_id
            let auth = authenticator
                .verify_file_token_for_doc(token, &doc_id, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;

            // Only Full permission can delete files
            if !matches!(auth, Authorization::Full) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Insufficient permissions to delete files"),
                ));
            }

            // Check if we have a store configured
            if server_state.store.is_none() {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    anyhow!("No store configured for file operations"),
                ));
            }

            // List all files in the document's directory
            let prefix = format!("files/{}/", doc_id);
            let store = server_state.store.as_ref().unwrap();

            let file_infos = store
                .list(&prefix)
                .await
                .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

            if file_infos.is_empty() {
                tracing::info!("No files to delete for document: {}", doc_id);
                return Ok(StatusCode::NO_CONTENT);
            }

            // Delete each file
            let mut deleted_count = 0;
            for file_info in file_infos {
                let key = file_info.key;
                if let Err(e) = store.remove(&format!("files/{}/{}", doc_id, key)).await {
                    tracing::error!("Failed to delete file {}/{}: {}", doc_id, key, e);
                    continue;
                }
                deleted_count += 1;
            }

            tracing::info!("Deleted {} files for document: {}", deleted_count, doc_id);
            return Ok(StatusCode::NO_CONTENT);
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    } else {
        // No auth configured
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("Authentication is required for file operations"),
        ));
    }
}

/// Delete a specific file by hash
///
/// This endpoint accepts either:
/// - A file token with the doc_id (hash not required)
/// - A doc token with the doc_id
/// - A server token
///
/// The hash to delete is specified in the URL path.
/// Returns 204 No Content on success, 404 if file not found
async fn handle_file_delete_by_hash(
    State(server_state): State<Arc<Server>>,
    Path((doc_id, file_hash)): Path<(String, String)>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<StatusCode, AppError> {
    // Get token
    let token = get_token_from_header(auth_header);

    // Verify token is for this doc_id and has required permission
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Verify token is for this doc_id
            let auth = authenticator
                .verify_file_token_for_doc(token, &doc_id, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;

            // Only Full permission can delete files
            if !matches!(auth, Authorization::Full) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Insufficient permissions to delete file"),
                ));
            }

            // Validate the file hash format
            if !validate_file_hash(&file_hash) {
                return Err(AppError(
                    StatusCode::BAD_REQUEST,
                    anyhow!("Invalid file hash format"),
                ));
            }

            // Check if we have a store configured
            if server_state.store.is_none() {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    anyhow!("No store configured for file operations"),
                ));
            }

            // Construct the file path
            let key = format!("files/{}/{}", doc_id, file_hash);

            // Check if the file exists before trying to delete it
            let exists = server_state
                .store
                .as_ref()
                .unwrap()
                .exists(&key)
                .await
                .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

            if !exists {
                // If the file is already gone, return 204 No Content since DELETE is idempotent
                tracing::debug!("File already deleted: {}/{}", doc_id, file_hash);
                return Ok(StatusCode::NO_CONTENT);
            }

            // Delete the file
            server_state
                .store
                .as_ref()
                .unwrap()
                .remove(&key)
                .await
                .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

            tracing::info!("Deleted file: {}/{}", doc_id, file_hash);
            return Ok(StatusCode::NO_CONTENT);
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    } else {
        // No auth configured
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("Authentication is required for file operations"),
        ));
    }
}

/// Handle HEAD request to check if a file exists in S3 storage
///
/// Returns:
/// - 200 OK if the file exists
/// - 404 Not Found if the file doesn't exist
/// - Other status codes for authentication/authorization errors

/// Get the history of all files for a document
///
/// This endpoint accepts either:
/// - A file token with the doc_id (hash not required)
/// - A doc token with the doc_id
/// - A server token
async fn handle_file_history(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Json<FileHistoryResponse>, AppError> {
    // Get token
    let token = get_token_from_header(auth_header);

    // Verify token is for this doc_id
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Verify token is for this doc_id - this now accepts both doc and file tokens
            let auth = authenticator
                .verify_file_token_for_doc(token, &doc_id, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;

            // Both ReadOnly and Full can view file history
            if !matches!(auth, Authorization::ReadOnly | Authorization::Full) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Insufficient permissions to view file history"),
                ));
            }
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    }

    // Check if we have a store configured
    if server_state.store.is_none() {
        return Err(AppError(
            StatusCode::INTERNAL_SERVER_ERROR,
            anyhow!("No store configured for file operations"),
        ));
    }

    // List files in the document's directory
    let prefix = format!("files/{}/", doc_id);
    let store = server_state.store.as_ref().unwrap();

    let file_infos = store
        .list(&prefix)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

    // Convert the raw file info into the API response format
    let files = file_infos
        .into_iter()
        .map(|info| FileHistoryEntry {
            hash: info.key,
            size: info.size,
            created_at: info.last_modified,
        })
        .collect();

    Ok(Json(FileHistoryResponse { files }))
}

async fn handle_doc_versions(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Json<DocumentVersionResponse>, AppError> {
    let token = get_token_from_header(auth_header);

    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            let auth = authenticator
                .verify_doc_token(token, &doc_id, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;

            if !matches!(auth, Authorization::ReadOnly | Authorization::Full) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Insufficient permissions to view document versions"),
                ));
            }
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    }

    let store = match &server_state.store {
        Some(s) => s,
        None => {
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                anyhow!("No store configured for operations"),
            ))
        }
    };

    let key = format!("{}/data.ysweet", doc_id);
    let versions = store
        .list_versions(&key)
        .await
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

    let entries = versions
        .into_iter()
        .map(|v| DocumentVersionEntry {
            version_id: v.version_id,
            created_at: v.last_modified,
            is_latest: v.is_latest,
        })
        .collect();

    Ok(Json(DocumentVersionResponse { versions: entries }))
}

async fn handle_file_head(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<StatusCode, AppError> {
    // Get token
    let token = get_token_from_header(auth_header);

    // Verify token is for this doc_id
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Verify token is for this doc_id
            let auth = authenticator
                .verify_file_token_for_doc(token, &doc_id, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;

            // Both ReadOnly and Full can check if a file exists
            if !matches!(auth, Authorization::ReadOnly | Authorization::Full) {
                return Err(AppError(
                    StatusCode::FORBIDDEN,
                    anyhow!("Insufficient permissions to access file"),
                ));
            }

            // Verify the token and get the file hash
            let permission = authenticator
                .verify_token_auto(token, current_time_epoch_millis())
                .map_err(|_| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token")))?;

            if let Permission::File(file_permission) = permission {
                let file_hash = file_permission.file_hash;

                // Validate the file hash
                if !validate_file_hash(&file_hash) {
                    return Err(AppError(
                        StatusCode::BAD_REQUEST,
                        anyhow!("Invalid file hash format in token"),
                    ));
                }

                // Check if we have a store configured
                if server_state.store.is_none() {
                    return Err(AppError(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        anyhow!("No store configured for file operations"),
                    ));
                }

                // Construct the file path with proper format - using doc_id/file_hash
                let key = format!("files/{}/{}", doc_id, file_hash);

                // Check if the file exists with a direct call to S3
                let exists = server_state
                    .store
                    .as_ref()
                    .unwrap()
                    .exists(&key)
                    .await
                    .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.into()))?;

                if exists {
                    tracing::debug!("File exists: {}/{}", doc_id, file_hash);
                    return Ok(StatusCode::OK);
                } else {
                    tracing::debug!("File not found: {}/{}", doc_id, file_hash);
                    return Err(AppError(StatusCode::NOT_FOUND, anyhow!("File not found")));
                }
            } else {
                return Err(AppError(
                    StatusCode::BAD_REQUEST,
                    anyhow!("Token is not a file token"),
                ));
            }
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    } else {
        // No auth configured
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("Authentication is required for file operations"),
        ));
    }
}

#[derive(Deserialize)]
struct PlaneVerifiedUserData {
    authorization: Authorization,
}

fn get_authorization_from_plane_header(headers: HeaderMap) -> Result<Authorization, AppError> {
    if let Some(token) = headers.get(HeaderName::from_static(PLANE_VERIFIED_USER_DATA_HEADER)) {
        let token_str = token.to_str().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let user_data: PlaneVerifiedUserData =
            serde_json::from_str(token_str).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        Ok(user_data.authorization)
    } else {
        Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
    }
}

async fn reload_webhook_config_endpoint(
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Json<Value>, AppError> {
    // Get token
    let token = get_token_from_header(auth_header);

    // Verify token is server token (for server admin operations)
    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = token.as_deref() {
            // Verify this is a server admin token
            authenticator
                .verify_server_token(token, current_time_epoch_millis())
                .map_err(|e| AppError(StatusCode::UNAUTHORIZED, anyhow!("Invalid token: {}", e)))?;
        } else {
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    }

    // Reload webhook configuration
    match server_state.reload_webhook_config().await {
        Ok(status) => Ok(Json(json!({
            "status": "success",
            "message": status
        }))),
        Err(e) => {
            tracing::error!("Failed to reload webhook config: {}", e);
            Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                anyhow!("Failed to reload webhook configuration: {}", e),
            ))
        }
    }
}

async fn metrics_endpoint(State(_server_state): State<Arc<Server>>) -> Result<String, AppError> {
    use prometheus::{Encoder, TextEncoder};

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    encoder.encode(&metric_families, &mut buffer).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            anyhow!("Failed to encode metrics: {}", e),
        )
    })?;

    Ok(String::from_utf8(buffer).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            anyhow!("Failed to convert metrics to string: {}", e),
        )
    })?)
}

async fn handle_event_websocket_upgrade(
    ws: WebSocketUpgrade,
    Path(path): Path<EventWebSocketPath>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    use y_sweet_core::auth::{detect_token_format, TokenFormat};

    tracing::info!(
        "WebSocket upgrade request received for prefix: {}",
        path.prefix
    );

    if let Some(authenticator) = &server_state.authenticator {
        if let Some(token) = params.token.as_deref() {
            tracing::info!("Token provided, checking format...");

            // Check token format - only accept CWT tokens
            let token_format = detect_token_format(token);
            tracing::info!("Token format detected: {:?}", token_format);

            if token_format != TokenFormat::Cwt {
                tracing::warn!("Rejecting non-CWT token");
                return Err(AppError(
                    StatusCode::UNAUTHORIZED,
                    anyhow!("Only CWT tokens are supported for WebSocket event streaming"),
                ));
            }

            // Verify the CWT token using the auto method (which will route to CWT verification)
            tracing::info!("Verifying CWT token...");
            let permission = authenticator
                .verify_token_auto(token, current_time_epoch_millis())
                .map_err(|e| {
                    tracing::error!("Token verification failed: {}", e);
                    AppError(
                        StatusCode::UNAUTHORIZED,
                        anyhow!("Invalid CWT token: {}", e),
                    )
                })?;

            match permission {
                Permission::Prefix(prefix_perm) => {
                    tracing::info!("Valid prefix token for prefix: {}", prefix_perm.prefix);

                    // Validate that the URL path prefix matches the token prefix
                    if prefix_perm.prefix != path.prefix {
                        tracing::warn!(
                            "URL prefix '{}' does not match token prefix '{}'",
                            path.prefix,
                            prefix_perm.prefix
                        );
                        return Err(AppError(
                            StatusCode::FORBIDDEN,
                            anyhow!(
                                "URL prefix '{}' does not match token prefix '{}'",
                                path.prefix,
                                prefix_perm.prefix
                            ),
                        ));
                    }

                    return Ok(ws.on_upgrade(move |socket| {
                        handle_prefix_event_stream(socket, server_state, prefix_perm)
                    }));
                }
                Permission::Server => {
                    tracing::info!("Valid server token - creating synthetic prefix permission");

                    // Server tokens have full access, so create a synthetic prefix permission
                    // for the requested prefix with full authorization
                    let synthetic_prefix_perm = PrefixPermission {
                        prefix: path.prefix.clone(),
                        authorization: Authorization::Full,
                        user: None, // Server tokens don't have a user
                    };

                    return Ok(ws.on_upgrade(move |socket| {
                        handle_prefix_event_stream(socket, server_state, synthetic_prefix_perm)
                    }));
                }
                _ => {
                    tracing::warn!("Token is neither a prefix nor server token");
                    return Err(AppError(
                        StatusCode::FORBIDDEN,
                        anyhow!("Only CWT prefix tokens and server tokens are supported for event streaming"),
                    ));
                }
            }
        } else {
            tracing::warn!("No token provided in request");
            return Err(AppError(
                StatusCode::UNAUTHORIZED,
                anyhow!("No token provided"),
            ));
        }
    } else {
        tracing::error!("No authenticator configured");
        return Err(AppError(
            StatusCode::UNAUTHORIZED,
            anyhow!("Authentication required"),
        ));
    }
}

async fn handle_prefix_event_stream(
    socket: WebSocket,
    server_state: Arc<Server>,
    prefix_perm: PrefixPermission,
) {
    tracing::info!(
        "WebSocket connection established for prefix: {}",
        prefix_perm.prefix
    );

    let conn_id = nanoid::nanoid!();
    let (mut sink, mut stream) = socket.split();
    let (send, mut recv) = tokio::sync::mpsc::unbounded_channel();

    // Get cancellation token for graceful shutdown
    let cancellation_token = server_state.cancellation_token.clone();

    // Register temporary prefix in websocket sender
    server_state.websocket_sender.register_websocket_prefix(
        prefix_perm.prefix.clone(),
        conn_id.clone(),
        send.clone(),
        prefix_perm.authorization,
    );

    tracing::info!(
        "Registered WebSocket connection {} for prefix: {}",
        conn_id,
        prefix_perm.prefix
    );

    // Clone what we need for the tasks
    let send_clone = send.clone();
    let cancellation_token_outgoing = cancellation_token.clone();
    let cancellation_token_incoming = cancellation_token.clone();

    // Handle outgoing messages (events)
    let outgoing_task = tokio::spawn(async move {
        tracing::info!("Outgoing task started");
        loop {
            tokio::select! {
                _ = cancellation_token_outgoing.cancelled() => {
                    // Server is shutting down, close the connection
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                msg = recv.recv() => {
                    match msg {
                        Some(msg) => {
                            tracing::info!("Received message to send: {:?}", msg);
                            let json = serde_json::to_string(&msg).unwrap();
                            tracing::info!("Sending JSON to WebSocket: {}", json);
                            if sink.send(Message::Text(json)).await.is_err() {
                                tracing::error!("Failed to send message to WebSocket - connection closed");
                                break; // Connection closed
                            }
                            tracing::info!("Message sent successfully");
                        }
                        None => {
                            tracing::info!("Channel closed by sender - shutting down");
                            break; // Channel closed by sender (cleanup/shutdown)
                        }
                    }
                }
            }
        }
    });

    // Handle incoming messages (ping only)
    let incoming_task = tokio::spawn(async move {
        tracing::info!("Incoming task started");
        loop {
            tokio::select! {
                _ = cancellation_token_incoming.cancelled() => {
                    break; // Server is shutting down
                }
                msg = stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if text.trim() == "ping" {
                                if send_clone.send(ServerMessage::Pong).is_err() {
                                    break;
                                }
                            }
                            // Ignore all other messages
                        }
                        Some(Ok(Message::Close(_))) => break,
                        None => break, // Stream ended
                        _ => continue,
                    }
                }
            }
        }
    });

    // Wait for connection to close or shutdown signal
    tokio::select! {
        _ = cancellation_token.cancelled() => {
            // Shutdown requested - tasks will detect this via their own cancellation tokens
        }
        _ = outgoing_task => {},
        _ = incoming_task => {},
    }

    // Cleanup: unregister this specific connection
    server_state
        .websocket_sender
        .unregister_websocket_connection(&prefix_perm.prefix, &conn_id);
}

#[cfg(test)]
mod test {
    use super::*;
    use y_sweet_core::api_types::Authorization;
    use y_sweet_core::auth::ExpirationTimeEpochMillis;

    #[tokio::test]
    async fn test_auth_doc() {
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            None,
            vec![],
            CancellationToken::new(),
            true,
            None,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            Some(Json(AuthDocRequest {
                authorization: Authorization::Full,
                user_id: None,
                valid_for_seconds: None,
            })),
        )
        .await
        .unwrap();

        let expected_url = format!("ws://localhost/d/{doc_id}/ws");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    #[tokio::test]
    async fn test_auth_doc_with_prefix() {
        let prefix: Url = "https://foo.bar".parse().unwrap();
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            Some(prefix),
            vec![],
            CancellationToken::new(),
            true,
            None,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            None,
        )
        .await
        .unwrap();

        let expected_url = format!("wss://foo.bar/d/{doc_id}/ws");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    #[tokio::test]
    async fn test_file_head_endpoint() {
        use async_trait::async_trait;
        use std::collections::HashMap;
        use std::sync::Arc;
        use y_sweet_core::store::Result as StoreResult;

        // Create a mock store for testing
        #[derive(Clone)]
        struct MockStore {
            files: Arc<HashMap<String, Vec<u8>>>,
        }

        #[async_trait]
        impl Store for MockStore {
            async fn init(&self) -> StoreResult<()> {
                Ok(())
            }

            async fn get(&self, key: &str) -> StoreResult<Option<Vec<u8>>> {
                Ok(self.files.get(key).cloned())
            }

            async fn set(&self, _key: &str, _value: Vec<u8>) -> StoreResult<()> {
                Ok(())
            }

            async fn remove(&self, _key: &str) -> StoreResult<()> {
                Ok(())
            }

            async fn exists(&self, key: &str) -> StoreResult<bool> {
                Ok(self.files.contains_key(key))
            }

            async fn generate_upload_url(
                &self,
                _key: &str,
                _content_type: Option<&str>,
                _content_length: Option<u64>,
            ) -> StoreResult<Option<String>> {
                Ok(Some("http://mock-upload-url".to_string()))
            }

            async fn generate_download_url(&self, _key: &str) -> StoreResult<Option<String>> {
                Ok(Some("http://mock-download-url".to_string()))
            }
        }

        // Create a mock authenticator
        let authenticator = y_sweet_core::auth::Authenticator::gen_key().unwrap();
        let doc_id = "test-doc-123";
        let file_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        // Generate a file token
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX), // Never expires for test
            None,
            None,
            None,
        );

        // Set up the mock store with the test file
        let mut mock_files = HashMap::new();
        mock_files.insert(format!("files/{}/{}", doc_id, file_hash), vec![1, 2, 3, 4]);

        let mock_store = MockStore {
            files: Arc::new(mock_files),
        };

        // Create the server with our mock components
        let server_state = Arc::new(
            Server::new(
                Some(Box::new(mock_store)),
                Duration::from_secs(60),
                Some(authenticator.clone()),
                None,
                vec![],
                CancellationToken::new(),
                true,
                None,
            )
            .await
            .unwrap(),
        );

        // Create auth header with token
        let headers = TypedHeader(headers::Authorization::bearer(&token).unwrap());

        // Test the HEAD endpoint - should return 200 OK for existing file
        let result = handle_file_head(
            State(server_state.clone()),
            Path(doc_id.to_string()),
            Some(headers.clone()),
        )
        .await;

        assert!(
            result.is_ok(),
            "HEAD request should succeed for existing file"
        );
        assert_eq!(result.unwrap(), StatusCode::OK);

        // Test a file that doesn't exist
        let nonexistent_file_hash =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let nonexistent_token = authenticator.gen_file_token(
            nonexistent_file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
            None,
        );

        let nonexistent_headers =
            TypedHeader(headers::Authorization::bearer(&nonexistent_token).unwrap());

        let result = handle_file_head(
            State(server_state),
            Path(doc_id.to_string()),
            Some(nonexistent_headers),
        )
        .await;

        assert!(
            result.is_err(),
            "HEAD request should fail for non-existent file"
        );
        match result {
            Err(AppError(status, _)) => assert_eq!(status, StatusCode::NOT_FOUND),
            _ => panic!("Expected NOT_FOUND status for non-existent file"),
        };
    }

    #[tokio::test]
    async fn test_generate_context_aware_urls_with_prefix() {
        let url_prefix: Url = "https://api.example.com".parse().unwrap();
        let allowed_hosts = vec![];
        let doc_id = "test-doc";

        let (ws_url, base_url) =
            generate_context_aware_urls(&Some(url_prefix), &allowed_hosts, "unused-host", doc_id)
                .unwrap();

        assert_eq!(ws_url, "wss://api.example.com/d/test-doc/ws");
        assert_eq!(base_url, "https://api.example.com/d/test-doc");
    }

    #[tokio::test]
    async fn test_generate_context_aware_urls_with_allowed_hosts() {
        let allowed_hosts = vec![
            AllowedHost {
                host: "api.example.com".to_string(),
                scheme: "https".to_string(),
            },
            AllowedHost {
                host: "app.flycast".to_string(),
                scheme: "http".to_string(),
            },
        ];
        let doc_id = "test-doc";

        // Test HTTPS host
        let (ws_url, base_url) =
            generate_context_aware_urls(&None, &allowed_hosts, "api.example.com", doc_id).unwrap();

        assert_eq!(ws_url, "wss://api.example.com/d/test-doc/ws");
        assert_eq!(base_url, "https://api.example.com/d/test-doc");

        // Test flycast host
        let (ws_url, base_url) =
            generate_context_aware_urls(&None, &allowed_hosts, "app.flycast", doc_id).unwrap();

        assert_eq!(ws_url, "ws://app.flycast/d/test-doc/ws");
        assert_eq!(base_url, "http://app.flycast/d/test-doc");
    }

    #[tokio::test]
    async fn test_generate_context_aware_urls_rejects_unknown_host() {
        let allowed_hosts = vec![AllowedHost {
            host: "api.example.com".to_string(),
            scheme: "https".to_string(),
        }];
        let doc_id = "test-doc";

        let result = generate_context_aware_urls(&None, &allowed_hosts, "malicious.host", doc_id);

        assert!(result.is_err());
        match result {
            Err(AppError(StatusCode::BAD_REQUEST, _)) => {} // Expected
            _ => panic!("Expected BAD_REQUEST for unknown host"),
        }
    }

    #[tokio::test]
    async fn test_auth_doc_with_context_aware_urls() {
        let allowed_hosts = vec![
            AllowedHost {
                host: "api.example.com".to_string(),
                scheme: "https".to_string(),
            },
            AllowedHost {
                host: "app.flycast".to_string(),
                scheme: "http".to_string(),
            },
        ];

        let server_state = Arc::new(
            Server::new(
                None,
                Duration::from_secs(60),
                None,
                None, // No URL prefix - use context-aware generation
                allowed_hosts.clone(),
                CancellationToken::new(),
                true,
                None,
            )
            .await
            .unwrap(),
        );

        let doc_id = server_state.create_doc().await.unwrap();

        // Test with HTTPS host
        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "api.example.com",
            ))),
            State(server_state.clone()),
            Path(doc_id.clone()),
            Some(Json(AuthDocRequest {
                authorization: Authorization::Full,
                user_id: None,
                valid_for_seconds: None,
            })),
        )
        .await
        .unwrap();

        assert_eq!(token.url, format!("wss://api.example.com/d/{}/ws", doc_id));
        assert_eq!(
            token.base_url,
            Some(format!("https://api.example.com/d/{}", doc_id))
        );

        // Test with flycast host - create another server instance with same allowed hosts
        let server_state2 = Arc::new(
            Server::new(
                None,
                Duration::from_secs(60),
                None,
                None,
                allowed_hosts,
                CancellationToken::new(),
                true,
                None,
            )
            .await
            .unwrap(),
        );

        server_state2.load_doc(&doc_id, None).await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "app.flycast",
            ))),
            State(server_state2),
            Path(doc_id.clone()),
            Some(Json(AuthDocRequest {
                authorization: Authorization::Full,
                user_id: None,
                valid_for_seconds: None,
            })),
        )
        .await
        .unwrap();

        assert_eq!(token.url, format!("ws://app.flycast/d/{}/ws", doc_id));
        assert_eq!(
            token.base_url,
            Some(format!("http://app.flycast/d/{}", doc_id))
        );
    }
}
