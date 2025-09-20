use crate::api_types::Authorization;
use crate::sync::{
    self, awareness::Awareness, DefaultProtocol, EventMessage, Message, Protocol, SyncMessage,
    MSG_SYNC, MSG_SYNC_UPDATE,
};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock, RwLock};
use yrs::{
    block::ClientID,
    encoding::write::Write,
    updates::{
        decoder::Decode,
        encoder::{Encode, Encoder, EncoderV1},
    },
    ReadTxn, Subscription, Transact, Update,
};

// TODO: this is an implementation detail and should not be exposed.
pub const DOC_NAME: &str = "doc";

#[cfg(not(feature = "sync"))]
type Callback = Arc<dyn Fn(&[u8]) + 'static>;

#[cfg(feature = "sync")]
type Callback = Arc<dyn Fn(&[u8]) + 'static + Send + Sync>;

const SYNC_STATUS_MESSAGE: u8 = 102;

pub struct DocConnection {
    awareness: Arc<RwLock<Awareness>>,
    #[allow(unused)] // acts as RAII guard
    doc_subscription: Subscription,
    #[allow(unused)] // acts as RAII guard
    awareness_subscription: Subscription,
    authorization: Authorization,
    callback: Callback,
    closed: Arc<OnceLock<()>>,

    /// If the client sends an awareness state, this will be set to its client ID.
    /// It is used to clear the awareness state when a client disconnects.
    client_id: OnceLock<ClientID>,

    /// Event types that this connection is subscribed to
    event_subscriptions: Arc<RwLock<HashSet<String>>>,
}

impl DocConnection {
    #[cfg(not(feature = "sync"))]
    pub fn new<F>(
        awareness: Arc<RwLock<Awareness>>,
        authorization: Authorization,
        callback: F,
    ) -> Self
    where
        F: Fn(&[u8]) + 'static,
    {
        Self::new_inner(awareness, authorization, Arc::new(callback))
    }

    #[cfg(feature = "sync")]
    pub fn new<F>(
        awareness: Arc<RwLock<Awareness>>,
        authorization: Authorization,
        callback: F,
    ) -> Self
    where
        F: Fn(&[u8]) + 'static + Send + Sync,
    {
        Self::new_inner(awareness, authorization, Arc::new(callback))
    }

    pub fn new_inner(
        awareness: Arc<RwLock<Awareness>>,
        authorization: Authorization,
        callback: Callback,
    ) -> Self {
        let closed = Arc::new(OnceLock::new());

        let (doc_subscription, awareness_subscription) = {
            let mut awareness = awareness.write().unwrap();

            // Initial handshake is based on this:
            // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/sync.rs#L45-L54

            {
                // Send a server-side state vector, so that the client can send
                // updates that happened offline.
                let sv = awareness.doc().transact().state_vector();
                let sync_step_1 = Message::Sync(SyncMessage::SyncStep1(sv)).encode_v1();
                callback(&sync_step_1);
            }

            {
                // Send the initial awareness state.
                let update = awareness.update().unwrap();
                let awareness = Message::Awareness(update).encode_v1();
                callback(&awareness);
            }

            let doc_subscription = {
                let doc = awareness.doc();
                let callback = callback.clone();
                let closed = closed.clone();
                doc.observe_update_v1(move |_, event| {
                    if closed.get().is_some() {
                        return;
                    }
                    // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/net/broadcast.rs#L47-L52
                    let mut encoder = EncoderV1::new();
                    encoder.write_var(MSG_SYNC);
                    encoder.write_var(MSG_SYNC_UPDATE);
                    encoder.write_buf(&event.update);
                    let msg = encoder.to_vec();
                    callback(&msg);
                })
                .unwrap()
            };

            let callback = callback.clone();
            let closed = closed.clone();
            let awareness_subscription = awareness.on_update(move |awareness, e| {
                if closed.get().is_some() {
                    return;
                }

                // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/net/broadcast.rs#L59
                let added = e.added();
                let updated = e.updated();
                let removed = e.removed();
                let mut changed = Vec::with_capacity(added.len() + updated.len() + removed.len());
                changed.extend_from_slice(added);
                changed.extend_from_slice(updated);
                changed.extend_from_slice(removed);

                if let Ok(u) = awareness.update_with_clients(changed) {
                    let msg = Message::Awareness(u).encode_v1();
                    callback(&msg);
                }
            });

            (doc_subscription, awareness_subscription)
        };

        Self {
            awareness,
            doc_subscription,
            awareness_subscription,
            authorization,
            callback,
            client_id: OnceLock::new(),
            closed,
            event_subscriptions: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn send(&self, update: &[u8]) -> Result<(), anyhow::Error> {
        let msg = Message::decode_v1(update)?;
        let result = self.handle_msg(&DefaultProtocol, msg)?;

        if let Some(result) = result {
            let msg = result.encode_v1();
            (self.callback)(&msg);
        }

        Ok(())
    }

    // Adapted from:
    // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/net/conn.rs#L184C1-L222C1
    pub fn handle_msg<P: Protocol>(
        &self,
        protocol: &P,
        msg: Message,
    ) -> Result<Option<Message>, sync::Error> {
        let can_write = matches!(self.authorization, Authorization::Full);
        let a = &self.awareness;
        match msg {
            Message::Sync(msg) => match msg {
                SyncMessage::SyncStep1(sv) => {
                    let awareness = a.read().unwrap();
                    protocol.handle_sync_step1(&awareness, sv)
                }
                SyncMessage::SyncStep2(update) => {
                    if can_write {
                        let mut awareness = a.write().unwrap();
                        protocol.handle_sync_step2(&mut awareness, Update::decode_v1(&update)?)
                    } else {
                        Err(sync::Error::PermissionDenied {
                            reason: "Token does not have write access".to_string(),
                        })
                    }
                }
                SyncMessage::Update(update) => {
                    if can_write {
                        let mut awareness = a.write().unwrap();
                        protocol.handle_update(&mut awareness, Update::decode_v1(&update)?)
                    } else {
                        Err(sync::Error::PermissionDenied {
                            reason: "Token does not have write access".to_string(),
                        })
                    }
                }
            },
            Message::Auth(reason) => {
                let awareness = a.read().unwrap();
                protocol.handle_auth(&awareness, reason)
            }
            Message::AwarenessQuery => {
                let awareness = a.read().unwrap();
                protocol.handle_awareness_query(&awareness)
            }
            Message::Awareness(update) => {
                if update.clients.len() == 1 {
                    let client_id = update.clients.keys().next().unwrap();
                    self.client_id.get_or_init(|| *client_id);
                } else {
                    tracing::warn!("Received awareness update with more than one client");
                }
                let mut awareness = a.write().unwrap();
                protocol.handle_awareness_update(&mut awareness, update)
            }
            Message::Custom(SYNC_STATUS_MESSAGE, data) => {
                // Respond to the client with the same payload it sent.
                Ok(Some(Message::Custom(SYNC_STATUS_MESSAGE, data)))
            }
            Message::EventSubscribe(event_types) => {
                if let Ok(mut subscriptions) = self.event_subscriptions.write() {
                    for event_type in &event_types {
                        subscriptions.insert(event_type.clone());
                    }
                    tracing::debug!(
                        "Client subscribed to event types: {:?}. Total subscriptions: {}",
                        event_types,
                        subscriptions.len()
                    );
                } else {
                    tracing::warn!("Failed to acquire event subscriptions lock for subscribe");
                }
                Ok(None)
            }
            Message::EventUnsubscribe(event_types) => {
                if let Ok(mut subscriptions) = self.event_subscriptions.write() {
                    for event_type in &event_types {
                        subscriptions.remove(event_type);
                    }
                    tracing::debug!(
                        "Client unsubscribed from event types: {:?}. Total subscriptions: {}",
                        event_types,
                        subscriptions.len()
                    );
                } else {
                    tracing::warn!("Failed to acquire event subscriptions lock for unsubscribe");
                }
                Ok(None)
            }
            Message::Event(_event_data) => {
                // Clients shouldn't send events to the server, but we'll just log and ignore
                tracing::warn!("Client sent event message to server, ignoring");
                Ok(None)
            }
            Message::Custom(tag, data) => {
                let mut awareness = a.write().unwrap();
                protocol.missing_handle(&mut awareness, tag, data)
            }
        }
    }

    /// Send an event to this connection if it's subscribed to the event type
    pub fn send_event(&self, event: &EventMessage) -> Result<(), anyhow::Error> {
        // Check if connection is subscribed to this event type
        let is_subscribed = if let Ok(subscriptions) = self.event_subscriptions.read() {
            subscriptions.contains(&event.event_type)
        } else {
            tracing::warn!("Failed to acquire event subscriptions lock for send_event");
            return Ok(()); // Fail silently
        };

        if !is_subscribed {
            return Ok(()); // Not subscribed, don't send
        }

        // Serialize event to CBOR
        let cbor_data = event
            .to_cbor()
            .map_err(|e| anyhow::anyhow!("Failed to serialize event to CBOR: {:?}", e))?;

        // Send as Event message
        let msg = Message::Event(cbor_data).encode_v1();
        (self.callback)(&msg);

        tracing::debug!(
            "Sent event {} (type: {}) to client",
            event.event_id,
            event.event_type
        );

        Ok(())
    }

    /// Get the event types this connection is subscribed to
    pub fn get_event_subscriptions(&self) -> HashSet<String> {
        self.event_subscriptions
            .read()
            .map(|subscriptions| subscriptions.clone())
            .unwrap_or_default()
    }
}

impl Drop for DocConnection {
    fn drop(&mut self) {
        self.closed.set(()).unwrap();

        // If this client had an awareness state, remove it.
        if let Some(client_id) = self.client_id.get() {
            let mut awareness = self.awareness.write().unwrap();
            awareness.remove_state(*client_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{DefaultProtocol, EventMessage, Message};

    #[test]
    fn test_doc_connection_event_subscriptions() {
        let doc = yrs::Doc::new();
        let awareness = Arc::new(RwLock::new(Awareness::new(doc)));
        let (tx, _rx) = std::sync::mpsc::channel();

        let connection = DocConnection::new(awareness, Authorization::Full, move |_| {
            // Mock callback
            tx.send(()).unwrap();
        });

        // Initially no subscriptions
        assert!(connection.get_event_subscriptions().is_empty());

        // Subscribe to some event types
        let subscribe_msg = Message::EventSubscribe(vec![
            "document.updated".to_string(),
            "user.joined".to_string(),
        ]);

        let result = connection.handle_msg(&DefaultProtocol, subscribe_msg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Check subscriptions
        let subscriptions = connection.get_event_subscriptions();
        assert_eq!(subscriptions.len(), 2);
        assert!(subscriptions.contains("document.updated"));
        assert!(subscriptions.contains("user.joined"));

        // Unsubscribe from one event type
        let unsubscribe_msg = Message::EventUnsubscribe(vec!["user.joined".to_string()]);

        let result = connection.handle_msg(&DefaultProtocol, unsubscribe_msg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Check subscriptions after unsubscribe
        let subscriptions = connection.get_event_subscriptions();
        assert_eq!(subscriptions.len(), 1);
        assert!(subscriptions.contains("document.updated"));
        assert!(!subscriptions.contains("user.joined"));
    }

    #[test]
    fn test_doc_connection_send_event() {
        let doc = yrs::Doc::new();
        let awareness = Arc::new(RwLock::new(Awareness::new(doc)));
        let (tx, rx) = std::sync::mpsc::channel();

        let connection = Arc::new(DocConnection::new(
            awareness,
            Authorization::Full,
            move |bytes| {
                tx.send(bytes.to_vec()).unwrap();
            },
        ));

        // Subscribe to document.updated events
        let subscribe_msg = Message::EventSubscribe(vec!["document.updated".to_string()]);
        let result = connection.handle_msg(&DefaultProtocol, subscribe_msg);
        assert!(result.is_ok());

        // Create an event
        let event = EventMessage {
            event_id: "evt_test123".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "test_doc".to_string(),
            timestamp: 1640995200000,
            user: Some("test@example.com".to_string()),
            metadata: Some(serde_json::json!({"version": 2})),
            update: None,
        };

        // Send the event
        let result = connection.send_event(&event);
        assert!(result.is_ok());

        // Check that messages were sent in the correct order
        let _sync_step1 = rx.recv().unwrap(); // Initial SyncStep1
        let _awareness = rx.recv().unwrap(); // Initial Awareness
        let event_bytes = rx.recv().unwrap(); // From send_event

        // Decode the sent message
        let decoded_msg = Message::decode_v1(&event_bytes).unwrap();
        if let Message::Event(cbor_data) = decoded_msg {
            let decoded_event = EventMessage::from_cbor(&cbor_data).unwrap();
            assert_eq!(decoded_event, event);
        } else {
            panic!("Expected Event message");
        }
    }

    #[test]
    fn test_doc_connection_send_event_not_subscribed() {
        let doc = yrs::Doc::new();
        let awareness = Arc::new(RwLock::new(Awareness::new(doc)));
        let (tx, rx) = std::sync::mpsc::channel();

        let connection = Arc::new(DocConnection::new(
            awareness,
            Authorization::Full,
            move |bytes| {
                tx.send(bytes.to_vec()).unwrap();
            },
        ));

        // Don't subscribe to any events

        // Create an event
        let event = EventMessage {
            event_id: "evt_test123".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "test_doc".to_string(),
            timestamp: 1640995200000,
            user: None,
            metadata: None,
            update: None,
        };

        // Send the event - should succeed but not send anything
        let result = connection.send_event(&event);
        assert!(result.is_ok());

        // Check that no message was sent (only the initial handshake messages)
        let _sent_bytes = rx.recv().unwrap(); // Initial SyncStep1
        let _sent_bytes2 = rx.recv().unwrap(); // Initial Awareness

        // No more messages should be available immediately
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_doc_connection_handles_client_events() {
        let doc = yrs::Doc::new();
        let awareness = Arc::new(RwLock::new(Awareness::new(doc)));

        let connection = DocConnection::new(awareness, Authorization::Full, |_| {
            // Mock callback
        });

        // Client shouldn't send events to server, but we handle it gracefully
        let event = EventMessage {
            event_id: "evt_from_client".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "test_doc".to_string(),
            timestamp: 1640995200000,
            user: None,
            metadata: None,
            update: None,
        };

        let cbor_data = event.to_cbor().unwrap();
        let event_msg = Message::Event(cbor_data);

        let result = connection.handle_msg(&DefaultProtocol, event_msg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
