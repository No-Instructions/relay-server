//! Forked from [y-sync](https://github.com/y-crdt/y-sync/tree/master)

pub mod awareness;

use awareness::{Awareness, AwarenessUpdate};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use yrs::updates::decoder::{Decode, Decoder};
use yrs::updates::encoder::{Encode, Encoder};
use yrs::{ReadTxn, StateVector, Transact, Update};

/// Event message structure for CBOR serialization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventMessage {
    pub event_id: String,   // Unique event identifier
    pub event_type: String, // e.g., "document.updated"
    pub doc_id: String,     // Document that triggered the event
    pub timestamp: u64,     // Unix timestamp in milliseconds

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>, // User who triggered the event

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>, // Event-specific metadata

    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<Vec<u8>>, // Yjs update data for document.updated events
}

impl EventMessage {
    /// Serialize to CBOR bytes
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| Error::Other(format!("CBOR serialization failed: {}", e).into()))?;
        Ok(bytes)
    }

    /// Deserialize from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes)
            .map_err(|e| Error::Other(format!("CBOR deserialization failed: {}", e).into()))
    }
}

/*
 Core Yjs defines two message types:
 • YjsSyncStep1: Includes the State Set of the sending client. When received, the client should reply with YjsSyncStep2.
 • YjsSyncStep2: Includes all missing structs and the complete delete set. When received, the client is assured that it
   received all information from the remote client.

 In a peer-to-peer network, you may want to introduce a SyncDone message type. Both parties should initiate the connection
 with SyncStep1. When a client received SyncStep2, it should reply with SyncDone. When the local client received both
 SyncStep2 and SyncDone, it is assured that it is synced to the remote client.

 In a client-server model, you want to handle this differently: The client should initiate the connection with SyncStep1.
 When the server receives SyncStep1, it should reply with SyncStep2 immediately followed by SyncStep1. The client replies
 with SyncStep2 when it receives SyncStep1. Optionally the server may send a SyncDone after it received SyncStep2, so the
 client knows that the sync is finished.  There are two reasons for this more elaborated sync model: 1. This protocol can
 easily be implemented on top of http and websockets. 2. The server should only reply to requests, and not initiate them.
 Therefore, it is necessary that the client initiates the sync.

 Construction of a message:
 [messageType : varUint, message definition..]

 Note: A message does not include information about the room name. This must be handled by the upper layer protocol!

 stringify[messageType] stringifies a message definition (messageType is already read from the buffer)
*/

/// A default implementation of y-sync [Protocol].
pub struct DefaultProtocol;

impl Protocol for DefaultProtocol {}

/// Trait implementing a y-sync protocol. The default implementation can be found in
/// [DefaultProtocol], but its implementation steps can be potentially changed by the user if
/// necessary.
pub trait Protocol {
    /// To be called whenever a new connection has been accepted. Returns an encoded list of
    /// messages to be sent back to initiator. This binary may contain multiple messages inside,
    /// stored one after another.
    fn start<E: Encoder>(&self, awareness: &Awareness, encoder: &mut E) -> Result<(), Error> {
        let (sv, update) = {
            let sv = awareness.doc().transact().state_vector();
            let update = awareness.update()?;
            (sv, update)
        };
        Message::Sync(SyncMessage::SyncStep1(sv)).encode(encoder);
        Message::Awareness(update).encode(encoder);
        Ok(())
    }

    /// Y-sync protocol sync-step-1 - given a [StateVector] of a remote side, calculate missing
    /// updates. Returns a sync-step-2 message containing a calculated update.
    fn handle_sync_step1(
        &self,
        awareness: &Awareness,
        sv: StateVector,
    ) -> Result<Option<Message>, Error> {
        let update = awareness.doc().transact().encode_state_as_update_v1(&sv);
        Ok(Some(Message::Sync(SyncMessage::SyncStep2(update))))
    }

    /// Handle reply for a sync-step-1 send from this replica previously. By default, just apply
    /// an update to current `awareness` document instance.
    fn handle_sync_step2(
        &self,
        awareness: &mut Awareness,
        update: Update,
    ) -> Result<Option<Message>, Error> {
        let mut txn = awareness.doc().transact_mut();
        txn.apply_update(update);
        Ok(None)
    }

    /// Handle continuous update send from the client. By default just apply an update to a current
    /// `awareness` document instance.
    fn handle_update(
        &self,
        awareness: &mut Awareness,
        update: Update,
    ) -> Result<Option<Message>, Error> {
        self.handle_sync_step2(awareness, update)
    }

    /// Handle authorization message. By default, if reason for auth denial has been provided,
    /// send back [Error::PermissionDenied].
    fn handle_auth(
        &self,
        _awareness: &Awareness,
        deny_reason: Option<String>,
    ) -> Result<Option<Message>, Error> {
        if let Some(reason) = deny_reason {
            Err(Error::PermissionDenied { reason })
        } else {
            Ok(None)
        }
    }

    /// Returns an [AwarenessUpdate] which is a serializable representation of a current `awareness`
    /// instance.
    fn handle_awareness_query(&self, awareness: &Awareness) -> Result<Option<Message>, Error> {
        let update = awareness.update()?;
        Ok(Some(Message::Awareness(update)))
    }

    /// Reply to awareness query or just incoming [AwarenessUpdate], where current `awareness`
    /// instance is being updated with incoming data.
    fn handle_awareness_update(
        &self,
        awareness: &mut Awareness,
        update: AwarenessUpdate,
    ) -> Result<Option<Message>, Error> {
        awareness.apply_update(update)?;
        Ok(None)
    }

    /// Handle event subscription request. By default, logs the request and returns None.
    /// Implementations can override this to manage event subscriptions.
    fn handle_event_subscribe(
        &self,
        _awareness: &Awareness,
        event_types: Vec<String>,
    ) -> Result<Option<Message>, Error> {
        tracing::debug!("Event subscription request for types: {:?}", event_types);
        Ok(None)
    }

    /// Handle event unsubscription request. By default, logs the request and returns None.
    /// Implementations can override this to manage event subscriptions.
    fn handle_event_unsubscribe(
        &self,
        _awareness: &Awareness,
        event_types: Vec<String>,
    ) -> Result<Option<Message>, Error> {
        tracing::debug!("Event unsubscription request for types: {:?}", event_types);
        Ok(None)
    }

    /// Handle incoming event message. By default, logs and ignores the event.
    /// This should generally not be called on the server side.
    fn handle_event(
        &self,
        _awareness: &Awareness,
        event_data: Vec<u8>,
    ) -> Result<Option<Message>, Error> {
        tracing::debug!("Received event message with {} bytes", event_data.len());
        Ok(None)
    }

    /// Y-sync protocol enables to extend its own settings with custom handles. These can be
    /// implemented here. By default, it returns an [Error::Unsupported].
    fn missing_handle(
        &self,
        _awareness: &mut Awareness,
        tag: u8,
        _data: Vec<u8>,
    ) -> Result<Option<Message>, Error> {
        Err(Error::Unsupported(tag))
    }
}

/// Tag id for [Message::Sync].
pub const MSG_SYNC: u8 = 0;
/// Tag id for [Message::Awareness].
pub const MSG_AWARENESS: u8 = 1;
/// Tag id for [Message::Auth].
pub const MSG_AUTH: u8 = 2;
/// Tag id for [Message::AwarenessQuery].
pub const MSG_QUERY_AWARENESS: u8 = 3;
/// Tag id for [Message::Event].
pub const MSG_EVENT: u8 = 4;
/// Tag id for [Message::EventSubscribe].
pub const MSG_EVENT_SUBSCRIBE: u8 = 5;
/// Tag id for [Message::EventUnsubscribe].
pub const MSG_EVENT_UNSUBSCRIBE: u8 = 6;

pub const PERMISSION_DENIED: u8 = 0;
pub const PERMISSION_GRANTED: u8 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum Message {
    Sync(SyncMessage),
    Auth(Option<String>),
    AwarenessQuery,
    Awareness(AwarenessUpdate),
    Event(Vec<u8>),                // CBOR-encoded EventMessage
    EventSubscribe(Vec<String>),   // List of event types to subscribe to
    EventUnsubscribe(Vec<String>), // List of event types to unsubscribe from
    Custom(u8, Vec<u8>),
}

impl Encode for Message {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        match self {
            Message::Sync(msg) => {
                encoder.write_var(MSG_SYNC);
                msg.encode(encoder);
            }
            Message::Auth(reason) => {
                encoder.write_var(MSG_AUTH);
                if let Some(reason) = reason {
                    encoder.write_var(PERMISSION_DENIED);
                    encoder.write_string(reason);
                } else {
                    encoder.write_var(PERMISSION_GRANTED);
                }
            }
            Message::AwarenessQuery => {
                encoder.write_var(MSG_QUERY_AWARENESS);
            }
            Message::Awareness(update) => {
                encoder.write_var(MSG_AWARENESS);
                encoder.write_buf(update.encode_v1())
            }
            Message::Event(cbor_data) => {
                encoder.write_var(MSG_EVENT);
                encoder.write_buf(cbor_data);
            }
            Message::EventSubscribe(event_types) => {
                encoder.write_var(MSG_EVENT_SUBSCRIBE);
                encoder.write_var(event_types.len());
                for event_type in event_types {
                    encoder.write_string(event_type);
                }
            }
            Message::EventUnsubscribe(event_types) => {
                encoder.write_var(MSG_EVENT_UNSUBSCRIBE);
                encoder.write_var(event_types.len());
                for event_type in event_types {
                    encoder.write_string(event_type);
                }
            }
            Message::Custom(tag, data) => {
                encoder.write_u8(*tag);
                encoder.write_buf(data);
            }
        }
    }
}

impl Decode for Message {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, yrs::encoding::read::Error> {
        let tag: u8 = decoder.read_var()?;
        match tag {
            MSG_SYNC => {
                let msg = SyncMessage::decode(decoder)?;
                Ok(Message::Sync(msg))
            }
            MSG_AWARENESS => {
                let data = decoder.read_buf()?;
                let update = AwarenessUpdate::decode_v1(data)?;
                Ok(Message::Awareness(update))
            }
            MSG_AUTH => {
                let reason = if decoder.read_var::<u8>()? == PERMISSION_DENIED {
                    Some(decoder.read_string()?.to_string())
                } else {
                    None
                };
                Ok(Message::Auth(reason))
            }
            MSG_QUERY_AWARENESS => Ok(Message::AwarenessQuery),
            MSG_EVENT => {
                let data = decoder.read_buf()?;
                Ok(Message::Event(data.to_vec()))
            }
            MSG_EVENT_SUBSCRIBE => {
                let count: u64 = decoder.read_var()?;
                let mut event_types = Vec::new();
                for _ in 0..count {
                    let event_type = decoder.read_string()?.to_string();
                    event_types.push(event_type);
                }
                Ok(Message::EventSubscribe(event_types))
            }
            MSG_EVENT_UNSUBSCRIBE => {
                let count: u64 = decoder.read_var()?;
                let mut event_types = Vec::new();
                for _ in 0..count {
                    let event_type = decoder.read_string()?.to_string();
                    event_types.push(event_type);
                }
                Ok(Message::EventUnsubscribe(event_types))
            }
            tag => {
                let data = decoder.read_buf()?;
                Ok(Message::Custom(tag, data.to_vec()))
            }
        }
    }
}

/// Tag id for [SyncMessage::SyncStep1].
pub const MSG_SYNC_STEP_1: u8 = 0;
/// Tag id for [SyncMessage::SyncStep2].
pub const MSG_SYNC_STEP_2: u8 = 1;
/// Tag id for [SyncMessage::Update].
pub const MSG_SYNC_UPDATE: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncMessage {
    SyncStep1(StateVector),
    SyncStep2(Vec<u8>),
    Update(Vec<u8>),
}

impl Encode for SyncMessage {
    fn encode<E: Encoder>(&self, encoder: &mut E) {
        match self {
            SyncMessage::SyncStep1(sv) => {
                encoder.write_var(MSG_SYNC_STEP_1);
                encoder.write_buf(sv.encode_v1());
            }
            SyncMessage::SyncStep2(u) => {
                encoder.write_var(MSG_SYNC_STEP_2);
                encoder.write_buf(u);
            }
            SyncMessage::Update(u) => {
                encoder.write_var(MSG_SYNC_UPDATE);
                encoder.write_buf(u);
            }
        }
    }
}

impl Decode for SyncMessage {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, yrs::encoding::read::Error> {
        let tag: u8 = decoder.read_var()?;
        match tag {
            MSG_SYNC_STEP_1 => {
                let buf = decoder.read_buf()?;
                let sv = StateVector::decode_v1(buf)?;
                Ok(SyncMessage::SyncStep1(sv))
            }
            MSG_SYNC_STEP_2 => {
                let buf = decoder.read_buf()?;
                Ok(SyncMessage::SyncStep2(buf.into()))
            }
            MSG_SYNC_UPDATE => {
                let buf = decoder.read_buf()?;
                Ok(SyncMessage::Update(buf.into()))
            }
            _ => Err(yrs::encoding::read::Error::UnexpectedValue),
        }
    }
}

/// An error type returned in response from y-sync [Protocol].
#[derive(Debug, Error)]
pub enum Error {
    /// Incoming Y-protocol message couldn't be deserialized.
    #[error("failed to deserialize message: {0}")]
    EncodingError(#[from] yrs::encoding::read::Error),

    /// Applying incoming Y-protocol awareness update has failed.
    #[error("failed to process awareness update: {0}")]
    AwarenessEncoding(#[from] awareness::Error),

    /// An incoming Y-protocol authorization request has been denied.
    #[error("permission denied to access: {reason}")]
    PermissionDenied { reason: String },

    /// Thrown whenever an unknown message tag has been sent.
    #[error("unsupported message tag identifier: {0}")]
    Unsupported(u8),

    /// Custom dynamic kind of error, usually related to a warp internal error messages.
    #[error("internal failure: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Since y-sync protocol enables for a multiple messages to be packed into a singe byte payload,
/// [MessageReader] can be used over the decoder to read these messages one by one in iterable
/// fashion.
pub struct MessageReader<'a, D: Decoder>(&'a mut D);

impl<'a, D: Decoder> MessageReader<'a, D> {
    pub fn new(decoder: &'a mut D) -> Self {
        MessageReader(decoder)
    }
}

impl<'a, D: Decoder> Iterator for MessageReader<'a, D> {
    type Item = Result<Message, yrs::encoding::read::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match Message::decode(self.0) {
            Ok(msg) => Some(Ok(msg)),
            Err(yrs::encoding::read::Error::EndOfBuffer(_)) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        EventMessage, Message, SyncMessage, MSG_AUTH, MSG_AWARENESS, MSG_EVENT,
        MSG_EVENT_SUBSCRIBE, MSG_EVENT_UNSUBSCRIBE, MSG_QUERY_AWARENESS, MSG_SYNC,
    };
    use crate::sync::awareness::Awareness;
    use crate::sync::{DefaultProtocol, MessageReader, Protocol};
    use std::collections::HashMap;
    use yrs::encoding::read::Cursor;
    use yrs::updates::decoder::{Decode, DecoderV1};
    use yrs::updates::encoder::{Encode, Encoder, EncoderV1};
    use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact, Update};

    #[test]
    fn message_encoding() {
        let doc = Doc::new();
        let txt = doc.get_or_insert_text("text");
        txt.push(&mut doc.transact_mut(), "hello world");
        let mut awareness = Awareness::new(doc);
        awareness.set_local_state("{\"user\":{\"name\":\"Anonymous 50\",\"color\":\"#30bced\",\"colorLight\":\"#30bced33\"}}");

        let messages = [
            Message::Sync(SyncMessage::SyncStep1(
                awareness.doc().transact().state_vector(),
            )),
            Message::Sync(SyncMessage::SyncStep2(
                awareness
                    .doc()
                    .transact()
                    .encode_state_as_update_v1(&StateVector::default()),
            )),
            Message::Awareness(awareness.update().unwrap()),
            Message::Auth(Some("reason".to_string())),
            Message::AwarenessQuery,
        ];

        for msg in messages {
            let encoded = msg.encode_v1();
            let decoded = Message::decode_v1(&encoded)
                .unwrap_or_else(|_| panic!("failed to decode {:?}", msg));
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn protocol_init() {
        let awareness = Awareness::default();
        let protocol = DefaultProtocol;
        let mut encoder = EncoderV1::new();
        protocol.start(&awareness, &mut encoder).unwrap();
        let data = encoder.to_vec();
        let mut decoder = DecoderV1::new(Cursor::new(&data));
        let mut reader = MessageReader::new(&mut decoder);

        assert_eq!(
            reader.next().unwrap().unwrap(),
            Message::Sync(SyncMessage::SyncStep1(StateVector::default()))
        );

        assert_eq!(
            reader.next().unwrap().unwrap(),
            Message::Awareness(awareness.update().unwrap())
        );

        assert!(reader.next().is_none());
    }

    #[test]
    fn protocol_sync_steps() {
        let protocol = DefaultProtocol;

        let mut a1 = Awareness::new(Doc::with_client_id(1));
        let mut a2 = Awareness::new(Doc::with_client_id(2));

        let expected = {
            let txt = a1.doc_mut().get_or_insert_text("test");
            let mut txn = a1.doc_mut().transact_mut();
            txt.push(&mut txn, "hello");
            txn.encode_state_as_update_v1(&StateVector::default())
        };

        let result = protocol
            .handle_sync_step1(&a1, a2.doc().transact().state_vector())
            .unwrap();

        assert_eq!(
            result,
            Some(Message::Sync(SyncMessage::SyncStep2(expected)))
        );

        if let Some(Message::Sync(SyncMessage::SyncStep2(u))) = result {
            let result2 = protocol
                .handle_sync_step2(&mut a2, Update::decode_v1(&u).unwrap())
                .unwrap();

            assert!(result2.is_none());
        }

        let txt = a2.doc().transact().get_text("test").unwrap();
        assert_eq!(txt.get_string(&a2.doc().transact()), "hello".to_owned());
    }

    #[test]
    fn protocol_sync_step_update() {
        let protocol = DefaultProtocol;

        let mut a1 = Awareness::new(Doc::with_client_id(1));
        let mut a2 = Awareness::new(Doc::with_client_id(2));

        let data = {
            let txt = a1.doc_mut().get_or_insert_text("test");
            let mut txn = a1.doc_mut().transact_mut();
            txt.push(&mut txn, "hello");
            txn.encode_update_v1()
        };

        let result = protocol
            .handle_update(&mut a2, Update::decode_v1(&data).unwrap())
            .unwrap();

        assert!(result.is_none());

        let txt = a2.doc().transact().get_text("test").unwrap();
        assert_eq!(txt.get_string(&a2.doc().transact()), "hello".to_owned());
    }

    #[test]
    fn protocol_awareness_sync() {
        let protocol = DefaultProtocol;

        let mut a1 = Awareness::new(Doc::with_client_id(1));
        let mut a2 = Awareness::new(Doc::with_client_id(2));

        a1.set_local_state("{x:3}");
        let result = protocol.handle_awareness_query(&a1).unwrap();

        assert_eq!(result, Some(Message::Awareness(a1.update().unwrap())));

        if let Some(Message::Awareness(u)) = result {
            let result = protocol.handle_awareness_update(&mut a2, u).unwrap();
            assert!(result.is_none());
        }

        assert_eq!(a2.clients(), &HashMap::from([(1, "{x:3}".to_owned())]));
    }

    #[test]
    fn test_event_message_cbor_serialization() {
        let event = EventMessage {
            event_id: "evt_test123".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "test_doc".to_string(),
            timestamp: 1640995200000, // 2022-01-01 00:00:00 UTC
            user: Some("alice@example.com".to_string()),
            metadata: Some(serde_json::json!({
                "version": 2,
                "changes": ["text", "formatting"]
            })),
            update: None,
        };

        // Test serialization
        let cbor_bytes = event.to_cbor().unwrap();
        assert!(!cbor_bytes.is_empty());

        // Test deserialization
        let decoded_event = EventMessage::from_cbor(&cbor_bytes).unwrap();
        assert_eq!(decoded_event, event);
    }

    #[test]
    fn test_event_message_cbor_serialization_minimal() {
        let event = EventMessage {
            event_id: "evt_minimal".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "minimal_doc".to_string(),
            timestamp: 1640995200000,
            user: None,
            metadata: None,
            update: None,
        };

        let cbor_bytes = event.to_cbor().unwrap();
        let decoded_event = EventMessage::from_cbor(&cbor_bytes).unwrap();
        assert_eq!(decoded_event, event);
    }

    #[test]
    fn test_event_message_invalid_cbor() {
        let invalid_cbor = vec![0xff, 0x00, 0x01]; // Invalid CBOR data
        let result = EventMessage::from_cbor(&invalid_cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_subscribe_message_encoding() {
        let event_types = vec!["document.updated".to_string(), "user.joined".to_string()];
        let msg = Message::EventSubscribe(event_types.clone());

        let encoded = msg.encode_v1();
        let decoded = Message::decode_v1(&encoded).unwrap();

        assert_eq!(decoded, msg);
        if let Message::EventSubscribe(decoded_types) = decoded {
            assert_eq!(decoded_types, event_types);
        } else {
            panic!("Expected EventSubscribe message");
        }
    }

    #[test]
    fn test_event_unsubscribe_message_encoding() {
        let event_types = vec!["document.updated".to_string()];
        let msg = Message::EventUnsubscribe(event_types.clone());

        let encoded = msg.encode_v1();
        let decoded = Message::decode_v1(&encoded).unwrap();

        assert_eq!(decoded, msg);
        if let Message::EventUnsubscribe(decoded_types) = decoded {
            assert_eq!(decoded_types, event_types);
        } else {
            panic!("Expected EventUnsubscribe message");
        }
    }

    #[test]
    fn test_event_message_encoding() {
        let event = EventMessage {
            event_id: "evt_encode_test".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "encode_test_doc".to_string(),
            timestamp: 1640995200000,
            user: Some("test@example.com".to_string()),
            metadata: Some(serde_json::json!({"test": true})),
            update: None,
        };

        let cbor_data = event.to_cbor().unwrap();
        let msg = Message::Event(cbor_data.clone());

        let encoded = msg.encode_v1();
        let decoded = Message::decode_v1(&encoded).unwrap();

        assert_eq!(decoded, msg);
        if let Message::Event(decoded_cbor) = decoded {
            assert_eq!(decoded_cbor, cbor_data);

            // Verify we can decode the CBOR back to the original event
            let decoded_event = EventMessage::from_cbor(&decoded_cbor).unwrap();
            assert_eq!(decoded_event, event);
        } else {
            panic!("Expected Event message");
        }
    }

    #[test]
    fn test_empty_event_subscription_list() {
        let empty_types: Vec<String> = vec![];
        let msg = Message::EventSubscribe(empty_types.clone());

        let encoded = msg.encode_v1();
        let decoded = Message::decode_v1(&encoded).unwrap();

        assert_eq!(decoded, msg);
        if let Message::EventSubscribe(decoded_types) = decoded {
            assert_eq!(decoded_types, empty_types);
            assert!(decoded_types.is_empty());
        } else {
            panic!("Expected EventSubscribe message");
        }
    }

    #[test]
    fn test_large_event_subscription_list() {
        let event_types: Vec<String> = (0..100).map(|i| format!("event.type.{}", i)).collect();
        let msg = Message::EventSubscribe(event_types.clone());

        let encoded = msg.encode_v1();
        let decoded = Message::decode_v1(&encoded).unwrap();

        assert_eq!(decoded, msg);
        if let Message::EventSubscribe(decoded_types) = decoded {
            assert_eq!(decoded_types, event_types);
            assert_eq!(decoded_types.len(), 100);
        } else {
            panic!("Expected EventSubscribe message");
        }
    }

    #[test]
    fn test_protocol_handles_event_messages() {
        let protocol = DefaultProtocol;
        let awareness = Awareness::default();

        // Test event subscribe
        let result =
            protocol.handle_event_subscribe(&awareness, vec!["document.updated".to_string()]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test event unsubscribe
        let result =
            protocol.handle_event_unsubscribe(&awareness, vec!["document.updated".to_string()]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test event message
        let event = EventMessage {
            event_id: "evt_test".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "test_doc".to_string(),
            timestamp: 1640995200000,
            user: None,
            metadata: None,
            update: None,
        };
        let cbor_data = event.to_cbor().unwrap();
        let result = protocol.handle_event(&awareness, cbor_data);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_message_type_constants() {
        // Verify the message type constants have the expected values
        assert_eq!(MSG_SYNC, 0);
        assert_eq!(MSG_AWARENESS, 1);
        assert_eq!(MSG_AUTH, 2);
        assert_eq!(MSG_QUERY_AWARENESS, 3);
        assert_eq!(MSG_EVENT, 4);
        assert_eq!(MSG_EVENT_SUBSCRIBE, 5);
        assert_eq!(MSG_EVENT_UNSUBSCRIBE, 6);
    }

    #[test]
    fn test_all_message_types_roundtrip() {
        let doc = Doc::new();
        let txt = doc.get_or_insert_text("text");
        txt.push(&mut doc.transact_mut(), "hello world");
        let mut awareness = Awareness::new(doc);
        awareness.set_local_state("{\"user\":{\"name\":\"Test\"}}");

        // Test event message
        let event = EventMessage {
            event_id: "evt_roundtrip".to_string(),
            event_type: "document.updated".to_string(),
            doc_id: "roundtrip_doc".to_string(),
            timestamp: 1640995200000,
            user: Some("test@example.com".to_string()),
            metadata: Some(serde_json::json!({"test": "data"})),
            update: None,
        };
        let cbor_data = event.to_cbor().unwrap();

        let messages = [
            Message::Sync(SyncMessage::SyncStep1(
                awareness.doc().transact().state_vector(),
            )),
            Message::Sync(SyncMessage::SyncStep2(
                awareness
                    .doc()
                    .transact()
                    .encode_state_as_update_v1(&StateVector::default()),
            )),
            Message::Awareness(awareness.update().unwrap()),
            Message::Auth(Some("reason".to_string())),
            Message::Auth(None),
            Message::AwarenessQuery,
            Message::Event(cbor_data),
            Message::EventSubscribe(vec![
                "document.updated".to_string(),
                "user.joined".to_string(),
            ]),
            Message::EventUnsubscribe(vec!["user.left".to_string()]),
            Message::Custom(100, vec![1, 2, 3, 4]),
        ];

        for msg in messages {
            let encoded = msg.encode_v1();
            let decoded = Message::decode_v1(&encoded)
                .unwrap_or_else(|_| panic!("failed to decode {:?}", msg));
            assert_eq!(decoded, msg);
        }
    }
}
