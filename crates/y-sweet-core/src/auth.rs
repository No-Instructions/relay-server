use crate::api_types::Authorization;
use bincode::Options;
use data_encoding::Encoding;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use thiserror::Error;

pub const DEFAULT_EXPIRATION_SECONDS: u64 = 60 * 60; // 60 minutes

/// This newtype is introduced to distinguish between a u64 meant to represent the current time
/// (currently passed as a raw u64), and a u64 meant to represent an expiration time.
/// We introduce this to intentonally break callers to `gen_doc_token` that do not explicitly
/// update to pass an expiration time, so that calls that use the old signature to pass a current
/// time do not compile.
/// Unit is milliseconds since Jan 1, 1970.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExpirationTimeEpochMillis(pub u64);

impl ExpirationTimeEpochMillis {
    pub fn max() -> Self {
        Self(u64::MAX)
    }
}

/// This is a custom base64 encoder that is equivalent to BASE64URL_NOPAD for encoding,
/// but is tolerant when decoding of the “standard” alphabet and also of padding.
/// This is necessary for now because we used to use standard base64 encoding with padding,
/// but we can eventually remove it.
///
/// ```
/// use data_encoding::{Specification, BASE64URL_NOPAD, Translate};
/// let spec = Specification {
///     ignore: "=".to_string(),
///     translate: Translate {
///         from: "/+".to_string(),
///         to: "_-".to_string(),
///     },
///     ..BASE64URL_NOPAD.specification()
/// };
/// use y_sweet_core::auth::BASE64_CUSTOM;
/// assert_eq!(BASE64_CUSTOM, spec.encoding().unwrap());
/// ```
pub const BASE64_CUSTOM: Encoding = Encoding::internal_new(&[
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66, 67,
    68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66, 67, 68,
    69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98,
    99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 62, 128, 62, 128, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 128, 128, 128, 129, 128,
    128, 128, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 128, 128, 128, 128, 63, 128, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 30, 0,
]);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    #[error("The token is not a valid format")]
    InvalidToken,
    #[error("The token is expired")]
    Expired,
    #[error("The token is not valid for the requested resource")]
    InvalidResource,
    #[error("The token signature is invalid")]
    InvalidSignature,
    #[error("The key ID did not match")]
    KeyMismatch,
    #[error("Invalid CBOR structure")]
    InvalidCbor,
    #[error("Invalid COSE structure")]
    InvalidCose,
    #[error("Unsupported COSE algorithm")]
    UnsupportedAlgorithm,
    #[error("Invalid CWT claims")]
    InvalidClaims,
    #[error("HMAC signature verification failed")]
    HmacVerificationFailed,
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Debug, Clone)]
pub struct Authenticator {
    #[serde(with = "b64")]
    private_key: Vec<u8>,
    key_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DocPermission {
    pub doc_id: String,
    pub authorization: Authorization,
    pub user: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct FilePermission {
    pub file_hash: String,
    pub authorization: Authorization,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub doc_id: String,
    pub user: Option<String>,
}

// Legacy structs for backward compatibility with old tokens
#[derive(Serialize, Deserialize)]
struct LegacyDocPermission {
    pub doc_id: String,
    pub authorization: Authorization,
}

#[derive(Serialize, Deserialize)]
struct LegacyFilePermission {
    pub file_hash: String,
    pub authorization: Authorization,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub doc_id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct PrefixPermission {
    pub prefix: String,
    pub authorization: Authorization,
    pub user: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Permission {
    Server,
    Doc(DocPermission),
    File(FilePermission),
    Prefix(PrefixPermission),
}

// Legacy enums for backward compatibility
#[derive(Serialize, Deserialize)]
enum LegacyPermission {
    Server,
    Doc(LegacyDocPermission),
    File(LegacyFilePermission),
}

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub payload: Permission,
    pub expiration_millis: Option<ExpirationTimeEpochMillis>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub payload: Payload,
    pub token: Vec<u8>,
}

// Legacy structs for backward compatibility
#[derive(Serialize, Deserialize)]
struct LegacyPayload {
    pub payload: LegacyPermission,
    pub expiration_millis: Option<ExpirationTimeEpochMillis>,
}

#[derive(Serialize, Deserialize)]
struct LegacyAuthenticatedRequest {
    pub payload: LegacyPayload,
    pub token: Vec<u8>,
}

// Conversion from legacy to current structs
impl From<LegacyPermission> for Permission {
    fn from(legacy: LegacyPermission) -> Self {
        match legacy {
            LegacyPermission::Server => Permission::Server,
            LegacyPermission::Doc(doc) => Permission::Doc(DocPermission {
                doc_id: doc.doc_id,
                authorization: doc.authorization,
                user: None, // Old tokens don't have user field
            }),
            LegacyPermission::File(file) => Permission::File(FilePermission {
                file_hash: file.file_hash,
                authorization: file.authorization,
                content_type: file.content_type,
                content_length: file.content_length,
                doc_id: file.doc_id,
                user: None, // Old tokens don't have user field
            }),
        }
    }
}

impl From<LegacyPayload> for Payload {
    fn from(legacy: LegacyPayload) -> Self {
        Payload {
            payload: legacy.payload.into(),
            expiration_millis: legacy.expiration_millis,
        }
    }
}

impl From<LegacyAuthenticatedRequest> for AuthenticatedRequest {
    fn from(legacy: LegacyAuthenticatedRequest) -> Self {
        AuthenticatedRequest {
            payload: legacy.payload.into(),
            token: legacy.token,
        }
    }
}

fn bincode_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    // This uses different defaults than the default bincode::serialize() function.
    bincode::DefaultOptions::new().serialize(&value)
}

fn bincode_decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, bincode::Error> {
    // This uses different defaults than the default bincode::deserialize() function.
    bincode::DefaultOptions::new().deserialize(bytes)
}

fn b64_encode(bytes: &[u8]) -> String {
    BASE64_CUSTOM.encode(bytes)
}

fn b64_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    BASE64_CUSTOM
        .decode(input.as_bytes())
        .map_err(|_| AuthError::InvalidToken)
}

fn detect_key_type(key_bytes: &[u8]) -> &'static str {
    match key_bytes.len() {
        32 => "HMAC-SHA-256 (32 bytes)",
        33 => "ES256 compressed public key (33 bytes)",
        65 => "ES256 uncompressed public key (65 bytes)",
        _ => "Unknown key type",
    }
}

fn parse_key_format(input: &str) -> Result<Vec<u8>, AuthError> {
    let trimmed = input.trim();

    let key_bytes = if trimmed.starts_with("-----BEGIN") && trimmed.contains("-----END") {
        // Extract base64 content between PEM headers
        let lines: Vec<&str> = trimmed.lines().collect();
        let mut base64_content = String::new();

        let mut in_content = false;
        for line in lines {
            let line = line.trim();
            if line.starts_with("-----BEGIN") {
                in_content = true;
                continue;
            }
            if line.starts_with("-----END") {
                break;
            }
            if in_content && !line.is_empty() {
                base64_content.push_str(line);
            }
        }

        if base64_content.is_empty() {
            return Err(AuthError::InvalidToken);
        }

        tracing::info!("Parsed PEM format key");
        b64_decode(&base64_content)?
    } else {
        // Treat as raw base64
        tracing::info!("Parsed raw base64 key");
        b64_decode(trimmed)?
    };

    let key_type = detect_key_type(&key_bytes);
    tracing::info!("Detected key type: {}", key_type);

    Ok(key_bytes)
}

mod b64 {
    use super::*;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&b64_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        b64_decode(&s).map_err(de::Error::custom)
    }
}

impl Payload {
    pub fn new(payload: Permission) -> Self {
        Self {
            payload,
            expiration_millis: None,
        }
    }

    pub fn new_with_expiration(
        payload: Permission,
        expiration_millis: ExpirationTimeEpochMillis,
    ) -> Self {
        Self {
            payload,
            expiration_millis: Some(expiration_millis),
        }
    }
}

fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.to_vec()
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct KeyId(String);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KeyIdError {
    #[error("The key ID cannot be an empty string")]
    EmptyString,
    #[error("The key ID contains an invalid character: {ch}")]
    InvalidCharacter { ch: char },
}

impl KeyId {
    pub fn new(key_id: String) -> Result<Self, KeyIdError> {
        if key_id.is_empty() {
            return Err(KeyIdError::EmptyString);
        }

        let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for ch in key_id.chars() {
            if !valid_chars.contains(ch) {
                return Err(KeyIdError::InvalidCharacter { ch });
            }
        }

        Ok(Self(key_id))
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for KeyId {
    type Error = KeyIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

/// Token format enum for detecting token types
#[derive(Debug, PartialEq, Eq)]
pub enum TokenFormat {
    Custom,
    Cwt,
}

/// Detect the format of a token based on its structure
pub fn detect_token_format(token: &str) -> TokenFormat {
    // Remove key_id prefix if present for detection
    let token_data = if let Some((_, token_part)) = token.split_once('.') {
        token_part
    } else {
        token
    };

    // Try to decode as base64
    if let Ok(decoded) = b64_decode(token_data) {
        // First check if it can be decoded as bincode (custom format)
        // This should be checked first since bincode is our current format
        if bincode_decode::<AuthenticatedRequest>(&decoded).is_ok() {
            return TokenFormat::Custom;
        }

        // Check if it's a valid CWT structure (with CWT tag 61 and COSE message inside)
        let is_cwt = is_cwt_token(&decoded);
        if is_cwt {
            return TokenFormat::Cwt;
        }
    } else {
    }

    // Default to custom format for backward compatibility
    TokenFormat::Custom
}

fn is_cwt_token(data: &[u8]) -> bool {
    // Try to parse as CBOR value first
    if let Ok(cbor_value) = ciborium::de::from_reader(&data[..]) {
        match cbor_value {
            // Check for CWT tag 61 with inner COSE structure
            ciborium::Value::Tag(61, inner_value) => {
                // Inner value should be a COSE message (Sign1 or Mac0)
                let mut inner_bytes = Vec::new();
                if ciborium::ser::into_writer(&*inner_value, &mut inner_bytes).is_ok() {
                    // The inner value might itself be a tagged COSE message
                    if let Ok(inner_cbor) = ciborium::de::from_reader(&inner_bytes[..]) {
                        match inner_cbor {
                            ciborium::Value::Tag(inner_tag, _) => {
                                if inner_tag == 17 || inner_tag == 18 {
                                    return true;
                                }
                            }
                            _ => {}
                        }
                    }

                    let result = is_cose_message(&inner_bytes);
                    return result;
                }
            }
            ciborium::Value::Tag(_tag_num, _) => {
                return is_cose_message(data);
            }
            _ => {
                return is_cose_message(data);
            }
        }
    } else {
    }
    false
}

fn is_cose_message(data: &[u8]) -> bool {
    use coset::CborSerializable;

    let sign1_ok = coset::CoseSign1::from_slice(data).is_ok();
    let mac0_ok = coset::CoseMac0::from_slice(data).is_ok();

    sign1_ok || mac0_ok
}

impl Authenticator {
    pub fn new(key: &str) -> Result<Self, AuthError> {
        let private_key = parse_key_format(key)?;

        Ok(Self {
            private_key,
            key_id: None,
        })
    }

    pub fn server_token(&self) -> String {
        self.server_token_cwt()
    }

    fn sign(&self, payload: Payload) -> String {
        let mut hash_payload =
            bincode_encode(&payload).expect("Bincode serialization should not fail.");
        hash_payload.extend_from_slice(&self.private_key);

        let token = hash(&hash_payload);

        let auth_req = AuthenticatedRequest { payload, token };

        let auth_enc = bincode_encode(&auth_req).expect("Bincode serialization should not fail.");
        let result = b64_encode(&auth_enc);
        if let Some(key_id) = &self.key_id {
            format!("{}.{}", key_id, result)
        } else {
            result
        }
    }

    fn verify(&self, token: &str, current_time: u64) -> Result<Payload, AuthError> {
        let token = if let Some((prefix, token)) = token.split_once('.') {
            if Some(prefix) != self.key_id.as_deref() {
                return Err(AuthError::KeyMismatch);
            }

            token
        } else {
            if self.key_id.is_some() {
                return Err(AuthError::KeyMismatch);
            }

            token
        };

        // Try to decode with current format first, fallback to legacy format
        let decoded_bytes = b64_decode(token)?;

        // First try current format
        if let Ok(auth_req) = bincode_decode::<AuthenticatedRequest>(&decoded_bytes) {
            let mut payload =
                bincode_encode(&auth_req.payload).expect("Bincode serialization should not fail.");
            payload.extend_from_slice(&self.private_key);
            let expected_token = hash(&payload);

            if expected_token != auth_req.token {
                return Err(AuthError::InvalidSignature);
            } else if auth_req
                .payload
                .expiration_millis
                .unwrap_or(ExpirationTimeEpochMillis::max())
                .0
                < current_time
            {
                return Err(AuthError::Expired);
            } else {
                return Ok(auth_req.payload);
            }
        }

        // Try legacy format
        if let Ok(legacy_req) = bincode_decode::<LegacyAuthenticatedRequest>(&decoded_bytes) {
            // For legacy tokens, we need to verify using the legacy payload structure
            let mut payload = bincode_encode(&legacy_req.payload)
                .expect("Bincode serialization should not fail.");
            payload.extend_from_slice(&self.private_key);
            let expected_token = hash(&payload);

            if expected_token != legacy_req.token {
                return Err(AuthError::InvalidSignature);
            }

            // Convert to current format
            let auth_req: AuthenticatedRequest = legacy_req.into();

            if auth_req
                .payload
                .expiration_millis
                .unwrap_or(ExpirationTimeEpochMillis::max())
                .0
                < current_time
            {
                return Err(AuthError::Expired);
            } else {
                return Ok(auth_req.payload);
            }
        }

        Err(AuthError::InvalidToken)
    }

    pub fn with_key_id(self, key_id: KeyId) -> Self {
        Self {
            key_id: Some(key_id.0),
            ..self
        }
    }

    pub fn verify_server_token(
        &self,
        token: &str,
        current_time_epoch_millis: u64,
    ) -> Result<(), AuthError> {
        let permission = self.verify_token_auto(token, current_time_epoch_millis)?;
        match permission {
            Permission::Server => Ok(()),
            _ => Err(AuthError::InvalidResource),
        }
    }

    pub fn private_key(&self) -> String {
        b64_encode(&self.private_key)
    }

    pub fn gen_doc_token(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        user: Option<&str>,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::Doc(DocPermission {
                doc_id: doc_id.to_string(),
                authorization,
                user: user.map(|u| u.to_string()),
            }),
            expiration_time,
        );
        self.sign(payload)
    }

    pub fn gen_file_token(
        &self,
        file_hash: &str,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        content_type: Option<&str>,
        content_length: Option<u64>,
        user: Option<&str>,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::File(FilePermission {
                file_hash: file_hash.to_string(),
                doc_id: doc_id.to_string(),
                authorization,
                content_type: content_type.map(|s| s.to_string()),
                content_length,
                user: user.map(|u| u.to_string()),
            }),
            expiration_time,
        );
        self.sign(payload)
    }

    /// Generate a CWT server token
    pub fn server_token_cwt(&self) -> String {
        self.gen_cwt_token(Permission::Server, None)
    }

    /// Generate a CWT document token
    pub fn gen_doc_token_cwt(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        user: Option<&str>,
        channel: Option<String>,
    ) -> String {
        // Validate channel if provided
        if let Some(ref channel_name) = channel {
            if !crate::api_types::validate_key(channel_name) {
                panic!("Invalid channel name: must contain only alphanumeric characters, hyphens, and underscores");
            }
        }

        let permission = Permission::Doc(DocPermission {
            doc_id: doc_id.to_string(),
            authorization,
            user: user.map(|u| u.to_string()),
        });
        self.gen_cwt_token_with_channel(permission, Some(expiration_time), channel)
    }

    /// Generate a CWT file token
    pub fn gen_file_token_cwt(
        &self,
        file_hash: &str,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        content_type: Option<&str>,
        content_length: Option<u64>,
        user: Option<&str>,
        channel: Option<String>,
    ) -> String {
        // Validate channel if provided
        if let Some(ref channel_name) = channel {
            if !crate::api_types::validate_key(channel_name) {
                panic!("Invalid channel name: must contain only alphanumeric characters, hyphens, and underscores");
            }
        }

        let permission = Permission::File(FilePermission {
            file_hash: file_hash.to_string(),
            doc_id: doc_id.to_string(),
            authorization,
            content_type: content_type.map(|s| s.to_string()),
            content_length,
            user: user.map(|u| u.to_string()),
        });
        self.gen_cwt_token_with_channel(permission, Some(expiration_time), channel)
    }

    /// Generate a prefix token (custom format)
    pub fn gen_prefix_token(
        &self,
        prefix: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        user: Option<&str>,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::Prefix(PrefixPermission {
                prefix: prefix.to_string(),
                authorization,
                user: user.map(|u| u.to_string()),
            }),
            expiration_time,
        );
        self.sign(payload)
    }

    /// Generate a CWT prefix token
    pub fn gen_prefix_token_cwt(
        &self,
        prefix: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        user: Option<&str>,
    ) -> String {
        let permission = Permission::Prefix(PrefixPermission {
            prefix: prefix.to_string(),
            authorization,
            user: user.map(|u| u.to_string()),
        });
        self.gen_cwt_token(permission, Some(expiration_time))
    }

    /// Generate a CWT token for any permission type
    fn gen_cwt_token(
        &self,
        permission: Permission,
        expiration_time: Option<ExpirationTimeEpochMillis>,
    ) -> String {
        self.gen_cwt_token_with_channel(permission, expiration_time, None)
    }

    fn gen_cwt_token_with_channel(
        &self,
        permission: Permission,
        expiration_time: Option<ExpirationTimeEpochMillis>,
        channel: Option<String>,
    ) -> String {
        use crate::cwt::{permission_to_scope, CwtAuthenticator, CwtClaims};

        let cwt_auth = CwtAuthenticator::new(&self.private_key, self.key_id.clone())
            .expect("CWT authenticator creation should not fail");

        // Extract user information from permission
        let subject = match &permission {
            Permission::Doc(doc_perm) => doc_perm.user.clone(),
            Permission::File(file_perm) => file_perm.user.clone(),
            Permission::Prefix(prefix_perm) => prefix_perm.user.clone(),
            Permission::Server => None,
        };

        let claims = CwtClaims {
            issuer: Some("relay-server".to_string()),
            subject,
            audience: None,
            expiration: expiration_time.map(|exp| exp.0 / 1000), // Convert to seconds
            issued_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            scope: permission_to_scope(&permission),
            channel,
        };

        let token_bytes = cwt_auth
            .create_cwt(claims)
            .expect("CWT creation should not fail");

        let token = b64_encode(&token_bytes);

        if let Some(key_id) = &self.key_id {
            format!("{}.{}", key_id, token)
        } else {
            token
        }
    }

    pub fn verify_doc_token(
        &self,
        token: &str,
        doc: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Authorization, AuthError> {
        let payload = self.verify_token_auto(token, current_time_epoch_millis)?;

        match payload {
            Permission::Doc(doc_permission) => {
                if doc_permission.doc_id == doc {
                    Ok(doc_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::File(file_permission) => {
                // Only check for file tokens using doc_id, not file_hash
                // This prevents document tokens from being misinterpreted
                if file_permission.doc_id == doc {
                    Ok(file_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Prefix(prefix_permission) => {
                if doc.starts_with(&prefix_permission.prefix) {
                    Ok(prefix_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Server => Ok(Authorization::Full), // Server tokens can access any doc.
        }
    }

    pub fn verify_file_token(
        &self,
        token: &str,
        file_hash: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Authorization, AuthError> {
        let payload = self.verify_token_auto(token, current_time_epoch_millis)?;

        match payload {
            Permission::File(file_permission) => {
                if file_permission.file_hash == file_hash {
                    Ok(file_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Server => Ok(Authorization::Full), // Server tokens can access any file
            _ => Err(AuthError::InvalidResource),
        }
    }

    pub fn verify_file_token_for_doc(
        &self,
        token: &str,
        doc_id: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Authorization, AuthError> {
        let payload = self.verify_token_auto(token, current_time_epoch_millis)?;

        match payload {
            Permission::File(file_permission) => {
                if file_permission.doc_id == doc_id {
                    Ok(file_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Doc(doc_permission) => {
                // Allow Doc tokens to perform file operations for their doc_id
                if doc_permission.doc_id == doc_id {
                    Ok(doc_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Prefix(prefix_permission) => {
                if doc_id.starts_with(&prefix_permission.prefix) {
                    Ok(prefix_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Server => Ok(Authorization::Full), // Server tokens can access any doc
        }
    }

    pub fn file_token_metadata(
        &self,
        token: &str,
    ) -> Result<Option<(String, Option<String>, Option<u64>)>, AuthError> {
        let payload = self.decode_token(token)?;

        match payload.payload {
            Permission::File(file_permission) => Ok(Some((
                file_permission.doc_id,
                file_permission.content_type,
                file_permission.content_length,
            ))),
            _ => Ok(None), // Not a file token
        }
    }

    pub fn gen_key() -> Result<Authenticator, AuthError> {
        Self::gen_key_hmac()
    }

    pub fn gen_key_hmac() -> Result<Authenticator, AuthError> {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let key = b64_encode(&key);

        let authenticator = Authenticator::new(&key)?;
        Ok(authenticator)
    }

    pub fn gen_key_ecdsa() -> Result<Authenticator, AuthError> {
        use p256::SecretKey;
        use rand::rngs::OsRng;

        let secret_key = SecretKey::random(&mut OsRng);
        let private_key_bytes = secret_key.to_bytes();

        Ok(Authenticator {
            private_key: private_key_bytes.to_vec(),
            key_id: None,
        })
    }

    pub fn decode_token(&self, token: &str) -> Result<Payload, AuthError> {
        let token = if let Some((_, token)) = token.split_once('.') {
            token
        } else {
            token
        };

        // Try to decode with current format first, fallback to legacy format
        let decoded_bytes = b64_decode(token)?;
        let auth_req: AuthenticatedRequest =
            match bincode_decode::<AuthenticatedRequest>(&decoded_bytes) {
                Ok(req) => req,
                Err(_) => {
                    // Try legacy format
                    match bincode_decode::<LegacyAuthenticatedRequest>(&decoded_bytes) {
                        Ok(legacy_req) => legacy_req.into(),
                        Err(_) => return Err(AuthError::InvalidToken),
                    }
                }
            };

        Ok(auth_req.payload)
    }

    /// Verify a token automatically detecting its format (custom or CWT)
    pub fn verify_token_auto(
        &self,
        token: &str,
        current_time: u64,
    ) -> Result<Permission, AuthError> {
        match detect_token_format(token) {
            TokenFormat::Custom => {
                let payload = self.verify(token, current_time)?;
                Ok(payload.payload)
            }
            TokenFormat::Cwt => self.verify_cwt_token(token, current_time),
        }
    }

    /// Verify a CWT token and extract the permission
    fn verify_cwt_token(&self, token: &str, current_time: u64) -> Result<Permission, AuthError> {
        let (permission, _) = self.verify_cwt_token_with_channel(token, current_time)?;
        Ok(permission)
    }

    /// Verify a CWT token and extract both permission and channel
    fn verify_cwt_token_with_channel(
        &self,
        token: &str,
        current_time: u64,
    ) -> Result<(Permission, Option<String>), AuthError> {
        use crate::cwt::{scope_to_permission, CwtAuthenticator};

        tracing::debug!("Starting CWT token verification");

        // Remove key_id prefix if present
        let token_data = if let Some((prefix, token_part)) = token.split_once('.') {
            if Some(prefix) != self.key_id.as_deref() {
                tracing::debug!(
                    "Key ID mismatch - expected: {:?}, got: {}",
                    self.key_id,
                    prefix
                );
                return Err(AuthError::KeyMismatch);
            }
            token_part
        } else {
            if self.key_id.is_some() {
                tracing::debug!(
                    "Expected key_id prefix but token has none, configured key_id: {:?}",
                    self.key_id
                );
                return Err(AuthError::KeyMismatch);
            }
            token
        };

        let token_bytes = b64_decode(token_data).map_err(|e| {
            tracing::error!("Base64 decode failed: {}", e);
            e
        })?;

        let cwt_auth =
            CwtAuthenticator::new(&self.private_key, self.key_id.clone()).map_err(|e| {
                tracing::error!("Failed to create CWT authenticator: {:?}", e);
                AuthError::InvalidToken
            })?;

        let claims = cwt_auth.verify_cwt(&token_bytes).map_err(|e| match e {
            crate::cwt::CwtError::InvalidCbor => {
                tracing::debug!("Token has invalid CBOR structure");
                AuthError::InvalidCbor
            }
            crate::cwt::CwtError::InvalidCose => {
                tracing::debug!("Token has invalid COSE structure");
                AuthError::InvalidCose
            }
            crate::cwt::CwtError::InvalidClaims => {
                tracing::debug!("Token has invalid claims structure");
                AuthError::InvalidClaims
            }
            crate::cwt::CwtError::HmacVerificationFailed => {
                tracing::debug!("HMAC signature verification failed");
                AuthError::HmacVerificationFailed
            }
            _ => {
                tracing::debug!("Other CWT error: {:?}", e);
                AuthError::InvalidToken
            }
        })?;

        tracing::trace!(
            "CWT verification successful - issuer: {:?}, scope: {}",
            claims.issuer,
            claims.scope
        );

        // Validate issuer - accept relay-server, auth.system3.dev, and auth.system3.md
        if let Some(ref issuer) = claims.issuer {
            const VALID_ISSUERS: &[&str] = &["relay-server", "auth.system3.dev", "auth.system3.md"];
            if !VALID_ISSUERS.contains(&issuer.as_str()) {
                tracing::debug!("Invalid issuer: {}", issuer);
                return Err(AuthError::InvalidClaims);
            }
        }

        // Check expiration
        if let Some(exp) = claims.expiration {
            let exp_millis = exp * 1000;
            if exp_millis < current_time {
                tracing::debug!("Token expired");
                return Err(AuthError::Expired);
            }
        }

        // Parse permission from scope and add user information from subject
        let mut permission = scope_to_permission(&claims.scope).map_err(|e| {
            tracing::debug!("Failed to parse scope '{}': {:?}", claims.scope, e);
            AuthError::InvalidClaims
        })?;

        // Add user information from the subject field
        match &mut permission {
            Permission::Doc(doc_perm) => {
                doc_perm.user = claims.subject.clone();
            }
            Permission::File(file_perm) => {
                file_perm.user = claims.subject.clone();
            }
            Permission::Prefix(prefix_perm) => {
                prefix_perm.user = claims.subject.clone();
            }
            Permission::Server => {}
        }

        tracing::debug!("CWT token verification successful");
        Ok((permission, claims.channel))
    }

    /// Extract user information from a token (works with both custom and CWT tokens)
    pub fn extract_user_from_token(&self, token: &str) -> Result<Option<String>, AuthError> {
        match detect_token_format(token) {
            TokenFormat::Custom => {
                let payload = self.decode_token(token)?;
                match payload.payload {
                    Permission::Doc(doc_perm) => Ok(doc_perm.user),
                    Permission::File(file_perm) => Ok(file_perm.user),
                    Permission::Prefix(prefix_perm) => Ok(prefix_perm.user),
                    Permission::Server => Ok(None),
                }
            }
            TokenFormat::Cwt => {
                use crate::cwt::CwtAuthenticator;

                // Remove key_id prefix if present
                let token_data = if let Some((prefix, token_part)) = token.split_once('.') {
                    if Some(prefix) != self.key_id.as_deref() {
                        return Err(AuthError::KeyMismatch);
                    }
                    token_part
                } else {
                    if self.key_id.is_some() {
                        return Err(AuthError::KeyMismatch);
                    }
                    token
                };

                let token_bytes = b64_decode(token_data)?;
                let cwt_auth = CwtAuthenticator::new(&self.private_key, self.key_id.clone())
                    .map_err(|_| AuthError::InvalidToken)?;

                let claims = cwt_auth
                    .verify_cwt(&token_bytes)
                    .map_err(|_| AuthError::InvalidToken)?;

                Ok(claims.subject)
            }
        }
    }

    /// Verify a document token and return both authorization and user information
    pub fn verify_doc_token_with_user(
        &self,
        token: &str,
        doc_id: &str,
        current_time: u64,
    ) -> Result<(Authorization, Option<String>), AuthError> {
        let auth = self.verify_doc_token(token, doc_id, current_time)?;
        let user = self.extract_user_from_token(token)?;
        Ok((auth, user))
    }

    /// Verify a file token and return both authorization and user information
    pub fn verify_file_token_with_user(
        &self,
        token: &str,
        file_hash: &str,
        current_time: u64,
    ) -> Result<(Authorization, Option<String>), AuthError> {
        let auth = self.verify_file_token(token, file_hash, current_time)?;
        let user = self.extract_user_from_token(token)?;
        Ok((auth, user))
    }

    /// Verify a document token with prefix support and return both authorization and user information
    pub fn verify_doc_token_with_prefix(
        &self,
        token: &str,
        doc_id: &str,
        current_time: u64,
    ) -> Result<(Authorization, Option<String>), AuthError> {
        // Try direct doc token first
        if let Ok(auth) = self.verify_doc_token(token, doc_id, current_time) {
            let user = self.extract_user_from_token(token)?;
            return Ok((auth, user));
        }

        // Try prefix tokens
        let permission = self.verify_token_auto(token, current_time)?;
        match permission {
            Permission::Prefix(prefix_permission) => {
                if doc_id.starts_with(&prefix_permission.prefix) {
                    Ok((prefix_permission.authorization, prefix_permission.user))
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            _ => Err(AuthError::InvalidResource),
        }
    }

    /// Verify a token and extract channel claim (CWT tokens only)
    pub fn verify_token_with_channel(
        &self,
        token: &str,
        current_time: u64,
    ) -> Result<(Permission, Option<String>), AuthError> {
        match detect_token_format(token) {
            TokenFormat::Custom => {
                let payload = self.verify(token, current_time)?;
                Ok((payload.payload, None)) // Custom tokens don't have channel claims
            }
            TokenFormat::Cwt => {
                let (permission, channel) =
                    self.verify_cwt_token_with_channel(token, current_time)?;
                Ok((permission, channel))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_token_with_metadata() {
        let authenticator = Authenticator::gen_key().unwrap();
        let file_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let doc_id = "doc123";
        let content_type = "application/json";
        let content_length = 12345;

        // Generate token with content-type and length
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            Some(content_type),
            Some(content_length),
            None,
        );

        // Verify the token works for file hash authentication
        assert!(matches!(
            authenticator.verify_file_token(&token, file_hash, 0),
            Ok(Authorization::Full)
        ));

        // Verify the token works for doc authentication
        assert!(matches!(
            authenticator.verify_file_token_for_doc(&token, doc_id, 0),
            Ok(Authorization::Full)
        ));

        // Decode the token and verify metadata
        let payload = authenticator.decode_token(&token).unwrap();
        if let Permission::File(file_permission) = payload.payload {
            assert_eq!(file_permission.file_hash, file_hash);
            assert_eq!(file_permission.doc_id, doc_id);
            assert_eq!(file_permission.content_type, Some(content_type.to_string()));
            assert_eq!(file_permission.content_length, Some(content_length));
        } else {
            panic!("Expected File permission type");
        }

        // Test file_token_metadata
        let metadata = authenticator.file_token_metadata(&token).unwrap().unwrap();
        assert_eq!(metadata.0, doc_id);
        assert_eq!(metadata.1, Some(content_type.to_string()));
        assert_eq!(metadata.2, Some(content_length));
    }

    #[test]
    fn test_file_token_without_metadata() {
        let authenticator = Authenticator::gen_key().unwrap();
        let file_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let doc_id = "doc123";

        // Generate token without content-type and length
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
            None,
            None,
        );

        // Verify the token with file hash
        assert!(matches!(
            authenticator.verify_file_token(&token, file_hash, 0),
            Ok(Authorization::Full)
        ));

        // Verify the token with doc id
        assert!(matches!(
            authenticator.verify_file_token_for_doc(&token, doc_id, 0),
            Ok(Authorization::Full)
        ));

        // Decode the token and verify no metadata present
        let payload = authenticator.decode_token(&token).unwrap();
        if let Permission::File(file_permission) = payload.payload {
            assert_eq!(file_permission.file_hash, file_hash);
            assert_eq!(file_permission.doc_id, doc_id);
            assert_eq!(file_permission.content_type, None);
            assert_eq!(file_permission.content_length, None);
        } else {
            panic!("Expected File permission type");
        }
    }

    #[test]
    fn test_flex_b64() {
        let expect = [3, 242, 3, 248, 6, 220, 118];

        assert_eq!(b64_decode("A/ID+Abcdg==").unwrap(), expect);
        assert_eq!(b64_decode("A/ID+Abcdg").unwrap(), expect);

        assert_eq!(b64_decode("A_ID-Abcdg==").unwrap(), expect);
        assert_eq!(b64_decode("A_ID-Abcdg").unwrap(), expect);
    }

    #[test]
    fn test_b64_encode_options() {
        let data = [3, 242, 3, 248, 6, 220, 118];

        assert_eq!(b64_encode(&data), "A_ID-Abcdg");
    }

    #[test]
    fn test_simple_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", DEFAULT_EXPIRATION_SECONDS + 1),
            Err(AuthError::Expired)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc456", 0),
            Err(AuthError::InvalidResource)
        ));
    }

    #[test]
    fn test_read_only_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(0),
            None,
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::ReadOnly)
        ));
    }

    #[test]
    fn test_server_token_for_doc_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let server_token = authenticator.server_token();
        assert!(matches!(
            authenticator.verify_doc_token(&server_token, "doc123", 0),
            Ok(Authorization::Full)
        ));
    }

    #[test]
    fn test_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
        );
        assert!(
            token.starts_with("myKeyId."),
            "Token {} does not start with myKeyId.",
            token
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));

        let token = authenticator.server_token();
        assert!(
            token.starts_with("myKeyId."),
            "Token {} does not start with myKeyId.",
            token
        );
        assert_eq!(authenticator.verify_server_token(&token, 0), Ok(()));
    }

    #[test]
    fn test_construct_key_id() {
        assert_eq!(KeyId::new("".to_string()), Err(KeyIdError::EmptyString));
        assert_eq!(
            KeyId::new("*".to_string()),
            Err(KeyIdError::InvalidCharacter { ch: '*' })
        );
        assert_eq!(
            KeyId::new("myKeyId".to_string()),
            Ok(KeyId("myKeyId".to_string()))
        );
    }

    #[test]
    fn test_key_id_mismatch() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
        );
        let token = token.replace("myKeyId.", "aDifferentKeyId.");
        assert!(token.starts_with("aDifferentKeyId."));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_missing_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
        );
        let token = token.replace("myKeyId.", "");
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_unexpected_key_id() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
        );
        let token = format!("unexpectedKeyId.{}", token);
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let authenticator = Authenticator::gen_key().unwrap();
        let actual_payload = Payload::new(Permission::Doc(DocPermission {
            doc_id: "doc123".to_string(),
            authorization: Authorization::Full,
            user: None,
        }));
        let mut encoded_payload =
            bincode_encode(&actual_payload).expect("Bincode serialization should not fail.");
        encoded_payload.extend_from_slice(&authenticator.private_key);

        let token = hash(&encoded_payload);

        let auth_req = AuthenticatedRequest {
            payload: Payload::new(Permission::Doc(DocPermission {
                doc_id: "abc123".to_string(),
                authorization: Authorization::Full,
                user: None,
            })),
            token,
        };

        let auth_enc = bincode_encode(&auth_req).expect("Bincode serialization should not fail.");
        let signed = b64_encode(&auth_enc);

        assert!(matches!(
            authenticator.verify_doc_token(&signed, "doc123", 0),
            Err(AuthError::InvalidSignature)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&signed, "abc123", 0),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn test_roundtrip_serde_authenticator() {
        let authenticator = Authenticator::gen_key().unwrap();
        let serialized = serde_json::to_string(&authenticator).unwrap();
        let deserialized: Authenticator = serde_json::from_str(&serialized).unwrap();
        assert_eq!(authenticator, deserialized);
    }

    // CWT Token Tests
    #[test]
    fn test_cwt_server_token() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.server_token_cwt();

        assert_eq!(detect_token_format(&token), TokenFormat::Cwt);

        // Verify the token works
        assert_eq!(authenticator.verify_server_token(&token, 0), Ok(()));
    }

    #[test]
    fn test_cwt_doc_token() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
        );

        assert_eq!(detect_token_format(&token), TokenFormat::Cwt);

        // Verify the token works
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));

        // Verify it fails for wrong doc
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc456", 0),
            Err(AuthError::InvalidResource)
        ));
    }

    #[test]
    fn test_cwt_file_token() {
        let authenticator = Authenticator::gen_key().unwrap();
        let file_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let doc_id = "doc123";

        let token = authenticator.gen_file_token_cwt(
            file_hash,
            doc_id,
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("application/json"),
            Some(12345),
            None,
            None,
        );

        assert_eq!(detect_token_format(&token), TokenFormat::Cwt);

        // Verify the token works for file hash
        assert!(matches!(
            authenticator.verify_file_token(&token, file_hash, 0),
            Ok(Authorization::ReadOnly)
        ));

        // Verify the token works for doc id
        assert!(matches!(
            authenticator.verify_file_token_for_doc(&token, doc_id, 0),
            Ok(Authorization::ReadOnly)
        ));
    }

    #[test]
    fn test_token_format_detection() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Custom token
        let custom_token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
        );
        assert_eq!(detect_token_format(&custom_token), TokenFormat::Custom);

        // CWT token
        let cwt_token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
        );
        assert_eq!(detect_token_format(&cwt_token), TokenFormat::Cwt);
    }

    #[test]
    fn test_mixed_token_verification() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Custom tokens should work with auto verification
        let custom_token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
        );
        assert!(matches!(
            authenticator.verify_doc_token(&custom_token, "doc123", 0),
            Ok(Authorization::Full)
        ));

        // CWT tokens should work with auto verification
        let cwt_token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
        );
        assert!(matches!(
            authenticator.verify_doc_token(&cwt_token, "doc123", 0),
            Ok(Authorization::ReadOnly)
        ));
    }

    #[test]
    fn test_cwt_token_with_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("test_key".try_into().unwrap());

        let token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
        );

        assert!(token.starts_with("test_key."));
        assert_eq!(detect_token_format(&token), TokenFormat::Cwt);

        // Verify the token works
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));
    }

    #[test]
    fn test_cwt_expiration() {
        let authenticator = Authenticator::gen_key().unwrap();
        let short_expiration = ExpirationTimeEpochMillis(1000); // 1 second after epoch

        let token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            short_expiration,
            None,
            None,
        );

        // Should fail with expired error
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 2000),
            Err(AuthError::Expired)
        ));
    }

    #[test]
    fn test_cwt_invalid_signature() {
        let authenticator1 = Authenticator::gen_key().unwrap();
        let authenticator2 = Authenticator::gen_key().unwrap();

        let token = authenticator1.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
        );

        // Should fail with signature verification error
        assert!(matches!(
            authenticator2.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::HmacVerificationFailed)
        ));
    }

    #[test]
    fn test_user_identification_custom_tokens() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Test doc token with user
        let doc_token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("user123"),
        );

        let user = authenticator.extract_user_from_token(&doc_token).unwrap();
        assert_eq!(user, Some("user123".to_string()));

        let (auth, user) = authenticator
            .verify_doc_token_with_user(&doc_token, "doc123", 0)
            .unwrap();
        assert_eq!(auth, Authorization::Full);
        assert_eq!(user, Some("user123".to_string()));

        // Test file token with user
        let file_token = authenticator.gen_file_token(
            "hash123",
            "doc456",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
            Some("user456"),
        );

        let user = authenticator.extract_user_from_token(&file_token).unwrap();
        assert_eq!(user, Some("user456".to_string()));

        let (auth, user) = authenticator
            .verify_file_token_with_user(&file_token, "hash123", 0)
            .unwrap();
        assert_eq!(auth, Authorization::ReadOnly);
        assert_eq!(user, Some("user456".to_string()));

        // Test token without user
        let no_user_token = authenticator.gen_doc_token(
            "doc789",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
        );

        let user = authenticator
            .extract_user_from_token(&no_user_token)
            .unwrap();
        assert_eq!(user, None);
    }

    #[test]
    fn test_user_identification_cwt_tokens() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Test doc token with user
        let doc_token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("user123"),
            None,
        );

        let user = authenticator.extract_user_from_token(&doc_token).unwrap();
        assert_eq!(user, Some("user123".to_string()));

        let (auth, user) = authenticator
            .verify_doc_token_with_user(&doc_token, "doc123", 0)
            .unwrap();
        assert_eq!(auth, Authorization::Full);
        assert_eq!(user, Some("user123".to_string()));

        // Test file token with user
        let file_token = authenticator.gen_file_token_cwt(
            "hash123",
            "doc456",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("application/json"),
            Some(1024),
            Some("user456"),
            None,
        );

        let user = authenticator.extract_user_from_token(&file_token).unwrap();
        assert_eq!(user, Some("user456".to_string()));

        let (auth, user) = authenticator
            .verify_file_token_with_user(&file_token, "hash123", 0)
            .unwrap();
        assert_eq!(auth, Authorization::ReadOnly);
        assert_eq!(user, Some("user456".to_string()));

        // Test token without user
        let no_user_token = authenticator.gen_doc_token_cwt(
            "doc789",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
            None,
        );

        let user = authenticator
            .extract_user_from_token(&no_user_token)
            .unwrap();
        assert_eq!(user, None);
    }

    #[test]
    fn test_backward_compatibility_old_tokens() {
        // This test simulates old tokens that were created before the user field was added
        let authenticator = Authenticator::gen_key().unwrap();

        // Create an old-style payload manually (without user field)
        let old_payload = LegacyPayload {
            payload: LegacyPermission::Doc(LegacyDocPermission {
                doc_id: "test_doc".to_string(),
                authorization: Authorization::Full,
            }),
            expiration_millis: None,
        };

        // Encode it the old way
        let mut hash_payload =
            bincode_encode(&old_payload).expect("Bincode serialization should not fail.");
        hash_payload.extend_from_slice(&authenticator.private_key);
        let token_hash = hash(&hash_payload);

        let old_auth_req = LegacyAuthenticatedRequest {
            payload: old_payload,
            token: token_hash,
        };

        let auth_enc =
            bincode_encode(&old_auth_req).expect("Bincode serialization should not fail.");
        let old_token = b64_encode(&auth_enc);

        // Verify that the old token can still be verified
        match authenticator.verify_doc_token(&old_token, "test_doc", 0) {
            Ok(auth) => assert_eq!(auth, Authorization::Full),
            Err(e) => panic!("Failed to verify old token: {:?}", e),
        }

        // Verify that decode_token works
        let decoded = authenticator.decode_token(&old_token).unwrap();
        match decoded.payload {
            Permission::Doc(doc_perm) => {
                assert_eq!(doc_perm.doc_id, "test_doc");
                assert_eq!(doc_perm.authorization, Authorization::Full);
                assert_eq!(doc_perm.user, None); // Should be None for old tokens
            }
            _ => panic!("Expected Doc permission"),
        }
    }

    #[test]
    fn test_cwt_channel_claims() {
        let authenticator = Authenticator::gen_key().unwrap();
        let doc_id = "test_doc_123";
        let channel = "team-updates";

        // Test document token with channel claim
        let token_with_channel = authenticator.gen_doc_token_cwt(
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("user123"),
            Some(channel.to_string()),
        );

        // Test document token without channel claim
        let token_without_channel = authenticator.gen_doc_token_cwt(
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("user123"),
            None,
        );

        // Verify token with channel returns the channel
        let (permission, extracted_channel) = authenticator
            .verify_token_with_channel(&token_with_channel, 0)
            .unwrap();

        match permission {
            Permission::Doc(doc_perm) => {
                assert_eq!(doc_perm.doc_id, doc_id);
                assert_eq!(doc_perm.authorization, Authorization::Full);
                assert_eq!(doc_perm.user, Some("user123".to_string()));
            }
            _ => panic!("Expected doc permission"),
        }
        assert_eq!(extracted_channel, Some(channel.to_string()));

        // Verify token without channel returns None for channel
        let (permission, extracted_channel) = authenticator
            .verify_token_with_channel(&token_without_channel, 0)
            .unwrap();

        match permission {
            Permission::Doc(doc_perm) => {
                assert_eq!(doc_perm.doc_id, doc_id);
                assert_eq!(doc_perm.authorization, Authorization::Full);
                assert_eq!(doc_perm.user, Some("user123".to_string()));
            }
            _ => panic!("Expected doc permission"),
        }
        assert_eq!(extracted_channel, None);

        // Test file token with channel claim
        let file_token_with_channel = authenticator.gen_file_token_cwt(
            "file_hash_123",
            doc_id,
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("application/json"),
            Some(1024),
            Some("user456"),
            Some(channel.to_string()),
        );

        let (permission, extracted_channel) = authenticator
            .verify_token_with_channel(&file_token_with_channel, 0)
            .unwrap();

        match permission {
            Permission::File(file_perm) => {
                assert_eq!(file_perm.doc_id, doc_id);
                assert_eq!(file_perm.authorization, Authorization::ReadOnly);
                assert_eq!(file_perm.user, Some("user456".to_string()));
            }
            _ => panic!("Expected file permission"),
        }
        assert_eq!(extracted_channel, Some(channel.to_string()));
    }

    #[test]
    fn test_user_identification_mixed_tokens() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Create custom and CWT tokens for the same resource but different users
        let custom_token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("custom_user"),
        );

        let cwt_token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("cwt_user"),
            None,
        );

        // Verify both can extract users correctly
        let custom_user = authenticator
            .extract_user_from_token(&custom_token)
            .unwrap();
        let cwt_user = authenticator.extract_user_from_token(&cwt_token).unwrap();

        assert_eq!(custom_user, Some("custom_user".to_string()));
        assert_eq!(cwt_user, Some("cwt_user".to_string()));

        // Verify authorization and user extraction work together
        let (auth1, user1) = authenticator
            .verify_doc_token_with_user(&custom_token, "doc123", 0)
            .unwrap();
        let (auth2, user2) = authenticator
            .verify_doc_token_with_user(&cwt_token, "doc123", 0)
            .unwrap();

        assert_eq!(auth1, Authorization::Full);
        assert_eq!(user1, Some("custom_user".to_string()));
        assert_eq!(auth2, Authorization::ReadOnly);
        assert_eq!(user2, Some("cwt_user".to_string()));
    }

    #[test]
    fn test_auth_system3_debug() {
        // Test the failing WebSocket token
        let token = "2D3RhEOhAQWgWH-lAWxyZWxheS1zZXJ2ZXICbzk5b3J2MmxnMHg5ZzV5ZAQaaLkaHAYaaLkTFAl4UGRvYzo4NWEwNjcxMi1hZjE0LTQ3YmMtYTg1OS1lODEwNmNjNzg2ZTgtOGFjNjg3M2EtZTBkMS00NGRhLWE3MWMtNGI0M2UwOGFmY2NlOnJ3WCDaunvV8xuQFkbaGA8KPxm8ma-XAvDkvU1NMFO71e_0yA";
        let key_base64 = "H2uV4LFfYYNMkkOeAmlgYbl0Axx94fzL9TdrWgbxsVM";
        let doc_id = "85a06712-af14-47bc-a859-e8106cc786e8-8ac6873a-e0d1-44da-a71c-4b43e08afcce";

        let detected_format = detect_token_format(token);
        assert_eq!(
            detected_format,
            TokenFormat::Cwt,
            "Token should be detected as CWT format"
        );

        // Create authenticator from the key
        let auth = Authenticator::new(key_base64).expect("Failed to create authenticator");

        // Test at a valid time (iat=1756959508, exp=1756961308)
        let test_time = 1756959508u64 * 1000 + 60000; // 1 minute after issuance, well before expiry

        // The verify_cwt_token method returns Permission
        // where Permission contains the doc_id and authorization
        match auth.verify_cwt_token(token, test_time) {
            Ok(permission) => {
                // Token verification succeeded

                // Check if the permission matches our expected doc_id
                match permission {
                    Permission::Doc(doc_perm) => {
                        if doc_perm.doc_id == doc_id {
                        } else {
                        }
                    }
                    _ => {}
                }
            }
            Err(_e) => {
                // Also try to decode it
                match auth.decode_token(token) {
                    Ok(_payload) => {}
                    Err(_decode_err) => {}
                }
            }
        }
    }

    #[test]
    fn test_prefix_token_generation_and_verification() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Test custom format prefix tokens
        let custom_token = authenticator.gen_prefix_token(
            "org123-",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("admin@org123.com"),
        );

        // Test CWT format prefix tokens
        let cwt_token = authenticator.gen_prefix_token_cwt(
            "user456-",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("user456"),
        );

        // Verify that prefix tokens work with matching document IDs
        let (auth1, user1) = authenticator
            .verify_doc_token_with_prefix(&custom_token, "org123-project-alpha", 0)
            .unwrap();
        assert_eq!(auth1, Authorization::Full);
        assert_eq!(user1, Some("admin@org123.com".to_string()));

        let (auth2, user2) = authenticator
            .verify_doc_token_with_prefix(&cwt_token, "user456-personal-doc", 0)
            .unwrap();
        assert_eq!(auth2, Authorization::ReadOnly);
        assert_eq!(user2, Some("user456".to_string()));
    }

    #[test]
    fn test_prefix_token_matching_logic() {
        let authenticator = Authenticator::gen_key().unwrap();

        let prefix_token = authenticator.gen_prefix_token(
            "org123-",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
        );

        // Should match documents with the prefix
        assert!(authenticator
            .verify_doc_token_with_prefix(&prefix_token, "org123-project-alpha", 0)
            .is_ok());
        assert!(authenticator
            .verify_doc_token_with_prefix(&prefix_token, "org123-", 0)
            .is_ok());
        assert!(authenticator
            .verify_doc_token_with_prefix(&prefix_token, "org123-project-beta-doc456", 0)
            .is_ok());

        // Should not match documents without the prefix
        assert!(authenticator
            .verify_doc_token_with_prefix(&prefix_token, "org124-project", 0)
            .is_err());
        assert!(authenticator
            .verify_doc_token_with_prefix(&prefix_token, "different-org123-project", 0)
            .is_err());
        assert!(authenticator
            .verify_doc_token_with_prefix(&prefix_token, "org12-project", 0)
            .is_err());
    }

    #[test]
    fn test_empty_prefix_token() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Empty prefix should match any document (server-like behavior but with user tracking)
        let empty_prefix_token = authenticator.gen_prefix_token_cwt(
            "",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("superuser"),
        );

        let (auth, user) = authenticator
            .verify_doc_token_with_prefix(&empty_prefix_token, "any-doc-id", 0)
            .unwrap();
        assert_eq!(auth, Authorization::Full);
        assert_eq!(user, Some("superuser".to_string()));

        let (auth2, user2) = authenticator
            .verify_doc_token_with_prefix(&empty_prefix_token, "", 0)
            .unwrap();
        assert_eq!(auth2, Authorization::Full);
        assert_eq!(user2, Some("superuser".to_string()));
    }

    #[test]
    fn test_prefix_token_user_extraction() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Test custom format prefix token user extraction
        let custom_token = authenticator.gen_prefix_token(
            "test-",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("test_user"),
        );

        let user = authenticator
            .extract_user_from_token(&custom_token)
            .unwrap();
        assert_eq!(user, Some("test_user".to_string()));

        // Test CWT format prefix token user extraction
        let cwt_token = authenticator.gen_prefix_token_cwt(
            "cwt-",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("cwt_user"),
        );

        let cwt_user = authenticator.extract_user_from_token(&cwt_token).unwrap();
        assert_eq!(cwt_user, Some("cwt_user".to_string()));

        // Test token without user
        let no_user_token = authenticator.gen_prefix_token(
            "public-",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(u64::MAX),
            None,
        );

        let no_user = authenticator
            .extract_user_from_token(&no_user_token)
            .unwrap();
        assert_eq!(no_user, None);
    }

    #[test]
    fn test_prefix_token_with_direct_doc_token_fallback() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Create a direct document token
        let doc_token = authenticator.gen_doc_token(
            "org123-project-alpha",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("doc_user"),
        );

        // verify_doc_token_with_prefix should work with direct tokens too
        let (auth, user) = authenticator
            .verify_doc_token_with_prefix(&doc_token, "org123-project-alpha", 0)
            .unwrap();
        assert_eq!(auth, Authorization::Full);
        assert_eq!(user, Some("doc_user".to_string()));

        // Should fail for different document ID
        assert!(authenticator
            .verify_doc_token_with_prefix(&doc_token, "different-doc", 0)
            .is_err());
    }

    #[test]
    fn test_prefix_token_file_operations() {
        let authenticator = Authenticator::gen_key().unwrap();

        let prefix_token = authenticator.gen_prefix_token_cwt(
            "project-",
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX),
            Some("project_admin"),
        );

        // Prefix tokens should work for file operations within their prefix
        let auth = authenticator
            .verify_file_token_for_doc(&prefix_token, "project-alpha-doc123", 0)
            .unwrap();
        assert_eq!(auth, Authorization::Full);

        // Should fail for documents outside the prefix
        assert!(authenticator
            .verify_file_token_for_doc(&prefix_token, "other-project-doc", 0)
            .is_err());
    }

    #[test]
    fn test_prefix_token_expiration() {
        let authenticator = Authenticator::gen_key().unwrap();

        // Create an expired prefix token
        let expired_token = authenticator.gen_prefix_token(
            "temp-",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(1000), // Very old timestamp
            Some("temp_user"),
        );

        // Should fail due to expiration
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert!(matches!(
            authenticator.verify_doc_token_with_prefix(&expired_token, "temp-doc", current_time),
            Err(AuthError::Expired)
        ));
    }
}
