use serde::{Deserialize, Serialize};

/// Custom nanoid alphabet without underscore and hyphen (only alphanumeric characters)
pub const NANOID_ALPHABET: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
];

#[derive(Serialize)]
pub struct NewDocResponse {
    #[serde(rename = "docId")]
    pub doc_id: String,
}

#[derive(Serialize)]
pub struct FileUploadUrlResponse {
    /// The presigned URL for uploading a file
    #[serde(rename = "uploadUrl")]
    pub upload_url: String,
}

#[derive(Serialize)]
pub struct FileDownloadUrlResponse {
    /// The presigned URL for downloading a file
    #[serde(rename = "downloadUrl")]
    pub download_url: String,
}

#[derive(Serialize)]
pub struct FileHistoryEntry {
    /// The file hash identifier
    pub hash: String,
    /// File size in bytes
    pub size: u64,
    /// Last modified timestamp in milliseconds since epoch
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct FileHistoryResponse {
    /// List of files found for the document
    pub files: Vec<FileHistoryEntry>,
}

#[derive(Serialize)]
pub struct DocumentVersionEntry {
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(rename = "isLatest")]
    pub is_latest: bool,
}

#[derive(Serialize)]
pub struct DocumentVersionResponse {
    pub versions: Vec<DocumentVersionEntry>,
}

/// Validate that the file hash is a valid SHA256 hash (64 hex characters)
pub fn validate_file_hash(hash: &str) -> bool {
    // SHA256 hash is 64 characters long hex string
    if hash.len() != 64 {
        return false;
    }

    // Check if all characters are valid hex digits
    hash.chars().all(|c| c.is_ascii_hexdigit())
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Authorization {
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "full")]
    Full,
}

impl Authorization {
    fn full() -> Self {
        Self::Full
    }
}

#[derive(Deserialize)]
pub struct AuthDocRequest {
    #[serde(default = "Authorization::full")]
    pub authorization: Authorization,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "validForSeconds")]
    pub valid_for_seconds: Option<u64>,
}

impl Default for AuthDocRequest {
    fn default() -> Self {
        Self {
            authorization: Authorization::Full,
            user_id: None,
            valid_for_seconds: None,
        }
    }
}

#[derive(Serialize)]
pub struct ClientToken {
    /// The URL compatible with the y-websocket provider. The provider will append
    /// a document ID to this string and establish a WebSocket connection.
    pub url: String,

    /// The base URL for document-level endpoints.
    #[serde(rename = "baseUrl")]
    pub base_url: Option<String>,

    /// The document ID.
    #[serde(rename = "docId")]
    pub doc_id: String,

    /// An optional token that can be used to authenticate the client to the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// The authorization level of the client.
    #[serde(rename = "authorization")]
    pub authorization: Authorization,
}

#[derive(Deserialize, Debug)]
pub struct DocCreationRequest {
    /// The ID of the document to create. If not provided, a random ID will be generated.
    #[serde(skip_serializing_if = "Option::is_none", rename = "docId")]
    pub doc_id: Option<String>,
}

/// Validate that the document name contains only alphanumeric characters, dashes, and underscores.
/// This is the same alphabet used by nanoid when we generate a document name.
pub fn validate_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return false;
        }
    }
    true
}

/// Alias for backward compatibility
pub fn validate_doc_name(doc_name: &str) -> bool {
    validate_key(doc_name)
}
