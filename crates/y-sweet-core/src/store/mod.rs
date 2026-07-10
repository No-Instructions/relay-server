#[cfg(not(target_arch = "wasm32"))]
pub mod memory;
pub mod s3;

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Store bucket does not exist. {0}")]
    BucketDoesNotExist(String),
    #[error("Object does not exist. {0}")]
    DoesNotExist(String),
    #[error("Not authorized to access store. {0}")]
    NotAuthorized(String),
    #[error("Error connecting to store. {0}")]
    ConnectionError(String),
    #[error("Unsupported operation. {0}")]
    UnsupportedOperation(String),
    #[error("Write lease conflict. {0}")]
    LeaseConflict(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteLease {
    Missing,
    Digest { len: u64, sha256: [u8; 32] },
    Opaque { backend: String, token: String },
}

impl WriteLease {
    pub fn for_value(value: Option<&[u8]>) -> Self {
        match value {
            Some(bytes) => {
                let digest = Sha256::digest(bytes);
                let mut sha256 = [0u8; 32];
                sha256.copy_from_slice(&digest);
                Self::Digest {
                    len: bytes.len() as u64,
                    sha256,
                }
            }
            None => Self::Missing,
        }
    }

    pub fn matches(&self, current: &LeasedValue) -> bool {
        self == &current.lease || self.matches_value(current.value.as_deref())
    }

    fn matches_value(&self, value: Option<&[u8]>) -> bool {
        match (self, value) {
            (Self::Missing, None) => true,
            (Self::Digest { len, sha256 }, Some(bytes)) => {
                *len == bytes.len() as u64 && *sha256 == Self::digest_bytes(bytes)
            }
            _ => false,
        }
    }

    fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);
        sha256
    }
}

#[derive(Debug, Clone)]
pub struct LeasedValue {
    pub value: Option<Vec<u8>>,
    pub lease: WriteLease,
}

impl LeasedValue {
    pub fn from_value(value: Option<Vec<u8>>) -> Self {
        let lease = WriteLease::for_value(value.as_deref());
        Self { value, lease }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub key: String,
    pub size: u64,
    pub last_modified: u64, // timestamp in milliseconds
}

#[derive(Debug, Clone, Serialize)]
pub struct FileListPage {
    pub files: Vec<FileInfo>,
    pub common_prefixes: Vec<String>,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub version_id: String,
    pub last_modified: u64,
    pub is_latest: bool,
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Store: 'static {
    async fn init(&self) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;
    async fn get_with_lease(&self, key: &str) -> Result<LeasedValue> {
        self.get(key).await.map(LeasedValue::from_value)
    }
    async fn set_if_unchanged(
        &self,
        key: &str,
        value: Vec<u8>,
        lease: &WriteLease,
    ) -> Result<WriteLease> {
        let current = self.get_with_lease(key).await?;
        if !lease.matches(&current) {
            return Err(StoreError::LeaseConflict(format!(
                "{} changed since it was read",
                key
            )));
        }

        self.set(key, value.clone()).await?;
        Ok(WriteLease::for_value(Some(&value)))
    }
    async fn remove(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;

    // Generate presigned URL for uploading file to storage
    async fn generate_upload_url(
        &self,
        _key: &str,
        _content_type: Option<&str>,
        _content_length: Option<u64>,
    ) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // Generate presigned URL for downloading file from storage
    async fn generate_download_url(&self, _key: &str) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // List files with a common prefix and return their file info (key, size, last_modified)
    async fn list(&self, _prefix: &str) -> Result<Vec<FileInfo>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support listing files".to_string(),
        ))
    }

    async fn list_page(
        &self,
        prefix: &str,
        continuation_token: Option<&str>,
    ) -> Result<FileListPage> {
        if continuation_token.is_some() {
            return Ok(FileListPage {
                files: Vec::new(),
                common_prefixes: Vec::new(),
                next_continuation_token: None,
            });
        }

        Ok(FileListPage {
            files: self.list(prefix).await?,
            common_prefixes: Vec::new(),
            next_continuation_token: None,
        })
    }

    async fn list_directory_page(
        &self,
        prefix: &str,
        continuation_token: Option<&str>,
    ) -> Result<FileListPage> {
        self.list_page(prefix, continuation_token).await
    }

    async fn list_versions(&self, _key: &str) -> Result<Vec<VersionInfo>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support listing versions".to_string(),
        ))
    }

    /// Fetch the bytes of a specific past version of `key`, identified by
    /// the storage backend's version id (S3 `VersionId`). Returns `None` if
    /// the (key, version) pair does not exist.
    async fn get_version(&self, _key: &str, _version_id: &str) -> Result<Option<Vec<u8>>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support fetching specific versions".to_string(),
        ))
    }

    // Whether this store supports direct uploads through the server
    // (as opposed to presigned URLs that bypass the server)
    fn supports_direct_uploads(&self) -> bool {
        false
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Store: Send + Sync {
    async fn init(&self) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;
    async fn get_with_lease(&self, key: &str) -> Result<LeasedValue> {
        self.get(key).await.map(LeasedValue::from_value)
    }
    async fn set_if_unchanged(
        &self,
        key: &str,
        value: Vec<u8>,
        lease: &WriteLease,
    ) -> Result<WriteLease> {
        let current = self.get_with_lease(key).await?;
        if !lease.matches(&current) {
            return Err(StoreError::LeaseConflict(format!(
                "{} changed since it was read",
                key
            )));
        }

        self.set(key, value.clone()).await?;
        Ok(WriteLease::for_value(Some(&value)))
    }
    async fn remove(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;

    // Generate presigned URL for uploading file to storage
    async fn generate_upload_url(
        &self,
        _key: &str,
        _content_type: Option<&str>,
        _content_length: Option<u64>,
    ) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // Generate presigned URL for downloading file from storage
    async fn generate_download_url(&self, _key: &str) -> Result<Option<String>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support generating presigned URLs".to_string(),
        ))
    }

    // List files with a common prefix and return their file info (key, size, last_modified)
    async fn list(&self, _prefix: &str) -> Result<Vec<FileInfo>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support listing files".to_string(),
        ))
    }

    async fn list_page(
        &self,
        prefix: &str,
        continuation_token: Option<&str>,
    ) -> Result<FileListPage> {
        if continuation_token.is_some() {
            return Ok(FileListPage {
                files: Vec::new(),
                common_prefixes: Vec::new(),
                next_continuation_token: None,
            });
        }

        Ok(FileListPage {
            files: self.list(prefix).await?,
            common_prefixes: Vec::new(),
            next_continuation_token: None,
        })
    }

    async fn list_directory_page(
        &self,
        prefix: &str,
        continuation_token: Option<&str>,
    ) -> Result<FileListPage> {
        self.list_page(prefix, continuation_token).await
    }

    async fn list_versions(&self, _key: &str) -> Result<Vec<VersionInfo>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support listing versions".to_string(),
        ))
    }

    /// Fetch the bytes of a specific past version of `key`, identified by
    /// the storage backend's version id (S3 `VersionId`). Returns `None` if
    /// the (key, version) pair does not exist.
    async fn get_version(&self, _key: &str, _version_id: &str) -> Result<Option<Vec<u8>>> {
        Err(StoreError::UnsupportedOperation(
            "This store does not support fetching specific versions".to_string(),
        ))
    }

    // Whether this store supports direct uploads through the server
    // (as opposed to presigned URLs that bypass the server)
    fn supports_direct_uploads(&self) -> bool {
        false
    }
}
