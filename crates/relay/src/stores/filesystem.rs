use async_trait::async_trait;
use std::{
    fs::{create_dir_all, read_dir, remove_file},
    path::PathBuf,
    time::SystemTime,
};
use y_sweet_core::store::{FileInfo, Result, Store, StoreError};

pub struct FileSystemStore {
    base_path: PathBuf,
}

impl FileSystemStore {
    pub fn new(base_path: PathBuf) -> std::result::Result<Self, std::io::Error> {
        create_dir_all(base_path.clone())?;
        Ok(Self { base_path })
    }
}

#[async_trait]
impl Store for FileSystemStore {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.base_path.join(key);
        let contents = std::fs::read(path);
        match contents {
            Ok(contents) => Ok(Some(contents)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::ConnectionError(e.to_string())),
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let path = self.base_path.join(key);
        create_dir_all(path.parent().expect("Bad parent"))
            .map_err(|_| StoreError::NotAuthorized("Error creating directories".to_string()))?;
        std::fs::write(path, value)
            .map_err(|_| StoreError::NotAuthorized("Error writing file.".to_string()))?;
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<()> {
        let path = self.base_path.join(key);
        remove_file(path)
            .map_err(|_| StoreError::NotAuthorized("Error removing file.".to_string()))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let path = self.base_path.join(key);
        Ok(path.exists())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<FileInfo>> {
        let dir_path = self.base_path.join(prefix);

        if !dir_path.exists() || !dir_path.is_dir() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();

        let dir_entries = match read_dir(&dir_path) {
            Ok(entries) => entries,
            Err(e) => {
                return Err(StoreError::ConnectionError(format!(
                    "Failed to read directory: {}",
                    e
                )))
            }
        };

        for entry in dir_entries {
            if let Ok(entry) = entry {
                let path = entry.path();

                if path.is_file() {
                    let metadata = match path.metadata() {
                        Ok(meta) => meta,
                        Err(_) => continue, // Skip files we can't read metadata for
                    };

                    let file_name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.to_string());

                    if let Some(key) = file_name {
                        let size = metadata.len();

                        // Get last modified time as milliseconds since epoch
                        let last_modified = metadata
                            .modified()
                            .ok()
                            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                            .map(|duration| duration.as_millis() as u64)
                            .unwrap_or(0);

                        files.push(FileInfo {
                            key,
                            size,
                            last_modified,
                        });
                    }
                }
            }
        }

        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_list_files() {
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create a store with the temp directory
        let store = FileSystemStore::new(base_path.clone()).unwrap();

        // Create a test directory structure with files
        let doc_id = "test-doc";
        let file_path = base_path.join("files").join(doc_id);
        std::fs::create_dir_all(&file_path).unwrap();

        // Create some test files with different content
        let test_files = vec![
            ("abcdef123456", "test content 1"),
            ("ghijkl789012", "test content 2 with more data"),
            ("mnopqr345678", "small"),
        ];

        for (hash, content) in &test_files {
            let file_path = file_path.join(hash);
            let mut file = File::create(file_path).unwrap();
            file.write_all(content.as_bytes()).unwrap();
        }

        // Test listing files
        let prefix = format!("files/{}", doc_id);
        let files = store.list(&prefix).await.unwrap();

        // Verify that we got the correct number of files
        assert_eq!(files.len(), test_files.len());

        // Verify that all expected files are in the result
        for (hash, content) in &test_files {
            let found = files.iter().any(|file| {
                file.key == *hash
                    && file.size == content.as_bytes().len() as u64
                    && file.last_modified > 0
            });
            assert!(found, "File with hash {} not found in results", hash);
        }

        // Test listing with a non-existent prefix
        let files = store.list("files/nonexistent").await.unwrap();
        assert_eq!(files.len(), 0);
    }

    #[tokio::test]
    async fn test_list_empty_directory() {
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create a store with the temp directory
        let store = FileSystemStore::new(base_path.clone()).unwrap();

        // Create an empty directory
        let doc_id = "empty-doc";
        let file_path = base_path.join("files").join(doc_id);
        std::fs::create_dir_all(&file_path).unwrap();

        // Test listing files in empty directory
        let prefix = format!("files/{}", doc_id);
        let files = store.list(&prefix).await.unwrap();

        // Verify that we got an empty list
        assert_eq!(files.len(), 0);
    }
}
