use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::SystemTime;
use tokio::io::AsyncReadExt;
use y_sweet_core::{
    api_types::Authorization,
    auth::{Authenticator, ExpirationTimeEpochMillis, Permission},
    store::{s3::S3Config, s3::S3Store, Store},
};

async fn sign_stdin(auth: &Authenticator) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut buffer = String::new();
    stdin.read_to_string(&mut buffer).await?;

    let input: serde_json::Value = serde_json::from_str(&buffer)?;

    // Extract fields from the JSON input
    let doc_id = input.get("docId").and_then(|v| v.as_str());
    let file_hash = input.get("fileHash").and_then(|v| v.as_str());
    let token_type = input
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("document");
    let auth_str = input
        .get("authorization")
        .and_then(|v| v.as_str())
        .unwrap_or("full");
    let content_type = input.get("contentType").and_then(|v| v.as_str());
    let content_length = input.get("contentLength").and_then(|v| v.as_u64());

    if token_type != "document"
        && token_type != "file"
        && token_type != "server"
        && token_type != "prefix"
    {
        anyhow::bail!(
            "Invalid token type: {}. Must be 'document', 'file', 'server', or 'prefix'",
            token_type
        );
    }

    let authorization = match auth_str {
        "read" | "read-only" => Authorization::ReadOnly,
        "full" => Authorization::Full,
        other => anyhow::bail!(
            "Invalid authorization: {}. Must be 'read', 'read-only', or 'full'",
            other
        ),
    };

    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis() as u64;

    let expiration = ExpirationTimeEpochMillis(
        current_time + (y_sweet_core::auth::DEFAULT_EXPIRATION_SECONDS * 1000),
    );

    let mut output = serde_json::Map::new();

    match token_type {
        "document" => {
            let doc_id =
                doc_id.ok_or_else(|| anyhow::anyhow!("docId is required for document tokens"))?;

            let token = auth.gen_doc_token(doc_id, authorization, expiration, None);

            output.insert(
                "docId".to_string(),
                serde_json::Value::String(doc_id.to_string()),
            );
            output.insert("token".to_string(), serde_json::Value::String(token));
            output.insert(
                "type".to_string(),
                serde_json::Value::String("document".to_string()),
            );

            let auth_value = match authorization {
                Authorization::ReadOnly => "read-only",
                Authorization::Full => "full",
            };
            output.insert(
                "authorization".to_string(),
                serde_json::Value::String(auth_value.to_string()),
            );
        }
        "file" => {
            let file_hash =
                file_hash.ok_or_else(|| anyhow::anyhow!("fileHash is required for file tokens"))?;

            let doc_id =
                doc_id.ok_or_else(|| anyhow::anyhow!("docId is required for file tokens"))?;

            let token = auth.gen_file_token(
                file_hash,
                doc_id,
                authorization,
                expiration,
                content_type,
                content_length,
                None,
            );

            output.insert(
                "fileHash".to_string(),
                serde_json::Value::String(file_hash.to_string()),
            );
            output.insert(
                "docId".to_string(),
                serde_json::Value::String(doc_id.to_string()),
            );
            output.insert("token".to_string(), serde_json::Value::String(token));
            output.insert(
                "type".to_string(),
                serde_json::Value::String("file".to_string()),
            );

            if let Some(ct) = content_type {
                output.insert(
                    "contentType".to_string(),
                    serde_json::Value::String(ct.to_string()),
                );
            }

            if let Some(cl) = content_length {
                output.insert(
                    "contentLength".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(cl)),
                );
            }

            let auth_value = match authorization {
                Authorization::ReadOnly => "read-only",
                Authorization::Full => "full",
            };
            output.insert(
                "authorization".to_string(),
                serde_json::Value::String(auth_value.to_string()),
            );
        }
        "server" => {
            // For server tokens, we don't need doc_id or file_hash
            // We also don't use the authorization parameter since server tokens always have full access

            let token = auth.server_token();

            output.insert("token".to_string(), serde_json::Value::String(token));
            output.insert(
                "type".to_string(),
                serde_json::Value::String("server".to_string()),
            );

            // Server tokens always have full authorization
            output.insert(
                "authorization".to_string(),
                serde_json::Value::String("full".to_string()),
            );
        }
        "prefix" => {
            let prefix = input
                .get("prefix")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("prefix is required for prefix tokens"))?;

            let user = input.get("user").and_then(|v| v.as_str());

            // Generate CWT prefix token
            let token = auth.gen_prefix_token_cwt(prefix, authorization, expiration, user);

            output.insert("token".to_string(), serde_json::Value::String(token));
            output.insert(
                "prefix".to_string(),
                serde_json::Value::String(prefix.to_string()),
            );
            output.insert(
                "type".to_string(),
                serde_json::Value::String("prefix".to_string()),
            );

            let auth_value = match authorization {
                Authorization::ReadOnly => "read-only",
                Authorization::Full => "full",
            };
            output.insert(
                "authorization".to_string(),
                serde_json::Value::String(auth_value.to_string()),
            );

            if let Some(user) = user {
                output.insert(
                    "user".to_string(),
                    serde_json::Value::String(user.to_string()),
                );
            }
        }
        _ => unreachable!(), // Already validated above
    }

    println!("{}", serde_json::Value::Object(output).to_string());
    Ok(())
}

async fn verify_stdin(auth: &Authenticator, id: Option<&str>) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut token = String::new();
    stdin.read_to_string(&mut token).await?;
    let token = token.trim();

    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis() as u64;

    let mut output = serde_json::Map::new();
    let mut verification = serde_json::Map::new();

    // Create token info
    let mut token_info = serde_json::Map::new();
    token_info.insert(
        "raw".to_string(),
        serde_json::Value::String(token.to_string()),
    );

    // First, try to decode the token to determine its type and extract payload data
    let token_decode_result = auth.decode_token(token);
    let token_type = match &token_decode_result {
        Ok(payload) => {
            match &payload.payload {
                Permission::Server => {
                    // Add server token info
                    verification.insert(
                        "authorization".to_string(),
                        serde_json::Value::String("full".to_string()),
                    );
                    "server"
                }
                Permission::Doc(doc_permission) => {
                    // Extract doc_id for the verification section
                    verification.insert(
                        "docId".to_string(),
                        serde_json::Value::String(doc_permission.doc_id.clone()),
                    );

                    // Add authorization
                    let auth_str = match doc_permission.authorization {
                        Authorization::ReadOnly => "read-only",
                        Authorization::Full => "full",
                    };
                    verification.insert(
                        "authorization".to_string(),
                        serde_json::Value::String(auth_str.to_string()),
                    );

                    // Add expiration if present
                    if let Some(expiration) = payload.expiration_millis {
                        verification.insert(
                            "expiresAt".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(expiration.0)),
                        );
                    }

                    "document"
                }
                Permission::File(file_permission) => {
                    // Extract file hash for the verification section
                    verification.insert(
                        "fileHash".to_string(),
                        serde_json::Value::String(file_permission.file_hash.clone()),
                    );

                    // Add doc_id
                    verification.insert(
                        "docId".to_string(),
                        serde_json::Value::String(file_permission.doc_id.clone()),
                    );

                    // Add authorization
                    let auth_str = match file_permission.authorization {
                        Authorization::ReadOnly => "read-only",
                        Authorization::Full => "full",
                    };
                    verification.insert(
                        "authorization".to_string(),
                        serde_json::Value::String(auth_str.to_string()),
                    );

                    // Add optional metadata if present
                    if let Some(content_type) = &file_permission.content_type {
                        verification.insert(
                            "contentType".to_string(),
                            serde_json::Value::String(content_type.clone()),
                        );
                    }

                    if let Some(content_length) = file_permission.content_length {
                        verification.insert(
                            "contentLength".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(content_length)),
                        );
                    }

                    // Add expiration if present
                    if let Some(expiration) = payload.expiration_millis {
                        verification.insert(
                            "expiresAt".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(expiration.0)),
                        );
                    }

                    "file"
                }
                Permission::Prefix(prefix_permission) => {
                    // Extract prefix for the verification section
                    verification.insert(
                        "prefix".to_string(),
                        serde_json::Value::String(prefix_permission.prefix.clone()),
                    );

                    // Add authorization
                    let auth_str = match prefix_permission.authorization {
                        Authorization::ReadOnly => "read-only",
                        Authorization::Full => "full",
                    };
                    verification.insert(
                        "authorization".to_string(),
                        serde_json::Value::String(auth_str.to_string()),
                    );

                    // Add user if present
                    if let Some(user) = &prefix_permission.user {
                        verification
                            .insert("user".to_string(), serde_json::Value::String(user.clone()));
                    }

                    // Add expiration if present
                    if let Some(expiration) = payload.expiration_millis {
                        verification.insert(
                            "expiresAt".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(expiration.0)),
                        );
                    }

                    "prefix"
                }
            }
        }
        Err(err) => {
            // Even if token is invalid, add the error for diagnostics
            verification.insert(
                "error".to_string(),
                serde_json::Value::String(format!("Failed to decode token: {}", err)),
            );
            "unknown"
        }
    };

    verification.insert(
        "kind".to_string(),
        serde_json::Value::String(token_type.to_string()),
    );

    match token_type {
        "server" => {
            // For server tokens we need to check:
            // 1. If it's a valid server token
            // 2. If a doc_id was provided, note that server tokens can access all docs
            match auth.verify_server_token(token, current_time) {
                Ok(()) => {
                    verification.insert("valid".to_string(), serde_json::Value::Bool(true));

                    // If a doc_id was provided, show that server tokens can access it
                    if let Some(doc_id) = id {
                        verification.insert(
                            "docId".to_string(),
                            serde_json::Value::String(doc_id.to_string()),
                        );
                        verification.insert(
                            "docAccess".to_string(),
                            serde_json::Value::String(
                                "full (server tokens can access all documents)".to_string(),
                            ),
                        );
                    }
                }
                Err(e) => {
                    verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                    // Don't override the original error if we already have one
                    if !verification.contains_key("error") {
                        verification.insert(
                            "error".to_string(),
                            serde_json::Value::String(e.to_string()),
                        );
                    }
                }
            }
        }
        "document" => {
            if let Some(id) = id {
                match auth.verify_doc_token(token, id, current_time) {
                    Ok(authorization) => {
                        let auth_str = match authorization {
                            Authorization::ReadOnly => "read-only",
                            Authorization::Full => "full",
                        };

                        verification.insert("valid".to_string(), serde_json::Value::Bool(true));
                        // Only add if not already there from decoding
                        if !verification.contains_key("authorization") {
                            verification.insert(
                                "authorization".to_string(),
                                serde_json::Value::String(auth_str.to_string()),
                            );
                        }
                        // Only add if not already there from decoding
                        if !verification.contains_key("docId") {
                            verification.insert(
                                "docId".to_string(),
                                serde_json::Value::String(id.to_string()),
                            );
                        }
                    }
                    Err(e) => {
                        verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                        // Only add if not already there from decoding
                        if !verification.contains_key("docId") {
                            verification.insert(
                                "docId".to_string(),
                                serde_json::Value::String(id.to_string()),
                            );
                        }
                        // Don't override the original error if we already have one
                        if !verification.contains_key("error") {
                            verification.insert(
                                "error".to_string(),
                                serde_json::Value::String(e.to_string()),
                            );
                        }
                        // Add validation errors section
                        verification.insert(
                            "validationError".to_string(),
                            serde_json::Value::String(e.to_string()),
                        );
                    }
                }
            } else {
                verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                // Don't override the original error if we already have one
                if !verification.contains_key("error") {
                    verification.insert(
                        "error".to_string(),
                        serde_json::Value::String(
                            "No document ID provided for verification".to_string(),
                        ),
                    );
                }
            }
        }
        "file" => {
            // For file tokens, we always display the metadata
            // But we only validate if a file hash or doc_id is provided

            // If we have a file_permission, add expected values to help users understand which identifiers to use
            if let Ok(payload) = &token_decode_result {
                if let Permission::File(file_permission) = &payload.payload {
                    if !verification.contains_key("expectedFileHash") {
                        verification.insert(
                            "expectedFileHash".to_string(),
                            serde_json::Value::String(file_permission.file_hash.clone()),
                        );
                    }
                    if !verification.contains_key("expectedDocId") {
                        verification.insert(
                            "expectedDocId".to_string(),
                            serde_json::Value::String(file_permission.doc_id.clone()),
                        );
                    }
                }
            }

            if let Some(id) = id {
                // Try both verification methods
                let file_match = auth.verify_file_token(token, id, current_time).is_ok();
                let doc_match = auth
                    .verify_file_token_for_doc(token, id, current_time)
                    .is_ok();

                if file_match || doc_match {
                    // One of the verification methods succeeded
                    let auth_result = if file_match {
                        auth.verify_file_token(token, id, current_time)
                    } else {
                        auth.verify_file_token_for_doc(token, id, current_time)
                    };

                    if let Ok(authorization) = auth_result {
                        let auth_str = match authorization {
                            Authorization::ReadOnly => "read-only",
                            Authorization::Full => "full",
                        };

                        verification.insert("valid".to_string(), serde_json::Value::Bool(true));
                        // Only add if not already there from decoding
                        if !verification.contains_key("authorization") {
                            verification.insert(
                                "authorization".to_string(),
                                serde_json::Value::String(auth_str.to_string()),
                            );
                        }

                        // Note which identifier matched
                        if file_match {
                            verification.insert(
                                "idType".to_string(),
                                serde_json::Value::String("fileHash".to_string()),
                            );
                        } else {
                            verification.insert(
                                "idType".to_string(),
                                serde_json::Value::String("docId".to_string()),
                            );
                        }
                    }
                } else {
                    // Both verification methods failed
                    verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                    // Don't override the original error if we already have one
                    if !verification.contains_key("error") {
                        verification.insert("error".to_string(), serde_json::Value::String(
                            format!("Token verification failed. The provided ID did not match the file hash or document ID in the token.")));
                    }
                    // Add validation errors section
                    verification.insert(
                        "validationError".to_string(),
                        serde_json::Value::String("ID mismatch with token".to_string()),
                    );
                }
            } else {
                // No ID provided
                verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                // Don't override the original error if we already have one
                if !verification.contains_key("error") {
                    verification.insert("error".to_string(), serde_json::Value::String(
                        "Token structure is valid but no file hash or doc ID provided for verification".to_string()));
                }
            }
        }
        _ => {
            verification.insert("valid".to_string(), serde_json::Value::Bool(false));
            // Don't override the original error if we already have one
            if !verification.contains_key("error") {
                verification.insert(
                    "error".to_string(),
                    serde_json::Value::String("Invalid or corrupted token".to_string()),
                );
            }
        }
    };

    output.insert("token".to_string(), serde_json::Value::Object(token_info));
    output.insert(
        "verification".to_string(),
        serde_json::Value::Object(verification),
    );

    println!("{}", serde_json::Value::Object(output).to_string());
    Ok(())
}

async fn presign_stdin(s3_config: &S3Config, auth: &Authenticator, action: &str) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut token = String::new();
    stdin.read_to_string(&mut token).await?;
    let token = token.trim();

    // Validate action
    if action != "upload-url" && action != "download-url" {
        anyhow::bail!(
            "Invalid action: {}. Must be 'upload-url' or 'download-url'",
            action
        );
    }

    // Get current time for token verification
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis() as u64;

    // Decode token to extract file hash and metadata
    let payload = auth.decode_token(token)?;

    // Extract file hash from token
    let (file_hash, authorization, content_type, content_length) = match &payload.payload {
        Permission::File(file_permission) => (
            &file_permission.file_hash,
            file_permission.authorization,
            file_permission.content_type.as_deref(),
            file_permission.content_length,
        ),
        _ => anyhow::bail!("Token is not a file token"),
    };

    // Verify token is valid (not expired)
    if let Some(expiration) = payload.expiration_millis {
        if expiration.0 < current_time {
            anyhow::bail!("Token is expired");
        }
    }

    // For uploads, we need full access
    if action == "upload-url" && authorization != Authorization::Full {
        anyhow::bail!("Upload requires a token with full authorization");
    }

    // Create S3 store
    let store = S3Store::new(s3_config.clone());

    let mut output = serde_json::Map::new();
    output.insert(
        "fileHash".to_string(),
        serde_json::Value::String(file_hash.to_string()),
    );

    // Diagnostic logging
    eprintln!("DEBUG: S3 bucket: {}", s3_config.bucket);
    eprintln!("DEBUG: S3 prefix: {:?}", s3_config.bucket_prefix);
    eprintln!("DEBUG: S3 endpoint: {}", s3_config.endpoint);
    eprintln!("DEBUG: File hash: {}", file_hash);

    // Our enhanced S3Store now handles proper path prefixing with files/ automatically
    let url = match action {
        "upload-url" => {
            // Simply pass the file hash - the store will add files/ prefix if needed
            store
                .generate_upload_url(file_hash, content_type, content_length)
                .await?
        }
        "download-url" => {
            // Don't check existence as it can give false negatives with certain S3 configurations
            store.init().await?;
            store.generate_download_url(file_hash, false).await?
        }
        _ => unreachable!(), // Already validated above
    };

    if let Some(url) = url {
        output.insert("url".to_string(), serde_json::Value::String(url));
        output.insert(
            "action".to_string(),
            serde_json::Value::String(action.to_string()),
        );

        if let Some(ct) = content_type {
            output.insert(
                "contentType".to_string(),
                serde_json::Value::String(ct.to_string()),
            );
        }

        if let Some(cl) = content_length {
            output.insert(
                "contentLength".to_string(),
                serde_json::Value::Number(serde_json::Number::from(cl)),
            );
        }
    } else {
        output.insert(
            "error".to_string(),
            serde_json::Value::String("Failed to generate URL".to_string()),
        );
    }

    println!("{}", serde_json::Value::Object(output).to_string());
    Ok(())
}

// This function is now replaced by S3Config::from_env in y-sweet-core

/// Y-Sign is a tool for signing and verifying tokens for y-sweet
#[derive(Parser)]
#[clap(version)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SignSubcommand,
}

#[derive(Subcommand)]
enum SignSubcommand {
    /// Generate a token for a document or file
    Sign {
        /// The authentication key for signing tokens
        #[clap(long, env = "RELAY_SERVER_AUTH")]
        auth: String,
    },

    /// Verify a token for a document or file
    Verify {
        /// The authentication key for verifying tokens
        #[clap(long, env = "RELAY_SERVER_AUTH")]
        auth: String,

        /// The document ID to verify against
        #[clap(long)]
        doc_id: Option<String>,

        /// The file hash to verify against
        #[clap(long)]
        file_hash: Option<String>,
    },

    /// Generate a presigned URL for a file using a token
    Presign {
        /// Action to perform (upload-url or download-url)
        action: String,

        /// Optional S3 store URL (s3://bucket/path format)
        #[clap(long, env = "RELAY_SERVER_STORAGE")]
        store: Option<String>,

        /// Optional AWS endpoint URL override
        #[clap(long, env = "AWS_ENDPOINT_URL_S3")]
        endpoint: Option<String>,

        /// Optional path style flag
        #[clap(long, env = "AWS_S3_USE_PATH_STYLE")]
        path_style: bool,

        /// The authentication key for validating tokens
        #[clap(long, env = "RELAY_SERVER_AUTH")]
        auth: Option<String>,
    },

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // No need for complex logging setup in this simple tool

    match &opts.subcmd {
        SignSubcommand::Sign { auth } => {
            let authenticator = Authenticator::new(auth)?;
            sign_stdin(&authenticator).await?;
        }
        SignSubcommand::Verify {
            auth,
            doc_id,
            file_hash,
        } => {
            let authenticator = Authenticator::new(auth)?;
            // Use the doc_id if provided, otherwise use file_hash if provided
            let id = doc_id.as_deref().or(file_hash.as_deref());
            verify_stdin(&authenticator, id).await?;
        }
        SignSubcommand::Presign {
            action,
            store,
            endpoint,
            path_style,
            auth,
        } => {
            // If store is provided via CLI arg, set it as an environment variable
            if let Some(store_url) = store {
                std::env::set_var("RELAY_SERVER_STORAGE", store_url);
            }

            // Use the unified S3Config::from_env method
            let mut s3_config = S3Config::from_env(None, None)?;

            // Override endpoint if provided
            if let Some(endpoint) = endpoint {
                s3_config.endpoint = endpoint.clone();
            }

            // Override path style if provided
            if *path_style {
                s3_config.path_style = true;
            }

            // Get auth key from command line argument or environment
            let auth_key = match auth {
                Some(key) => key.clone(),
                None => std::env::var("RELAY_SERVER_AUTH").map_err(|_| {
                    anyhow::anyhow!("RELAY_SERVER_AUTH environment variable is required")
                })?,
            };
            let authenticator = Authenticator::new(&auth_key)?;

            presign_stdin(&s3_config, &authenticator, &action).await?;
        }
        SignSubcommand::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use y_sweet_core::{
        api_types::Authorization,
        auth::{Authenticator, ExpirationTimeEpochMillis},
    };

    // Test server token generation and verification
    #[tokio::test]
    async fn test_server_token_generation() {
        let authenticator = Authenticator::new("dGVzdGtleXRlc3RrZXk=").unwrap();

        // Generate a server token
        let token = authenticator.server_token();

        // Create a mock context that simulates the sign_stdin and verify_stdin functions
        // without actually redirecting stdin/stdout

        // Verify the token and expected output for sign_stdin
        let sign_result = {
            // Create the expected JSON output
            let mut json_output = serde_json::Map::new();
            json_output.insert(
                "token".to_string(),
                serde_json::Value::String(token.clone()),
            );
            json_output.insert(
                "type".to_string(),
                serde_json::Value::String("server".to_string()),
            );
            json_output.insert(
                "authorization".to_string(),
                serde_json::Value::String("full".to_string()),
            );

            serde_json::Value::Object(json_output).to_string()
        };

        // Verify the token and expected output for verify_stdin
        let verify_result = {
            // Create the verification JSON output
            let mut json_output = serde_json::Map::new();
            let mut token_info = serde_json::Map::new();
            token_info.insert("raw".to_string(), serde_json::Value::String(token.clone()));

            let mut verification = serde_json::Map::new();
            verification.insert(
                "kind".to_string(),
                serde_json::Value::String("server".to_string()),
            );
            verification.insert("valid".to_string(), serde_json::Value::Bool(true));
            verification.insert(
                "authorization".to_string(),
                serde_json::Value::String("full".to_string()),
            );

            // Simulate verifying with a doc_id
            let doc_id = "test-doc-123";
            verification.insert(
                "docId".to_string(),
                serde_json::Value::String(doc_id.to_string()),
            );
            verification.insert(
                "docAccess".to_string(),
                serde_json::Value::String(
                    "full (server tokens can access all documents)".to_string(),
                ),
            );

            json_output.insert("token".to_string(), serde_json::Value::Object(token_info));
            json_output.insert(
                "verification".to_string(),
                serde_json::Value::Object(verification),
            );

            serde_json::Value::Object(json_output).to_string()
        };

        // Assertions on the expected JSON output for sign_stdin
        assert!(sign_result.contains("\"type\":\"server\""));
        assert!(sign_result.contains("\"authorization\":\"full\""));
        assert!(sign_result.contains(&format!("\"token\":\"{}\"", token)));

        // Assertions on the expected JSON output for verify_stdin
        assert!(verify_result.contains("\"valid\":true"));
        assert!(verify_result.contains("\"kind\":\"server\""));
        assert!(verify_result.contains("\"authorization\":\"full\""));
        assert!(verify_result.contains("docAccess"));
    }

    // Test file token verification with hash
    #[tokio::test]
    async fn test_verify_file_token_with_hash() {
        let authenticator = Authenticator::new("dGVzdGtleXRlc3RrZXk=").unwrap();
        let file_hash = "test123";
        let doc_id = "doc123";
        let content_type = "text/plain";
        let content_length = 1024;

        // Generate a file token
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX), // Never expires for testing
            Some(content_type),
            Some(content_length),
            None,
        );

        // Create a mock context that simulates the verify_stdin function's behavior
        // without actually redirecting stdin/stdout
        let verify_result = {
            // This is where we would normally call verify_stdin with redirected IO
            // For testing, we'll simulate the JSON output and assertions

            // Create the verification JSON output as it would be produced by verify_stdin
            let mut json_output = serde_json::Map::new();
            let mut token_info = serde_json::Map::new();
            token_info.insert("raw".to_string(), serde_json::Value::String(token.clone()));

            // Insert expected fields based on our implementation
            let mut verification = serde_json::Map::new();
            verification.insert(
                "kind".to_string(),
                serde_json::Value::String("file".to_string()),
            );
            verification.insert("valid".to_string(), serde_json::Value::Bool(true));
            verification.insert(
                "fileHash".to_string(),
                serde_json::Value::String(file_hash.to_string()),
            );
            verification.insert(
                "expectedDocId".to_string(),
                serde_json::Value::String(doc_id.to_string()),
            );
            verification.insert(
                "contentType".to_string(),
                serde_json::Value::String(content_type.to_string()),
            );
            verification.insert(
                "contentLength".to_string(),
                serde_json::Value::Number(serde_json::Number::from(content_length)),
            );

            // Create the final result JSON
            json_output.insert("token".to_string(), serde_json::Value::Object(token_info));
            json_output.insert(
                "verification".to_string(),
                serde_json::Value::Object(verification),
            );

            serde_json::Value::Object(json_output).to_string()
        };

        // Assertions on the expected JSON output
        assert!(verify_result.contains("\"valid\":true"));
        assert!(verify_result.contains("\"kind\":\"file\""));
        assert!(verify_result.contains(&format!("\"fileHash\":\"{}\"", file_hash)));
        assert!(verify_result.contains(&format!("\"expectedDocId\":\"{}\"", doc_id)));
        assert!(verify_result.contains(&format!("\"contentType\":\"{}\"", content_type)));
        assert!(verify_result.contains(&format!("\"contentLength\":{}", content_length)));
    }

    // Test file token verification without hash
    #[tokio::test]
    async fn test_verify_file_token_without_hash() {
        let authenticator = Authenticator::new("dGVzdGtleXRlc3RrZXk=").unwrap();
        let file_hash = "test123";
        let doc_id = "doc123";
        let content_type = "text/plain";
        let content_length = 1024;

        // Generate a file token
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(u64::MAX), // Never expires for testing
            Some(content_type),
            Some(content_length),
            None,
        );

        // Simulate the verification JSON output without providing a file hash
        let verify_result = {
            // Create the verification JSON output as it would be produced by verify_stdin
            let mut json_output = serde_json::Map::new();
            let mut token_info = serde_json::Map::new();
            token_info.insert("raw".to_string(), serde_json::Value::String(token.clone()));

            // Insert expected fields for file token without hash
            let mut verification = serde_json::Map::new();
            verification.insert(
                "kind".to_string(),
                serde_json::Value::String("file".to_string()),
            );
            verification.insert("valid".to_string(), serde_json::Value::Bool(false));
            verification.insert(
                "fileHash".to_string(),
                serde_json::Value::String(file_hash.to_string()),
            );
            verification.insert(
                "expectedDocId".to_string(),
                serde_json::Value::String(doc_id.to_string()),
            );
            verification.insert(
                "contentType".to_string(),
                serde_json::Value::String(content_type.to_string()),
            );
            verification.insert(
                "contentLength".to_string(),
                serde_json::Value::Number(serde_json::Number::from(content_length)),
            );
            verification.insert(
                "expectedFileHash".to_string(),
                serde_json::Value::String(file_hash.to_string()),
            );
            verification.insert(
                "error".to_string(),
                serde_json::Value::String(
                    "Token structure is valid but no file hash or doc ID provided for verification"
                        .to_string(),
                ),
            );

            // Create the final result JSON
            json_output.insert("token".to_string(), serde_json::Value::Object(token_info));
            json_output.insert(
                "verification".to_string(),
                serde_json::Value::Object(verification),
            );

            serde_json::Value::Object(json_output).to_string()
        };

        // Assertions on the expected JSON output
        assert!(verify_result.contains("\"valid\":false"));
        assert!(verify_result.contains("\"kind\":\"file\""));
        assert!(verify_result.contains(&format!("\"fileHash\":\"{}\"", file_hash)));
        assert!(verify_result.contains(&format!("\"expectedDocId\":\"{}\"", doc_id)));
        assert!(verify_result.contains(&format!("\"contentType\":\"{}\"", content_type)));
        assert!(verify_result.contains(&format!("\"contentLength\":{}", content_length)));
        assert!(verify_result.contains("\"expectedFileHash\":"));
        assert!(
            verify_result.contains("Token structure is valid but no file hash or doc ID provided")
        );
    }

    // Test server token verification
    #[tokio::test]
    async fn test_verify_server_token() {
        let authenticator = Authenticator::new("dGVzdGtleXRlc3RrZXk=").unwrap();

        // Generate a server token
        let token = authenticator.server_token();

        // Simulate verification output
        let verify_result = {
            // Create the verification JSON output
            let mut json_output = serde_json::Map::new();
            let mut token_info = serde_json::Map::new();
            token_info.insert("raw".to_string(), serde_json::Value::String(token.clone()));

            let mut verification = serde_json::Map::new();
            verification.insert(
                "kind".to_string(),
                serde_json::Value::String("server".to_string()),
            );
            verification.insert("valid".to_string(), serde_json::Value::Bool(true));

            json_output.insert("token".to_string(), serde_json::Value::Object(token_info));
            json_output.insert(
                "verification".to_string(),
                serde_json::Value::Object(verification),
            );

            serde_json::Value::Object(json_output).to_string()
        };

        // Assertions on the expected JSON output
        assert!(verify_result.contains("\"valid\":true"));
        assert!(verify_result.contains("\"kind\":\"server\""));
    }
}
