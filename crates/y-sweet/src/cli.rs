use colored::Colorize;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use url::Url;
use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::{AuthError, Authenticator};

pub fn print_auth_message(auth: &Authenticator) {
    match auth.key_material() {
        y_sweet_core::auth::AuthKeyMaterial::EcdsaP256Public(_) => {
            println!("Run y-sweet with the following option to enable authentication (verification-only mode):");
            println!();
            println!(
                "   {} {} {}",
                "y-sweet serve".bright_black(),
                "--auth".bright_white().bold(),
                auth.key_material().to_base64().bright_blue().bold()
            );
            println!();
            println!(
                "   {}",
                "Note: This is a public key - server will verify tokens but cannot create them."
                    .bright_yellow()
            );
        }
        _ => {
            println!("Run y-sweet with the following option to enable authentication:");
            println!();
            println!(
                "   {} {} {}",
                "y-sweet serve".bright_black(),
                "--auth".bright_white().bold(),
                auth.key_material().to_base64().bright_blue().bold()
            );
        }
    }
    println!();
}
#[derive(Deserialize)]
struct SignInput {
    #[serde(rename = "docId")]
    doc_id: Option<String>,
    #[serde(rename = "fileHash")]
    file_hash: Option<String>,
    authorization: Option<String>,
    #[serde(rename = "type")]
    token_type: Option<String>,
}

#[derive(Serialize)]
struct SignOutput {
    #[serde(rename = "docId", skip_serializing_if = "Option::is_none")]
    doc_id: Option<String>,
    #[serde(rename = "fileHash", skip_serializing_if = "Option::is_none")]
    file_hash: Option<String>,
    token: String,
    authorization: Authorization,
    #[serde(rename = "type")]
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(rename = "baseUrl", skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
}

#[derive(Serialize)]
struct VerifyOutput {
    token: TokenInfo,
    verification: VerificationResult,
}

#[derive(Serialize)]
struct TokenInfo {
    payload: serde_json::Value,
    raw: String,
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "docId")]
    doc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "fileHash")]
    file_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub async fn sign_stdin(auth: &Authenticator) -> anyhow::Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut buffer = String::new();
    stdin.read_to_string(&mut buffer).await?;

    let input: SignInput = serde_json::from_str(&buffer)?;

    // Determine token type - default to "document" if not specified
    let token_type = input.token_type.as_deref().unwrap_or("document");

    if token_type != "document" && token_type != "file" {
        anyhow::bail!(
            "Invalid token type: {}. Must be 'document' or 'file'",
            token_type
        );
    }

    let authorization = match input.authorization.as_deref() {
        Some("read") => Authorization::ReadOnly,
        Some("full") => Authorization::Full,
        Some(other) => anyhow::bail!("Invalid authorization: {}. Must be 'read' or 'full'", other),
        None => Authorization::Full,
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let expiration = y_sweet_core::auth::ExpirationTimeEpochMillis(
        current_time + (y_sweet_core::auth::DEFAULT_EXPIRATION_SECONDS * 1000),
    );

    match token_type {
        "document" => {
            let doc_id = input
                .doc_id
                .ok_or_else(|| anyhow::anyhow!("docId is required for document tokens"))?;

            let token = auth.gen_doc_token(&doc_id, authorization.clone(), expiration, None)?;

            let (url, base_url) = if let Ok(prefix_url) = std::env::var("RELAY_SERVER_PREFIX_URL") {
                let prefix_url = Url::parse(&prefix_url)?;
                let mut ws_url = prefix_url.clone();
                ws_url
                    .set_scheme(if prefix_url.scheme() == "https" {
                        "wss"
                    } else {
                        "ws"
                    })
                    .map_err(|_| anyhow::anyhow!("Failed to set websocket scheme"))?;
                ws_url = ws_url.join(&format!("/d/{}/ws", doc_id))?;

                let mut base_url = prefix_url;
                if !base_url.as_str().ends_with('/') {
                    base_url = base_url.join("/")?;
                }
                base_url = base_url.join(&format!("d/{}", doc_id))?;

                (Some(ws_url.to_string()), Some(base_url.to_string()))
            } else {
                (None, None)
            };

            let output = SignOutput {
                doc_id: Some(doc_id),
                file_hash: None,
                token,
                authorization,
                token_type: "document".to_string(),
                url,
                base_url,
            };

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "file" => {
            let file_hash = input
                .file_hash
                .ok_or_else(|| anyhow::anyhow!("fileHash is required for file tokens"))?;

            let doc_id = input
                .doc_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("docId is required for file tokens"))?;

            let token = auth.gen_file_token(
                &file_hash,
                &doc_id,
                authorization.clone(),
                expiration,
                None,
                None,
                None,
            )?;

            // For files, we don't generate URLs since they are accessed through the file endpoints
            let output = SignOutput {
                doc_id: Some(doc_id),
                file_hash: Some(file_hash),
                token,
                authorization,
                token_type: "file".to_string(),
                url: None,
                base_url: None,
            };

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => unreachable!(), // We already validated token_type above
    }

    Ok(())
}

pub async fn verify_stdin(auth: &Authenticator, id: Option<&str>) -> anyhow::Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut token = String::new();
    stdin.read_to_string(&mut token).await?;
    let token = token.trim();

    // Try to decode the token regardless of verification
    let decoded_payload = match auth.decode_token(token) {
        Ok(payload) => serde_json::to_value(payload)?,
        Err(_) => serde_json::Value::Null,
    };

    // Try to determine the token type from the payload
    let token_type = if let serde_json::Value::Object(obj) = &decoded_payload {
        if let Some(serde_json::Value::Object(payload_obj)) = obj.get("payload") {
            if payload_obj.contains_key("Doc") {
                "document"
            } else if payload_obj.contains_key("File") {
                "file"
            } else if payload_obj.contains_key("Server") {
                "server"
            } else {
                "unknown"
            }
        } else {
            "unknown"
        }
    } else {
        "unknown"
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    let verification = match auth.verify_server_token(token, current_time) {
        Ok(()) => VerificationResult {
            valid: true,
            kind: "server".to_string(),
            authorization: None,
            doc_id: None,
            file_hash: None,
            error: None,
        },
        Err(AuthError::InvalidResource) => {
            // This might be a document or file token
            if let Some(id) = id {
                if token_type == "file" {
                    // Try both file verification methods (by hash and by doc_id)
                    let file_hash_auth = auth.verify_file_token(token, id, current_time);
                    let doc_id_auth = auth.verify_file_token_for_doc(token, id, current_time);

                    if let Ok(authorization) = file_hash_auth {
                        // Successfully verified as file hash
                        let auth_str = match authorization {
                            Authorization::ReadOnly => "read",
                            Authorization::Full => "full",
                        };

                        VerificationResult {
                            valid: true,
                            kind: "file".to_string(),
                            authorization: Some(auth_str.to_string()),
                            doc_id: None,
                            file_hash: Some(id.to_string()),
                            error: None,
                        }
                    } else if let Ok(authorization) = doc_id_auth {
                        // Successfully verified as doc_id
                        let auth_str = match authorization {
                            Authorization::ReadOnly => "read",
                            Authorization::Full => "full",
                        };

                        VerificationResult {
                            valid: true,
                            kind: "file".to_string(),
                            authorization: Some(auth_str.to_string()),
                            doc_id: Some(id.to_string()),
                            file_hash: None,
                            error: None,
                        }
                    } else {
                        // Both verification methods failed
                        VerificationResult {
                            valid: false,
                            kind: "file".to_string(),
                            authorization: None,
                            doc_id: None,
                            file_hash: Some(id.to_string()),
                            error: Some(
                                "File token verification failed for both file hash and doc ID"
                                    .to_string(),
                            ),
                        }
                    }
                } else {
                    // Verify as document token
                    match auth.verify_doc_token(token, id, current_time) {
                        Ok(authorization) => {
                            let auth_str = match authorization {
                                Authorization::ReadOnly => "read",
                                Authorization::Full => "full",
                            };

                            VerificationResult {
                                valid: true,
                                kind: "document".to_string(),
                                authorization: Some(auth_str.to_string()),
                                doc_id: Some(id.to_string()),
                                file_hash: None,
                                error: None,
                            }
                        }
                        Err(e) => VerificationResult {
                            valid: false,
                            kind: "document".to_string(),
                            authorization: None,
                            doc_id: Some(id.to_string()),
                            file_hash: None,
                            error: Some(e.to_string()),
                        },
                    }
                }
            } else {
                VerificationResult {
                    valid: false,
                    kind: "unknown".to_string(),
                    authorization: None,
                    doc_id: None,
                    file_hash: None,
                    error: Some("No ID provided for token verification".to_string()),
                }
            }
        }
        Err(e) => VerificationResult {
            valid: false,
            kind: "server".to_string(),
            authorization: None,
            doc_id: None,
            file_hash: None,
            error: Some(e.to_string()),
        },
    };

    let output = VerifyOutput {
        token: TokenInfo {
            payload: decoded_payload,
            raw: token.to_string(),
        },
        verification,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
