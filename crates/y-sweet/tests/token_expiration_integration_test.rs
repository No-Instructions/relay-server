use std::time::Duration;
use tokio::time::sleep;

use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::{Authenticator, ExpirationTimeEpochMillis};

#[tokio::test]
async fn test_token_expiration_integration() {
    // Create a test authenticator with a valid 32-byte base64 key
    let mut auth = Authenticator::new("dGhpcy1pcy1leGFjdGx5LTMyLWJ5dGVzLWZvci10ZXN0")
        .expect("Failed to create authenticator");
    auth.set_expected_audience(Some("https://test.example.com".to_string()));

    // Create a token that expires in 1 second
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let short_expiration = ExpirationTimeEpochMillis(current_time + 1000);

    let token = auth
        .gen_doc_token_cwt(
            "test-doc",
            Authorization::Full,
            short_expiration,
            None,
            None,
        )
        .expect("Failed to generate token");

    // Verify token is valid initially
    let verification_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let result = auth.verify_doc_token(&token, "test-doc", verification_time);
    assert!(result.is_ok(), "Token should be valid initially");

    // Wait for token to expire
    sleep(Duration::from_millis(1100)).await;

    // Verify token is now expired
    let current_time_after_sleep = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let result = auth.verify_doc_token(&token, "test-doc", current_time_after_sleep);
    assert!(result.is_err(), "Token should be expired");

    // Check that it's specifically an expiration error
    let error_message = format!("{}", result.unwrap_err());
    assert!(
        error_message.contains("expired") || error_message.contains("Expired"),
        "Error should mention expiration, got: {}",
        error_message
    );
}

#[tokio::test]
async fn test_token_without_expiration() {
    // Create a test authenticator with a valid 32-byte base64 key
    let mut auth = Authenticator::new("dGhpcy1pcy1leGFjdGx5LTMyLWJ5dGVzLWZvci10ZXN0")
        .expect("Failed to create authenticator");
    auth.set_expected_audience(Some("https://test.example.com".to_string()));

    // Create a token without expiration by using a very far future time
    let far_future = ExpirationTimeEpochMillis(u64::MAX / 2); // Very far in the future
    let token = auth
        .gen_doc_token_cwt("test-doc", Authorization::Full, far_future, None, None)
        .expect("Failed to generate token");

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Verify token is valid
    let result = auth.verify_doc_token(&token, "test-doc", current_time);
    assert!(result.is_ok(), "Token without expiration should be valid");

    // Wait a bit
    sleep(Duration::from_millis(50)).await;

    // Verify token is still valid
    let current_time_after_sleep = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let result = auth.verify_doc_token(&token, "test-doc", current_time_after_sleep);
    assert!(
        result.is_ok(),
        "Token without expiration should still be valid"
    );
}

#[tokio::test]
async fn test_token_verification_timing() {
    // Create a test authenticator with a valid 32-byte base64 key
    let mut auth = Authenticator::new("dGhpcy1pcy1leGFjdGx5LTMyLWJ5dGVzLWZvci10ZXN0")
        .expect("Failed to create authenticator");
    auth.set_expected_audience(Some("https://test.example.com".to_string()));

    // Test with expiration - create a token that expires in 2 seconds
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let expiration_time = ExpirationTimeEpochMillis(current_time + 2000); // 2 seconds

    let token_with_exp = auth
        .gen_doc_token_cwt("test-doc", Authorization::Full, expiration_time, None, None)
        .expect("Failed to generate token");

    // Verify token is initially valid
    let result = auth.verify_doc_token(&token_with_exp, "test-doc", current_time + 100);
    assert!(result.is_ok(), "Token should be valid initially");

    // Wait for token to expire
    sleep(Duration::from_millis(2100)).await;

    // Verify token is now expired
    let current_time_after_sleep = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let result = auth.verify_doc_token(&token_with_exp, "test-doc", current_time_after_sleep);
    assert!(result.is_err(), "Token should be expired");

    // Check that it's specifically an expiration error
    let error_message = format!("{}", result.unwrap_err());
    assert!(
        error_message.contains("expired") || error_message.contains("Expired"),
        "Error should mention expiration, got: {}",
        error_message
    );
}
