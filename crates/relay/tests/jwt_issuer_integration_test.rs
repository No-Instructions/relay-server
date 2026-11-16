//! A JWT from a configured issuer opens a document websocket within its
//! granted prefix, and is refused outside it.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use relay::server::Server;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite};
use tokio_util::sync::CancellationToken;
use y_sweet_core::auth::{b64_encode, Authenticator};
use y_sweet_core::config::{JwtGrantConfig, JwtIssuerConfig, OneOrMany};
use y_sweet_core::jwt::JwtIssuers;

const ISSUER: &str = "https://login.example.com/tenant/v2.0";
const AUDIENCE: &str = "relay-client-id";

#[tokio::test]
async fn jwt_opens_websocket_within_its_prefix() {
    let secret = p256::SecretKey::random(&mut OsRng);
    let point = secret.public_key().to_encoded_point(false);
    let encoding_key = EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes());

    let issuers = JwtIssuers::from_config(&[JwtIssuerConfig {
        issuer: ISSUER.to_string(),
        audience: OneOrMany::One(AUDIENCE.to_string()),
        jwks_uri: None,
        user_claim: "sub".to_string(),
        algorithms: vec!["ES256".to_string()],
        leeway_seconds: 60,
        jwks_refresh_seconds: 3600,
        grant: vec![JwtGrantConfig {
            claim: "roles".to_string(),
            contains: "Relay.Write".to_string(),
            scope: "prefix:relay-1-:rw".to_string(),
        }],
    }])
    .unwrap();
    // Inject the keys rather than fetch them, so the test makes no outbound calls.
    issuers
        .set_keys(
            ISSUER,
            &json!({ "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": "key-1",
                "x": b64_encode(point.x().unwrap()),
                "y": b64_encode(point.y().unwrap()),
            }]}),
        )
        .unwrap();

    let mut authenticator = Authenticator::gen_key().unwrap();
    authenticator.set_expected_audience(Some("https://relay.example.com".to_string()));
    authenticator.set_jwt_issuers(Arc::new(issuers));

    let shutdown = CancellationToken::new();
    let server = Arc::new(
        Server::new(
            None,
            Duration::from_secs(60),
            Some(authenticator),
            None,
            vec![],
            shutdown.clone(),
            true,
            None,
        )
        .await
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = server.routes();
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await
            .unwrap();
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("key-1".to_string());
    let token = jsonwebtoken::encode(
        &header,
        &json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "exp": now + 300,
            "roles": ["Relay.Write"],
        }),
        &encoding_key,
    )
    .unwrap();

    let url = |doc: &str| format!("ws://{address}/d/{doc}/ws/{doc}?token={token}");

    let (mut socket, _) = connect_async(url("relay-1-doc"))
        .await
        .expect("a JWT should open a doc within its prefix");
    socket.close(None).await.unwrap();

    match connect_async(url("other-doc")).await {
        Err(tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), http::StatusCode::FORBIDDEN)
        }
        other => panic!(
            "expected a 403 outside the prefix, got {:?}",
            other.map(|_| ())
        ),
    }

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
