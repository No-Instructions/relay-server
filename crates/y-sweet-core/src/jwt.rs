//! Verification of JWTs from external issuers configured with `[[jwt_issuer]]`.
//!
//! Each issuer's signing keys are kept in a cache that a background task
//! fills from the issuer's JWKS, so that verification itself stays
//! synchronous. Claims are mapped to Relay permissions through the issuer's
//! `[[jwt_issuer.grant]]` rules.

use crate::api_types::Authorization;
use crate::auth::{b64_decode, AuthError, Permission};
use crate::config::JwtIssuerConfig;
use crate::cwt::scope_to_permission;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Header, Validation};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// A token naming an unknown `kid` triggers at most one early refresh per
/// issuer in this window.
const UNKNOWN_KID_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(5 * 60);

/// The configured JWT issuers and their signing-key caches.
pub struct JwtIssuers {
    issuers: Vec<Arc<Issuer>>,
}

struct Issuer {
    issuer: String,
    audience: Vec<String>,
    jwks_uri: Option<String>,
    user_claim: String,
    algorithms: Vec<Algorithm>,
    leeway_seconds: u64,
    refresh_interval: Duration,
    grants: Vec<Grant>,
    keys: RwLock<HashMap<String, DecodingKey>>,
    last_fetch: Mutex<Option<Instant>>,
    refresh_requested: Notify,
}

struct Grant {
    claim: String,
    contains: String,
    permission: Permission,
}

impl std::fmt::Debug for JwtIssuers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.issuers.iter().map(|issuer| &issuer.issuer))
            .finish()
    }
}

/// Two handles are equal only when they are the same set of caches.
impl PartialEq for JwtIssuers {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl JwtIssuers {
    /// Build the issuers from configuration. Fails on anything that would make
    /// an issuer unusable or unsafe, so that a bad config stops startup.
    pub fn from_config(configs: &[JwtIssuerConfig]) -> Result<Self, String> {
        let mut seen = HashSet::new();
        let mut issuers = Vec::with_capacity(configs.len());

        for config in configs {
            if config.issuer.is_empty() {
                return Err("jwt_issuer.issuer cannot be empty".to_string());
            }
            if !seen.insert(config.issuer.as_str()) {
                return Err(format!("Duplicate jwt_issuer: {}", config.issuer));
            }
            let context = |msg: String| format!("jwt_issuer {}: {}", config.issuer, msg);

            let audience = config.audience.to_vec();
            if audience.is_empty() || audience.iter().any(|a| a.is_empty()) {
                return Err(context("audience cannot be empty".to_string()));
            }

            match &config.jwks_uri {
                Some(uri) => {
                    url::Url::parse(uri)
                        .map_err(|_| context(format!("invalid jwks_uri: {}", uri)))?;
                }
                None => {
                    url::Url::parse(&config.issuer).map_err(|_| {
                        context("issuer is not a URL, so jwks_uri must be set".to_string())
                    })?;
                }
            }

            if config.algorithms.is_empty() {
                return Err(context("algorithms cannot be empty".to_string()));
            }
            let algorithms = config
                .algorithms
                .iter()
                .map(|name| parse_algorithm(name).map_err(context))
                .collect::<Result<Vec<_>, _>>()?;

            if config.jwks_refresh_seconds == 0 {
                return Err(context("jwks_refresh_seconds must be positive".to_string()));
            }

            if config.grant.is_empty() {
                return Err(context(
                    "at least one [[jwt_issuer.grant]] is required".to_string(),
                ));
            }
            let mut grants = Vec::with_capacity(config.grant.len());
            for grant in &config.grant {
                if grant.claim.is_empty() {
                    return Err(context("grant.claim cannot be empty".to_string()));
                }
                let permission = scope_to_permission(&grant.scope)
                    .map_err(|_| context(format!("invalid grant scope: {}", grant.scope)))?;
                grants.push(Grant {
                    claim: grant.claim.clone(),
                    contains: grant.contains.clone(),
                    permission,
                });
            }

            issuers.push(Arc::new(Issuer {
                issuer: config.issuer.clone(),
                audience,
                jwks_uri: config.jwks_uri.clone(),
                user_claim: config.user_claim.clone(),
                algorithms,
                leeway_seconds: config.leeway_seconds,
                refresh_interval: Duration::from_secs(config.jwks_refresh_seconds),
                grants,
                keys: RwLock::new(HashMap::new()),
                last_fetch: Mutex::new(None),
                refresh_requested: Notify::new(),
            }));
        }

        Ok(Self { issuers })
    }

    /// Verify a JWT and return every permission its matching grants confer,
    /// in configuration order, each carrying the token's user.
    ///
    /// `current_time_millis` of `None` skips the `exp` and `nbf` checks.
    pub fn verify(
        &self,
        token: &str,
        current_time_millis: Option<u64>,
    ) -> Result<Vec<Permission>, AuthError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::InvalidToken)?;
        let iss = unverified_claims(token)
            .and_then(|claims| claims.get("iss")?.as_str().map(str::to_string))
            .ok_or_else(|| {
                tracing::info!("JWT rejected: no iss claim");
                AuthError::InvalidClaims
            })?;

        let issuer = self
            .issuers
            .iter()
            .find(|issuer| issuer.issuer == iss)
            .ok_or_else(|| {
                tracing::info!(issuer = %iss, "JWT rejected: issuer not configured");
                AuthError::UnknownIssuer
            })?;

        issuer.verify(token, &header, current_time_millis)
    }

    /// Replace an issuer's signing keys with those in a JWKS document.
    /// Returns the number of usable keys.
    pub fn set_keys(&self, issuer: &str, jwks: &Value) -> Result<usize, String> {
        let issuer = self.find(issuer)?;
        let keys = parse_jwks(jwks);
        let count = keys.len();
        *issuer.keys.write().unwrap() = keys;
        Ok(count)
    }

    /// Fetch an issuer's signing keys now. Returns the number of usable keys.
    pub async fn refresh(&self, issuer: &str, client: &reqwest::Client) -> Result<usize, String> {
        self.find(issuer)?.refresh(client).await
    }

    /// One long-running task per issuer that keeps its keys fresh. The caller
    /// spawns them on its runtime.
    pub fn refresh_tasks(&self) -> Vec<impl Future<Output = ()> + Send + 'static> {
        let client = reqwest::Client::new();
        self.issuers
            .iter()
            .map(|issuer| issuer.clone().refresh_loop(client.clone()))
            .collect()
    }

    fn find(&self, issuer: &str) -> Result<&Arc<Issuer>, String> {
        self.issuers
            .iter()
            .find(|i| i.issuer == issuer)
            .ok_or_else(|| format!("No jwt_issuer {}", issuer))
    }
}

impl Issuer {
    fn reject(&self, reason: &str, error: AuthError) -> AuthError {
        tracing::info!(issuer = %self.issuer, reason, "JWT rejected");
        error
    }

    fn verify(
        &self,
        token: &str,
        header: &Header,
        current_time_millis: Option<u64>,
    ) -> Result<Vec<Permission>, AuthError> {
        if !self.algorithms.contains(&header.alg) {
            return Err(self.reject("algorithm not allowed", AuthError::UnsupportedAlgorithm));
        }

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| self.reject("no kid in header", AuthError::KeyMismatch))?;
        let key = self.keys.read().unwrap().get(kid).cloned();
        let key = match key {
            Some(key) => key,
            None => {
                self.request_refresh();
                return Err(self.reject("unknown kid", AuthError::KeyMismatch));
            }
        };
        if key.family() != header.alg.family() {
            return Err(self.reject(
                "key type does not match algorithm",
                AuthError::UnsupportedAlgorithm,
            ));
        }

        let mut validation = Validation::new(header.alg);
        // Times are checked below against the caller's clock.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audience);

        let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
            .map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::InvalidSignature => {
                        self.reject("bad signature", AuthError::InvalidSignature)
                    }
                    ErrorKind::InvalidAudience => self.reject(
                        "audience mismatch",
                        AuthError::InvalidAudience {
                            expected: self.audience.join(","),
                            found: unverified_claims(token)
                                .and_then(|c| c.get("aud").map(|aud| aud.to_string()))
                                .unwrap_or_default(),
                        },
                    ),
                    ErrorKind::InvalidIssuer => {
                        self.reject("issuer mismatch", AuthError::InvalidClaims)
                    }
                    ErrorKind::MissingRequiredClaim(_) => {
                        self.reject("missing required claim", AuthError::InvalidClaims)
                    }
                    ErrorKind::InvalidAlgorithm => {
                        self.reject("algorithm mismatch", AuthError::UnsupportedAlgorithm)
                    }
                    _ => self.reject("malformed token", AuthError::InvalidToken),
                }
            })?
            .claims;

        if let Some(now_millis) = current_time_millis {
            let now = now_millis / 1000;
            let exp = numeric_claim(&claims, "exp")
                .ok_or_else(|| self.reject("exp is not a number", AuthError::InvalidClaims))?;
            if now > exp.saturating_add(self.leeway_seconds) {
                return Err(self.reject("expired", AuthError::Expired));
            }
            if let Some(nbf) = claims.get("nbf") {
                let nbf = nbf
                    .as_f64()
                    .ok_or_else(|| self.reject("nbf is not a number", AuthError::InvalidClaims))?;
                if nbf as u64 > now.saturating_add(self.leeway_seconds) {
                    return Err(self.reject("not yet valid", AuthError::NotYetValid));
                }
            }
        }

        let user = claims
            .get(&self.user_claim)
            .and_then(Value::as_str)
            .map(str::to_string);

        let permissions: Vec<Permission> = self
            .grants
            .iter()
            .filter(|grant| claim_contains(&claims, &grant.claim, &grant.contains))
            .map(|grant| with_user(grant.permission.clone(), user.clone()))
            .collect();

        if permissions.is_empty() {
            return Err(self.reject(
                "no grant matches",
                AuthError::InsufficientPermissions("no grant matches the token's claims".into()),
            ));
        }

        Ok(permissions)
    }

    /// Wake the refresh task early, at most once per
    /// `UNKNOWN_KID_REFRESH_INTERVAL`, so a rotated key is picked up without
    /// letting unknown-`kid` tokens drive requests to the issuer.
    fn request_refresh(&self) {
        let mut last_fetch = self.last_fetch.lock().unwrap();
        if last_fetch.map_or(true, |t| t.elapsed() >= UNKNOWN_KID_REFRESH_INTERVAL) {
            *last_fetch = Some(Instant::now());
            self.refresh_requested.notify_one();
        }
    }

    async fn refresh(&self, client: &reqwest::Client) -> Result<usize, String> {
        *self.last_fetch.lock().unwrap() = Some(Instant::now());
        let keys = tokio::time::timeout(FETCH_TIMEOUT, self.fetch_keys(client))
            .await
            .map_err(|_| "timed out".to_string())??;
        if keys.is_empty() {
            // Keep the keys we have rather than lock everyone out.
            return Err("JWKS has no usable signing keys".to_string());
        }
        let count = keys.len();
        *self.keys.write().unwrap() = keys;
        Ok(count)
    }

    async fn fetch_keys(
        &self,
        client: &reqwest::Client,
    ) -> Result<HashMap<String, DecodingKey>, String> {
        let jwks_uri = match &self.jwks_uri {
            Some(uri) => uri.clone(),
            None => {
                let discovery_url = format!(
                    "{}/.well-known/openid-configuration",
                    self.issuer.trim_end_matches('/')
                );
                let discovery = fetch_json(client, &discovery_url).await?;
                discovery
                    .get("jwks_uri")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{} has no jwks_uri", discovery_url))?
                    .to_string()
            }
        };
        Ok(parse_jwks(&fetch_json(client, &jwks_uri).await?))
    }

    async fn refresh_loop(self: Arc<Self>, client: reqwest::Client) {
        let mut retry = RETRY_MIN;
        loop {
            let wait = match self.refresh(&client).await {
                Ok(count) => {
                    tracing::info!(issuer = %self.issuer, keys = count, "Loaded JWT signing keys");
                    retry = RETRY_MIN;
                    self.refresh_interval
                }
                Err(error) => {
                    tracing::warn!(
                        issuer = %self.issuer,
                        %error,
                        "Failed to fetch JWT signing keys; keeping any already loaded"
                    );
                    let wait = retry;
                    retry = (retry * 2).min(RETRY_MAX).min(self.refresh_interval);
                    wait.min(self.refresh_interval)
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.refresh_requested.notified() => {}
            }
        }
    }
}

async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<Value, String> {
    client
        .get(url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|e| format!("{}: {}", url, e))?
        .json::<Value>()
        .await
        .map_err(|e| format!("{}: {}", url, e))
}

/// Keep the asymmetric signing keys that have a `kid`; skip anything else
/// rather than fail the whole set.
fn parse_jwks(jwks: &Value) -> HashMap<String, DecodingKey> {
    let mut keys = HashMap::new();
    let Some(entries) = jwks.get("keys").and_then(Value::as_array) else {
        return keys;
    };
    for entry in entries {
        let Ok(jwk) = serde_json::from_value::<Jwk>(entry.clone()) else {
            continue;
        };
        let Some(kid) = jwk.common.key_id.clone() else {
            continue;
        };
        if matches!(
            jwk.common.public_key_use,
            Some(PublicKeyUse::Encryption) | Some(PublicKeyUse::Other(_))
        ) {
            continue;
        }
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            continue;
        }
        if let Ok(key) = DecodingKey::from_jwk(&jwk) {
            keys.insert(kid, key);
        }
    }
    keys
}

fn parse_algorithm(name: &str) -> Result<Algorithm, String> {
    let algorithm =
        Algorithm::from_str(name).map_err(|_| format!("unsupported algorithm: {}", name))?;
    if algorithm.family() == AlgorithmFamily::Hmac {
        return Err(format!("symmetric algorithm {} is not allowed", name));
    }
    Ok(algorithm)
}

/// The payload of a JWT, decoded but not verified.
fn unverified_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&b64_decode(payload).ok()?).ok()
}

fn numeric_claim(claims: &Value, name: &str) -> Option<u64> {
    claims.get(name)?.as_f64().map(|value| value as u64)
}

/// Whether a top-level claim equals `value`, or is an array containing it.
fn claim_contains(claims: &Value, claim: &str, value: &str) -> bool {
    match claims.get(claim) {
        Some(Value::String(s)) => s == value,
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(value)),
        _ => false,
    }
}

fn with_user(mut permission: Permission, user: Option<String>) -> Permission {
    match &mut permission {
        Permission::Doc(p) => p.user = user,
        Permission::File(p) => p.user = user,
        Permission::Prefix(p) => p.user = user,
        Permission::Server => {}
    }
    permission
}

/// The authorization a permission confers. Server permissions confer full access.
pub(crate) fn authorization_of(permission: &Permission) -> Authorization {
    match permission {
        Permission::Server => Authorization::Full,
        Permission::Doc(p) => p.authorization,
        Permission::File(p) => p.authorization,
        Permission::Prefix(p) => p.authorization,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{b64_encode, detect_token_format, Authenticator, TokenFormat};
    use crate::config::{JwtGrantConfig, OneOrMany};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;
    use std::sync::OnceLock;

    const ISSUER: &str = "https://login.example.com/tenant/v2.0";
    const AUDIENCE: &str = "relay-client-id";
    const NOW_SECS: u64 = 1_800_000_000;
    const NOW_MILLIS: u64 = NOW_SECS * 1000;

    struct TestKey {
        kid: &'static str,
        alg: Algorithm,
        encoding: EncodingKey,
        jwk: Value,
    }

    fn rsa_key() -> &'static TestKey {
        static KEY: OnceLock<TestKey> = OnceLock::new();
        KEY.get_or_init(|| {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            use rsa::traits::PublicKeyParts;
            let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
            TestKey {
                kid: "rsa-1",
                alg: Algorithm::RS256,
                encoding: EncodingKey::from_rsa_der(private.to_pkcs1_der().unwrap().as_bytes()),
                jwk: json!({
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "rsa-1",
                    "n": b64_encode(&private.n().to_bytes_be()),
                    "e": b64_encode(&private.e().to_bytes_be()),
                }),
            }
        })
    }

    fn ec_key() -> &'static TestKey {
        static KEY: OnceLock<TestKey> = OnceLock::new();
        KEY.get_or_init(|| {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            use p256::pkcs8::EncodePrivateKey;
            let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
            let point = secret.public_key().to_encoded_point(false);
            TestKey {
                kid: "ec-1",
                alg: Algorithm::ES256,
                encoding: EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes()),
                jwk: json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "ec-1",
                    "x": b64_encode(point.x().unwrap()),
                    "y": b64_encode(point.y().unwrap()),
                }),
            }
        })
    }

    fn grant(claim: &str, contains: &str, scope: &str) -> JwtGrantConfig {
        JwtGrantConfig {
            claim: claim.to_string(),
            contains: contains.to_string(),
            scope: scope.to_string(),
        }
    }

    fn issuer_config(grants: Vec<JwtGrantConfig>) -> JwtIssuerConfig {
        JwtIssuerConfig {
            issuer: ISSUER.to_string(),
            audience: OneOrMany::One(AUDIENCE.to_string()),
            jwks_uri: None,
            user_claim: "sub".to_string(),
            algorithms: vec!["RS256".to_string(), "ES256".to_string()],
            leeway_seconds: 60,
            jwks_refresh_seconds: 3600,
            grant: grants,
        }
    }

    fn default_grants() -> Vec<JwtGrantConfig> {
        vec![
            grant("roles", "Relay.Read", "prefix:relay-1-:r"),
            grant("roles", "Relay.Write", "prefix:relay-1-:rw"),
        ]
    }

    fn issuers_with(grants: Vec<JwtGrantConfig>) -> JwtIssuers {
        let issuers = JwtIssuers::from_config(&[issuer_config(grants)]).unwrap();
        let jwks = json!({ "keys": [rsa_key().jwk, ec_key().jwk] });
        assert_eq!(issuers.set_keys(ISSUER, &jwks).unwrap(), 2);
        issuers
    }

    fn claims(roles: Value) -> Value {
        json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "exp": NOW_SECS + 3600,
            "nbf": NOW_SECS - 60,
            "roles": roles,
        })
    }

    fn sign(key: &TestKey, claims: &Value) -> String {
        let mut header = Header::new(key.alg);
        header.kid = Some(key.kid.to_string());
        jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
    }

    fn verify(issuers: &JwtIssuers, token: &str) -> Result<Vec<Permission>, AuthError> {
        issuers.verify(token, Some(NOW_MILLIS))
    }

    fn prefixes(permissions: &[Permission]) -> Vec<(String, Authorization)> {
        permissions
            .iter()
            .map(|p| match p {
                Permission::Prefix(p) => (p.prefix.clone(), p.authorization),
                other => panic!("unexpected permission {:?}", other),
            })
            .collect()
    }

    #[test]
    fn valid_rsa_token() {
        let issuers = issuers_with(default_grants());
        let token = sign(rsa_key(), &claims(json!(["Relay.Read"])));
        let permissions = verify(&issuers, &token).unwrap();
        assert_eq!(
            prefixes(&permissions),
            vec![("relay-1-".to_string(), Authorization::ReadOnly)]
        );
        match &permissions[0] {
            Permission::Prefix(p) => assert_eq!(p.user.as_deref(), Some("user-123")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_ec_token() {
        let issuers = issuers_with(default_grants());
        let token = sign(ec_key(), &claims(json!(["Relay.Write"])));
        assert_eq!(
            prefixes(&verify(&issuers, &token).unwrap()),
            vec![("relay-1-".to_string(), Authorization::Full)]
        );
    }

    #[test]
    fn user_claim_is_configurable() {
        let mut config = issuer_config(default_grants());
        config.user_claim = "oid".to_string();
        let issuers = JwtIssuers::from_config(&[config]).unwrap();
        issuers
            .set_keys(ISSUER, &json!({ "keys": [rsa_key().jwk] }))
            .unwrap();
        let mut c = claims(json!("Relay.Read"));
        c["oid"] = json!("object-id");
        let permissions = verify(&issuers, &sign(rsa_key(), &c)).unwrap();
        match &permissions[0] {
            Permission::Prefix(p) => assert_eq!(p.user.as_deref(), Some("object-id")),
            _ => unreachable!(),
        }
    }

    #[test]
    fn rejects_unknown_issuer() {
        let issuers = issuers_with(default_grants());
        let mut c = claims(json!(["Relay.Read"]));
        c["iss"] = json!("https://evil.example.com");
        assert_eq!(
            verify(&issuers, &sign(rsa_key(), &c)),
            Err(AuthError::UnknownIssuer)
        );
    }

    #[test]
    fn rejects_wrong_audience() {
        let issuers = issuers_with(default_grants());
        let mut c = claims(json!(["Relay.Read"]));
        c["aud"] = json!("someone-else");
        assert!(matches!(
            verify(&issuers, &sign(rsa_key(), &c)),
            Err(AuthError::InvalidAudience { .. })
        ));
    }

    #[test]
    fn accepts_audience_list_containing_ours() {
        let issuers = issuers_with(default_grants());
        let mut c = claims(json!(["Relay.Read"]));
        c["aud"] = json!(["other", AUDIENCE]);
        assert!(verify(&issuers, &sign(rsa_key(), &c)).is_ok());
    }

    #[test]
    fn rejects_missing_audience() {
        let issuers = issuers_with(default_grants());
        let mut c = claims(json!(["Relay.Read"]));
        c.as_object_mut().unwrap().remove("aud");
        assert_eq!(
            verify(&issuers, &sign(rsa_key(), &c)),
            Err(AuthError::InvalidClaims)
        );
    }

    #[test]
    fn rejects_expired() {
        let issuers = issuers_with(default_grants());
        let mut c = claims(json!(["Relay.Read"]));
        c["exp"] = json!(NOW_SECS - 61);
        assert_eq!(
            verify(&issuers, &sign(rsa_key(), &c)),
            Err(AuthError::Expired)
        );
        // Within the leeway it still passes.
        c["exp"] = json!(NOW_SECS - 59);
        assert!(verify(&issuers, &sign(rsa_key(), &c)).is_ok());
    }

    #[test]
    fn rejects_not_yet_valid() {
        let issuers = issuers_with(default_grants());
        let mut c = claims(json!(["Relay.Read"]));
        c["nbf"] = json!(NOW_SECS + 120);
        assert_eq!(
            verify(&issuers, &sign(rsa_key(), &c)),
            Err(AuthError::NotYetValid)
        );
    }

    #[test]
    fn rejects_unknown_kid_and_requests_one_refresh() {
        let issuers = issuers_with(default_grants());
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rotated".to_string());
        let token =
            jsonwebtoken::encode(&header, &claims(json!(["Relay.Read"])), &rsa_key().encoding)
                .unwrap();

        assert_eq!(verify(&issuers, &token), Err(AuthError::KeyMismatch));
        let first = issuers.issuers[0].last_fetch.lock().unwrap().unwrap();
        assert_eq!(verify(&issuers, &token), Err(AuthError::KeyMismatch));
        let second = issuers.issuers[0].last_fetch.lock().unwrap().unwrap();
        assert_eq!(first, second, "a second unknown kid must not refresh again");
    }

    #[test]
    fn rejects_hs256() {
        let issuers = issuers_with(default_grants());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(rsa_key().kid.to_string());
        let token = jsonwebtoken::encode(
            &header,
            &claims(json!(["Relay.Read"])),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        assert_eq!(
            verify(&issuers, &token),
            Err(AuthError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rejects_alg_none() {
        let issuers = issuers_with(default_grants());
        let header = b64_encode(br#"{"alg":"none","kid":"rsa-1"}"#);
        let payload = b64_encode(claims(json!(["Relay.Read"])).to_string().as_bytes());
        let token = format!("{}.{}.", header, payload);
        assert_eq!(detect_token_format(&token), TokenFormat::Jwt);
        assert_eq!(verify(&issuers, &token), Err(AuthError::InvalidToken));
    }

    #[test]
    fn rejects_key_of_the_wrong_type() {
        let issuers = issuers_with(default_grants());
        // An RS256 token naming the EC key.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(ec_key().kid.to_string());
        let token =
            jsonwebtoken::encode(&header, &claims(json!(["Relay.Read"])), &rsa_key().encoding)
                .unwrap();
        assert_eq!(
            verify(&issuers, &token),
            Err(AuthError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rejects_no_matching_grant() {
        let issuers = issuers_with(default_grants());
        let token = sign(rsa_key(), &claims(json!(["Something.Else"])));
        assert!(matches!(
            verify(&issuers, &token),
            Err(AuthError::InsufficientPermissions(_))
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let issuers = issuers_with(default_grants());
        let token = sign(rsa_key(), &claims(json!(["Relay.Read"])));
        let parts: Vec<&str> = token.split('.').collect();
        let forged = b64_encode(claims(json!(["Relay.Write"])).to_string().as_bytes());
        let tampered = format!("{}.{}.{}", parts[0], forged, parts[2]);
        assert_eq!(
            verify(&issuers, &tampered),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn grants_match_string_and_array_claims() {
        let issuers = issuers_with(vec![
            grant("roles", "Relay.Read", "prefix:a-:r"),
            grant("groups", "editors", "prefix:b-:rw"),
        ]);

        let mut c = claims(json!("Relay.Read"));
        c["groups"] = json!(["viewers", "editors"]);
        assert_eq!(
            prefixes(&verify(&issuers, &sign(rsa_key(), &c)).unwrap()),
            vec![
                ("a-".to_string(), Authorization::ReadOnly),
                ("b-".to_string(), Authorization::Full),
            ]
        );

        // A substring is not a match, nor is a non-string member.
        let mut c = claims(json!("Relay.ReadOnly"));
        c["groups"] = json!([["editors"], 1]);
        assert!(verify(&issuers, &sign(rsa_key(), &c)).is_err());
    }

    fn authenticator(grants: Vec<JwtGrantConfig>) -> Authenticator {
        let mut authenticator = Authenticator::gen_key().unwrap();
        authenticator.set_expected_audience(Some("https://relay.example.com".to_string()));
        authenticator.set_jwt_issuers(Arc::new(issuers_with(grants)));
        authenticator
    }

    #[test]
    fn server_grant_gives_admin_access() {
        let auth = authenticator(vec![
            grant("roles", "Relay.Write", "prefix:relay-1-:rw"),
            grant("roles", "Relay.Admin", "server"),
        ]);
        let token = sign(rsa_key(), &claims(json!(["Relay.Write", "Relay.Admin"])));

        // Server outranks a full prefix grant listed before it.
        assert_eq!(auth.verify_server_token(&token, NOW_MILLIS), Ok(()));
        assert_eq!(
            auth.verify_doc_token(&token, "any-doc", NOW_MILLIS),
            Ok(Authorization::Full)
        );

        // For a document the prefix grant covers, it is preferred, so the
        // user carries through.
        match auth
            .verify_token_for_doc(&token, "relay-1-doc", NOW_MILLIS)
            .unwrap()
            .0
        {
            Permission::Prefix(p) => assert_eq!(p.user.as_deref(), Some("user-123")),
            other => panic!("unexpected permission {:?}", other),
        }

        // Without the admin role, no server access.
        let writer = sign(rsa_key(), &claims(json!(["Relay.Write"])));
        assert_eq!(
            auth.verify_server_token(&writer, NOW_MILLIS),
            Err(AuthError::InvalidResource)
        );
    }

    #[test]
    fn strongest_grant_wins() {
        let auth = authenticator(default_grants());
        let token = sign(rsa_key(), &claims(json!(["Relay.Read", "Relay.Write"])));

        assert_eq!(
            auth.verify_doc_token(&token, "relay-1-doc", NOW_MILLIS),
            Ok(Authorization::Full)
        );
        assert_eq!(
            auth.verify_file_token_for_doc(&token, "relay-1-doc", NOW_MILLIS),
            Ok(Authorization::Full)
        );
        // With no document in hand, the most permissive grant stands for the token.
        match auth.verify_token_auto(&token, NOW_MILLIS).unwrap() {
            Permission::Prefix(p) => assert_eq!(p.authorization, Authorization::Full),
            other => panic!("unexpected permission {:?}", other),
        }
    }

    #[test]
    fn most_permissive_ties_go_to_the_first_grant() {
        let auth = authenticator(vec![
            grant("roles", "A", "prefix:a-:rw"),
            grant("roles", "B", "prefix:b-:rw"),
        ]);
        let token = sign(rsa_key(), &claims(json!(["B", "A"])));
        match auth.verify_token_auto(&token, NOW_MILLIS).unwrap() {
            Permission::Prefix(p) => assert_eq!(p.prefix, "a-"),
            other => panic!("unexpected permission {:?}", other),
        }
    }

    #[test]
    fn prefix_coverage() {
        let auth = authenticator(vec![
            grant("roles", "A", "prefix:a-:r"),
            grant("roles", "B", "prefix:b-:rw"),
        ]);
        let token = sign(rsa_key(), &claims(json!(["A", "B"])));

        assert_eq!(
            auth.verify_doc_token(&token, "a-doc", NOW_MILLIS),
            Ok(Authorization::ReadOnly)
        );
        assert_eq!(
            auth.verify_doc_token(&token, "b-doc", NOW_MILLIS),
            Ok(Authorization::Full)
        );
        assert_eq!(
            auth.verify_doc_token(&token, "c-doc", NOW_MILLIS),
            Err(AuthError::InvalidResource)
        );

        // The per-document check picks the grant that covers the document,
        // even when it isn't the first or the strongest.
        let (permission, channel) = auth
            .verify_token_for_doc(&token, "a-doc", NOW_MILLIS)
            .unwrap();
        assert_eq!(channel, None);
        match permission {
            Permission::Prefix(p) => {
                assert_eq!(p.prefix, "a-");
                assert_eq!(p.user.as_deref(), Some("user-123"));
            }
            other => panic!("unexpected permission {:?}", other),
        }

        assert_eq!(
            auth.extract_user_from_token(&token),
            Ok(Some("user-123".to_string()))
        );
    }

    #[test]
    fn jwt_rejected_when_no_issuers_configured() {
        let mut auth = Authenticator::gen_key().unwrap();
        auth.set_expected_audience(Some("https://relay.example.com".to_string()));
        let token = sign(rsa_key(), &claims(json!(["Relay.Read"])));
        assert_eq!(
            auth.verify_doc_token(&token, "relay-1-doc", NOW_MILLIS),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn relay_tokens_still_verify_alongside_issuers() {
        let auth = authenticator(default_grants());
        let token = auth
            .gen_doc_token_cwt(
                "doc-1",
                Authorization::Full,
                crate::auth::ExpirationTimeEpochMillis(NOW_MILLIS + 60_000),
                Some("cwt-user"),
                None,
            )
            .unwrap();
        assert_eq!(detect_token_format(&token), TokenFormat::Cwt);
        assert_eq!(
            auth.verify_doc_token(&token, "doc-1", NOW_MILLIS),
            Ok(Authorization::Full)
        );
    }

    #[test]
    fn detection() {
        let token = sign(rsa_key(), &claims(json!(["Relay.Read"])));
        assert_eq!(detect_token_format(&token), TokenFormat::Jwt);

        // Legacy `key_id.token` has a single dot and stays a custom token.
        let legacy = Authenticator::gen_key_legacy().unwrap();
        let legacy_token = legacy
            .gen_doc_token(
                "doc-1",
                Authorization::Full,
                crate::auth::ExpirationTimeEpochMillis::max(),
                None,
            )
            .unwrap();
        assert_eq!(detect_token_format(&legacy_token), TokenFormat::Custom);
        assert_eq!(
            detect_token_format(&format!("my_key.{}", legacy_token)),
            TokenFormat::Custom
        );

        // Three segments whose header isn't JSON with an `alg` are not a JWT.
        assert_ne!(detect_token_format("a.b.c"), TokenFormat::Jwt);
        let no_alg = format!("{}.e30.sig", b64_encode(br#"{"typ":"JWT"}"#));
        assert_ne!(detect_token_format(&no_alg), TokenFormat::Jwt);
    }

    #[test]
    fn config_refusals() {
        let refuse = |config: JwtIssuerConfig, needle: &str| {
            let err = JwtIssuers::from_config(&[config]).unwrap_err();
            assert!(
                err.contains(needle),
                "{:?} should mention {:?}",
                err,
                needle
            );
        };

        refuse(
            issuer_config(vec![grant("roles", "X", "prefix:missing-auth")]),
            "invalid grant scope",
        );
        refuse(issuer_config(vec![]), "at least one");

        let mut hs = issuer_config(default_grants());
        hs.algorithms = vec!["HS256".to_string()];
        refuse(hs, "symmetric");

        let mut none = issuer_config(default_grants());
        none.algorithms = vec!["none".to_string()];
        refuse(none, "unsupported algorithm");

        let mut no_audience = issuer_config(default_grants());
        no_audience.audience = OneOrMany::Many(vec![]);
        refuse(no_audience, "audience");

        let mut not_a_url = issuer_config(default_grants());
        not_a_url.issuer = "my-issuer".to_string();
        refuse(not_a_url, "jwks_uri must be set");

        let err = JwtIssuers::from_config(&[
            issuer_config(default_grants()),
            issuer_config(default_grants()),
        ])
        .unwrap_err();
        assert!(err.contains("Duplicate"));
    }

    #[test]
    fn jwks_skips_unusable_keys() {
        let keys = parse_jwks(&json!({ "keys": [
            rsa_key().jwk,
            { "kty": "oct", "kid": "hmac", "k": "c2VjcmV0" },
            { "kty": "RSA", "use": "enc", "kid": "enc",
              "n": rsa_key().jwk["n"], "e": rsa_key().jwk["e"] },
            { "kty": "RSA", "n": rsa_key().jwk["n"], "e": rsa_key().jwk["e"] },
            { "kty": "unknown", "kid": "weird" },
        ]}));
        assert_eq!(keys.keys().collect::<Vec<_>>(), vec!["rsa-1"]);
    }

    /// Serve fixed responses by path over plain HTTP/1.1. `routes` receives
    /// the server's base URL, so a response can name another route.
    async fn serve(routes: impl FnOnce(&str) -> Vec<(&'static str, u16, String)>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let routes = routes(&base);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = routes
                    .iter()
                    .find(|(p, _, _)| *p == path)
                    .map(|(_, s, b)| (*s, b.clone()))
                    .unwrap_or((404, String::new()));
                let response = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        base
    }

    #[tokio::test]
    async fn fetcher_reads_discovery_then_jwks() {
        let base = serve(|base| {
            vec![
                (
                    "/tenant/.well-known/openid-configuration",
                    200,
                    json!({ "issuer": format!("{}/tenant", base),
                            "jwks_uri": format!("{}/keys", base) })
                    .to_string(),
                ),
                ("/keys", 200, json!({ "keys": [rsa_key().jwk] }).to_string()),
            ]
        })
        .await;

        let issuer = format!("{}/tenant/", base);
        let mut config = issuer_config(default_grants());
        config.issuer = issuer.clone();
        let issuers = JwtIssuers::from_config(&[config]).unwrap();
        let client = reqwest::Client::new();

        assert_eq!(issuers.refresh(&issuer, &client).await, Ok(1));

        let mut c = claims(json!(["Relay.Read"]));
        c["iss"] = json!(issuer);
        assert!(issuers
            .verify(&sign(rsa_key(), &c), Some(NOW_MILLIS))
            .is_ok());
    }

    #[tokio::test]
    async fn failed_refresh_keeps_existing_keys() {
        let base = serve(|_| vec![("/keys", 500, String::new())]).await;
        let mut config = issuer_config(default_grants());
        config.jwks_uri = Some(format!("{}/keys", base));
        let issuers = JwtIssuers::from_config(&[config]).unwrap();
        issuers
            .set_keys(ISSUER, &json!({ "keys": [rsa_key().jwk] }))
            .unwrap();

        let client = reqwest::Client::new();
        assert!(issuers.refresh(ISSUER, &client).await.is_err());

        let token = sign(rsa_key(), &claims(json!(["Relay.Read"])));
        assert!(verify(&issuers, &token).is_ok());
    }

    #[tokio::test]
    async fn empty_jwks_keeps_existing_keys() {
        let base = serve(|_| vec![("/keys", 200, json!({ "keys": [] }).to_string())]).await;
        let mut config = issuer_config(default_grants());
        config.jwks_uri = Some(format!("{}/keys", base));
        let issuers = JwtIssuers::from_config(&[config]).unwrap();
        issuers
            .set_keys(ISSUER, &json!({ "keys": [rsa_key().jwk] }))
            .unwrap();

        let client = reqwest::Client::new();
        assert!(issuers.refresh(ISSUER, &client).await.is_err());
        let token = sign(rsa_key(), &claims(json!(["Relay.Read"])));
        assert!(verify(&issuers, &token).is_ok());
    }
}
