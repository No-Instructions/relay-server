# Architecture Change Request: JWT Issuer Authentication

## Problem Statement

Relay accepts only tokens it can verify with its own `[[auth]]` keys: legacy
tokens and CWTs. A deployment that already has an identity provider (any
OpenID Connect issuer, such as Entra ID, Auth0, Keycloak or Okta) has to run a
separate service that turns the provider's tokens into Relay tokens, and keep
that service's signing key in step with Relay's.

Most identity providers already issue signed JWTs and publish their public
keys as a JWKS. If Relay can verify those JWTs itself, and map their claims
(roles, groups) to Relay scopes, the extra service is not needed.

## Proposed Solution

Relay keeps its own tokens unchanged. In addition, it accepts JWTs from
issuers named in `relay.toml`, and maps each JWT's claims to Relay's existing
scopes through rules in the same file.

## Configuration

```toml
[[jwt_issuer]]
issuer = "https://login.example.com/tenant/v2.0"  # must equal the token's `iss`
audience = "relay-client-id"        # string or list; the token's `aud` must contain one
# jwks_uri = "https://..."          # default: discovery at <issuer>/.well-known/openid-configuration
# user_claim = "sub"                # claim used as the Relay user id
# algorithms = ["RS256", "ES256"]   # HS* and "none" are refused
# leeway_seconds = 60               # clock skew allowed for exp and nbf
# jwks_refresh_seconds = 3600       # how often to refetch the keys

[[jwt_issuer.grant]]
claim = "roles"                     # a top-level claim: a string or an array of strings
contains = "Relay.Read"             # matches an equal string or an array member
scope = "prefix:<relay-id>-:r"      # any Relay scope; "server" gives full admin access

[[jwt_issuer.grant]]
claim = "roles"
contains = "Relay.Write"
scope = "prefix:<relay-id>-:rw"
```

Rules checked at startup (a failure stops the server):

- Each `issuer` is unique. Issuers are matched by exact `iss`.
- `audience` is not empty.
- `jwks_uri`, when given, is a URL. Without it, `issuer` must be a URL so that
  discovery can be used.
- Every algorithm is one `jsonwebtoken` supports and is asymmetric (RS*, PS*,
  ES256, ES384, EdDSA). HS* and `none` are refused.
- There is at least one grant, and each scope parses with the scope parser
  that CWTs use (`server`, `doc:`, `file:`, `prefix:`).
- At least one `[[auth]]` key is configured. Without one Relay runs with
  authentication disabled, and a JWT would never be checked.

**A `server` grant gives the JWT full admin access**, the same as a Relay
server token: every document and file, document creation, and the admin
endpoints. Write one only deliberately, and match it on a claim that only
administrators carry. To keep JWTs away from the admin endpoints, don't write
one.

## Verification

### Detection

`detect_token_format` returns `TokenFormat::Jwt` for three base64url segments
joined by two dots, where the first is a JSON object with a string `alg`.
Relay's own tokens are base64 without dots, and the legacy `key_id.token` form
has one dot, so the formats don't collide.

### Steps

1. Read `iss` from the payload without verifying it, and select the issuer
   block with that exact `iss`. An unknown issuer is rejected
   (`UnknownIssuer`).
2. Check the header's `alg` is in the issuer's `algorithms`.
3. Select the key by the header's `kid` from the issuer's key cache. A token
   with no `kid`, or an unknown `kid`, is rejected (`KeyMismatch`). The key's
   type must match `alg`.
4. Verify the signature with `jsonwebtoken`, which also checks `iss` and that
   `aud` contains one of `audience`. `exp`, `iss` and `aud` are required.
5. Check `exp` and, when present, `nbf` against the caller's clock, with
   `leeway_seconds` either way (`Expired`, `NotYetValid`).
6. Collect every grant whose claim matches. No match is rejected
   (`InsufficientPermissions`).

The value of `user_claim`, when it is a string, becomes the `user` of each
resulting permission, so attribution and logging see JWT users as they see CWT
subjects.

The JWT path checks `aud` against the issuer's `audience`, not against
`server.url` as CWTs do.

### Several matching grants

A Relay token carries one scope; a JWT can match several grants.

- Where a check names a document or file (`verify_doc_token`,
  `verify_file_token`, `verify_file_token_for_doc`, the websocket upgrade, and
  document creation with a `docId`), the request is allowed if any matching
  grant covers it, and the strongest authorization wins (`rw` over `r`).
  `Authenticator::verify_token_for_doc` returns that grant for callers that
  match on the permission themselves.
  There, a grant naming the document is preferred over a `server` grant of
  equal strength, because a server permission carries no user.
- Where a check returns a single `Permission` with no document in hand
  (`verify_token_auto`, `verify_token_with_channel`, `verify_server_token`),
  it returns the most permissive matching grant (`server`, then `rw`, then
  `r`), the first in file order on a tie.

JWTs carry no channel claim, so their requests take the channel-less routing
path.

## JWKS Cache

Verification is synchronous, so each issuer's keys live in a shared cache that
a background task fills (`JwtIssuers::refresh_tasks`, spawned by `main`):

- Keys are fetched at startup. A failure is logged and retried with backoff
  (5 s doubling to 5 min); it doesn't stop the server. Tokens from that issuer
  fail until keys load.
- Keys are refetched every `jwks_refresh_seconds`.
- A token naming an unknown `kid` wakes the task early, at most once per
  5 minutes per issuer, so a rotated key is picked up without letting such
  tokens drive requests to the issuer.
- A failed refetch, or one that returns no usable keys, keeps the existing
  keys.
- Only asymmetric signing keys with a `kid` are kept. Symmetric (`oct`) keys,
  keys marked for encryption, and unparseable entries are skipped.

## Failure Modes

| Situation | Result |
| --- | --- |
| `iss` not configured | `UnknownIssuer` |
| `alg` not allowed, `none`, or wrong key type | `UnsupportedAlgorithm` (or `InvalidToken` for `none`, which doesn't parse) |
| No `kid`, or `kid` not in the cache | `KeyMismatch`; may trigger an early refresh |
| Bad signature | `InvalidSignature` |
| `aud` doesn't match | `InvalidAudience` |
| `exp`, `iss` or `aud` missing | `InvalidClaims` |
| Past `exp` + leeway | `Expired` |
| Before `nbf` - leeway | `NotYetValid` |
| No grant matches | `InsufficientPermissions` |
| JWT presented with no `[[jwt_issuer]]` configured | `InvalidToken` |
| Issuer unreachable at startup | Logged and retried; that issuer's tokens fail until keys load |

Each rejection is logged at `info` with the issuer and reason. The token is
never logged.

An open websocket is not closed when its JWT's `exp` passes. The same is true
of CWTs today: the socket reads its expiry only from legacy tokens.

## Unchanged When Unconfigured

With no `[[jwt_issuer]]` blocks, nothing changes: no background task runs, no
outbound requests are made, and a JWT-shaped token is rejected as
`InvalidToken`. Legacy and CWT verification are untouched in either case.

## Implementation Location

- `y-sweet-core/src/jwt.rs`: `JwtIssuers` (config validation, verification,
  key cache and refresh tasks).
- `y-sweet-core/src/config.rs`: `JwtIssuerConfig`, `JwtGrantConfig`, startup
  validation.
- `y-sweet-core/src/auth.rs`: `TokenFormat::Jwt`, multi-grant handling in the
  `verify_*` methods, `verify_token_for_doc`.
- `relay/src/main.rs`: builds the issuers and spawns their refresh tasks.
- `relay/src/server.rs`: the websocket upgrade and document creation use
  `verify_token_for_doc`.

## Testing

- Unit tests in `jwt.rs` with RSA and P-256 keys generated in the test and a
  JWKS injected into the cache: valid tokens, each rejection above, grant
  matching on string and array claims, strongest-grant choice, prefix
  coverage, detection alongside legacy and CWT tokens, config refusals, and
  the fetcher reading discovery and `jwks_uri` from a local HTTP server.
- `relay/tests/jwt_issuer_integration_test.rs`: a JWT opens a document
  websocket within its prefix and is refused (403) outside it.
