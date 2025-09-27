# Y-Sweet Legacy Token Signing - Byte-Level Specification

This document provides a complete byte-level specification for implementing the legacy token signing algorithm used in Y-Sweet, suitable for implementation in Go or any other programming language.

## Overview

The Y-Sweet legacy token format uses a custom signing mechanism based on SHA256 hashing, bincode serialization, and a custom Base64 encoding scheme. The token structure embeds both the payload data and the signature in a single encoded string.

## Token Structure

```
[optional_key_id].[base64_encoded_authenticated_request]
```

Where:
- `optional_key_id`: If present, separated by a dot (`.`) 
- `base64_encoded_authenticated_request`: The main token data

## Core Data Structures

### 1. Permission Types

The system supports four permission types:

```rust
enum Permission {
    Server,
    Doc(DocPermission),
    File(FilePermission), 
    Prefix(PrefixPermission),
}
```

#### DocPermission
```rust
struct DocPermission {
    doc_id: String,
    authorization: Authorization,
    user: Option<String>,
}
```

#### FilePermission
```rust
struct FilePermission {
    file_hash: String,
    authorization: Authorization,
    content_type: Option<String>,
    content_length: Option<u64>,
    doc_id: String,
    user: Option<String>,
}
```

#### PrefixPermission  
```rust
struct PrefixPermission {
    prefix: String,
    authorization: Authorization,
    user: Option<String>,
}
```

#### Authorization
```rust
enum Authorization {
    ReadOnly = 0,
    Full = 1,
}
```

### 2. Core Structures

#### Payload
```rust
struct Payload {
    payload: Permission,
    expiration_millis: Option<ExpirationTimeEpochMillis>,
}
```

#### AuthenticatedRequest
```rust
struct AuthenticatedRequest {
    payload: Payload,
    token: Vec<u8>,  // 32-byte SHA256 hash
}
```

#### ExpirationTimeEpochMillis
```rust
struct ExpirationTimeEpochMillis(u64);  // Milliseconds since Unix epoch
```

## Token Generation Algorithm

### Step 1: Create Payload
Create a `Payload` struct containing the permission and optional expiration time.

### Step 2: Serialize Payload
Serialize the payload using bincode with default options:
```rust
let payload_bytes = bincode::DefaultOptions::new().serialize(&payload)?;
```

### Step 3: Create Hash Input
Concatenate the serialized payload with the private key:
```rust
let mut hash_input = payload_bytes;
hash_input.extend_from_slice(&private_key);
```

### Step 4: Generate Token Hash
Generate SHA256 hash of the concatenated data:
```rust
let token_hash = SHA256(hash_input);
```

### Step 5: Create AuthenticatedRequest
```rust
let auth_req = AuthenticatedRequest {
    payload: payload,
    token: token_hash,
};
```

### Step 6: Serialize AuthenticatedRequest
```rust
let auth_req_bytes = bincode::DefaultOptions::new().serialize(&auth_req)?;
```

### Step 7: Base64 Encode
Encode using the custom Base64 encoding scheme:
```rust
let token_string = custom_base64_encode(auth_req_bytes);
```

### Step 8: Add Key ID (Optional)
If a key ID is configured:
```rust
let final_token = format!("{}.{}", key_id, token_string);
```

## Token Verification Algorithm

### Step 1: Parse Key ID
If token contains a dot (`.`), split on the first dot:
```rust
let (key_id, token_data) = token.split_once('.').unwrap_or(("", token));
```

### Step 2: Base64 Decode
```rust
let decoded_bytes = custom_base64_decode(token_data)?;
```

### Step 3: Deserialize AuthenticatedRequest
```rust
let auth_req: AuthenticatedRequest = bincode::DefaultOptions::new().deserialize(&decoded_bytes)?;
```

### Step 4: Recreate Hash Input
```rust
let payload_bytes = bincode::DefaultOptions::new().serialize(&auth_req.payload)?;
let mut hash_input = payload_bytes;
hash_input.extend_from_slice(&private_key);
```

### Step 5: Verify Signature
```rust
let expected_hash = SHA256(hash_input);
if expected_hash != auth_req.token {
    return Err("Invalid signature");
}
```

### Step 6: Check Expiration
```rust
if let Some(exp) = auth_req.payload.expiration_millis {
    if exp.0 < current_time_millis {
        return Err("Token expired");
    }
}
```

## Custom Base64 Encoding

The system uses a custom Base64 encoding scheme that is URL-safe and supports both encoding formats for compatibility:

### Encoding
- Uses URL-safe alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`
- No padding characters in output
- Equivalent to standard `BASE64URL_NOPAD`

### Decoding (Flexible)
The decoder accepts multiple formats for backward compatibility:
- Standard Base64: `+/` characters with optional `=` padding
- URL-safe Base64: `-_` characters with optional `=` padding  
- Mixed formats are supported

### Implementation Reference
```rust
const BASE64_CUSTOM: Encoding = /* custom encoding table */;

fn b64_encode(bytes: &[u8]) -> String {
    BASE64_CUSTOM.encode(bytes)
}

fn b64_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    BASE64_CUSTOM.decode(input.as_bytes()).map_err(|_| AuthError::InvalidToken)
}
```

## Bincode Serialization Details

### Configuration
Uses `bincode::DefaultOptions::new()` which provides:
- Little-endian byte order
- Variable-length integer encoding
- No size limits
- Fixed-length array encoding

### Key Serialization Behaviors
- `String`: Length prefix (u64) + UTF-8 bytes
- `Option<T>`: 1 byte tag (0=None, 1=Some) + value if Some
- `Vec<u8>`: Length prefix (u64) + raw bytes
- `u64`: 8 bytes little-endian
- Enums: Variant index (u32) + variant data

## Legacy Compatibility

The system maintains backward compatibility with older token formats through legacy structures:

### LegacyDocPermission
```rust
struct LegacyDocPermission {
    doc_id: String,
    authorization: Authorization,
    // Note: No user field
}
```

### LegacyFilePermission
```rust
struct LegacyFilePermission {
    file_hash: String,
    authorization: Authorization,
    content_type: Option<String>,
    content_length: Option<u64>,
    doc_id: String,
    // Note: No user field
}
```

### LegacyPermission
```rust
enum LegacyPermission {
    Server,
    Doc(LegacyDocPermission),
    File(LegacyFilePermission),
    // Note: No Prefix variant
}
```

During verification, if the current format fails to deserialize, the system attempts to deserialize as legacy format and converts to current format (setting `user: None`).

## Error Handling

### Error Types
- `InvalidToken`: Base64 decoding failed or malformed structure
- `InvalidSignature`: Hash verification failed
- `Expired`: Token expiration time has passed
- `KeyMismatch`: Provided key ID doesn't match expected key ID
- `InvalidResource`: Token permission doesn't match requested resource

## Security Considerations

### Private Key Requirements
- Recommended: 32-byte (256-bit) cryptographically secure random key
- Minimum: 16 bytes
- Must be kept secret and used consistently for signing/verification

### Hash Function
- Uses SHA256 for cryptographic security
- Hash input includes both payload and private key to prevent tampering

### Timing Attacks
- Use constant-time comparison for hash verification
- Validate expiration after signature verification

## Example Implementation Outline (Go)

```go
type Permission struct {
    Type string `json:"type"` // "server", "doc", "file", "prefix"
    // Additional fields based on type
}

type Payload struct {
    Payload          Permission `bincode:"payload"`
    ExpirationMillis *uint64    `bincode:"expiration_millis"`
}

type AuthenticatedRequest struct {
    Payload Payload `bincode:"payload"`
    Token   []byte  `bincode:"token"`
}

func SignToken(payload Payload, privateKey []byte) (string, error) {
    // 1. Serialize payload with bincode
    payloadBytes, err := bincode.Marshal(payload)
    if err != nil {
        return "", err
    }
    
    // 2. Create hash input (payload + private key)
    hashInput := append(payloadBytes, privateKey...)
    
    // 3. Generate SHA256 hash
    hash := sha256.Sum256(hashInput)
    
    // 4. Create authenticated request
    authReq := AuthenticatedRequest{
        Payload: payload,
        Token:   hash[:],
    }
    
    // 5. Serialize authenticated request
    authReqBytes, err := bincode.Marshal(authReq)
    if err != nil {
        return "", err
    }
    
    // 6. Base64 encode
    return customBase64Encode(authReqBytes), nil
}

func VerifyToken(token string, privateKey []byte, currentTimeMillis uint64) (*Payload, error) {
    // Implementation follows verification algorithm above
}
```

## Test Vectors

For validation, implementers should test against tokens generated by the reference Rust implementation with known private keys and payloads.

## Notes for Go Implementation

1. **Bincode Compatibility**: Use a Go bincode library that matches Rust's `bincode::DefaultOptions::new()` behavior
2. **SHA256**: Use `crypto/sha256` from Go standard library
3. **Base64**: Implement the custom encoding scheme or adapt existing Base64 libraries
4. **Endianness**: Ensure little-endian serialization for numeric types
5. **Error Handling**: Implement all error types for proper compatibility
6. **Testing**: Generate test tokens with the Rust implementation to validate your Go implementation

This specification provides all the information needed to implement a fully compatible Y-Sweet legacy token signing system in Go or any other programming language.