# Relay Server

[Relay](https://relay.md) adds real-time collaboration to Obsidian. Share exactly the folders you want, keep the rest of your vault private, and work together even when offline. The server in this repository powers that experience.

Relay Server is a fork of [jamsocket/y-sweet](https://github.com/jamsocket/y-sweet). It exposes the same CRDT-based document store under a new name and integrates with Relay's Control Plane for authentication and permissions.

## Features

 - Real‑time collaboration engine built atop y-crdt, enabling high-performance conflict‑free shared editing
 - Use the Relay.md control plane for login and access control management
 - Fully private self-hosting of your documents and attachments (no connection to the public internet required!)
 - 1-step deployment into your Tailscale Tailnet
 - Persistence to S3‑compatible object storage (S3, Cloudflare R2, Minio)
 - Flexible deployment/isolation with single server or session‑per‑document model
 - Python SDK
 - Webhook Event Delivery

## Configuration

Configuration can be provided via a relay.toml file, or via environment variables.

```toml
# relay.toml
[server]
url = "https://relay.example.com"
host = "0.0.0.0"
port = 8080

# Relay.md public keys
[[auth]]
key_id = "relay_2025_10_22"
public_key = "/6OgBTHaRdWLogewMdyE+7AxnI0/HP3WGqRs/bYBlFg="

[[auth]]
key_id = "relay_2025_10_23"
public_key = "fbm9JLHrwPpST5HAYORTQR/i1VbZ1kdp2ZEy0XpMbf0="

# Document and attachment persistence
# Supports S3-compatible storage
[store]
type = "aws"
bucket = "my-bucket"
region = "us-east-1"
access_key_id = "AKIA..."        # or set AWS_ACCESS_KEY_ID
secret_access_key = "secret..."  # or set AWS_SECRET_ACCESS_KEY
prefix = ""
```

## Self-hosting

> :information_source: **Note:** The Relay Server and Relay Obsidian Plugin are open source, but the Relay Control Plane is not open source. Using a Self-Hosted Relay Server with more than 3 collaborators requires a paid license to support the development of Relay.


Self-hosting gives you complete privacy for your notes and attachments. Relay's Control Plane handles login and permissions, but cannot read your content. The recommended setup uses Docker with Cloudflare R2 for persistence.

See [relay-server-template](https://github.com/no-instructions/relay-server-template) for detailed hosting instructions and deployment templates.


## Contact

- Discord: [https://discord.system3.md](https://discord.system3.md)
- Email: contact@system3.md


## Acknowledgements

Relay Server builds on [y-sweet](https://github.com/jamsocket/y-sweet) by the folks at Jamsocket, which in turn uses [y-crdt](https://github.com/y-crdt/y-crdt).

The server source code is MIT licensed.
