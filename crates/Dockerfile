FROM rust:1.89-slim-trixie AS builder

WORKDIR /build

COPY . .
RUN cargo build --release

FROM debian:trixie-slim

RUN mkdir -p /app/data

WORKDIR /app

# Add tailscale
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscale /usr/local/bin/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
RUN apt-get update && apt-get install -y ca-certificates

# Add relay binary
COPY --from=builder /build/target/release/relay /app/relay
COPY ./run.sh /app/run.sh
COPY ./relay.toml /app/relay.toml
RUN chmod +x /app/run.sh

ENTRYPOINT ["./run.sh"]
