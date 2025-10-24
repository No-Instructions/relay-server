FROM rust:1.89-slim-trixie AS builder

WORKDIR /build

COPY . .
RUN cargo build --release

FROM debian:trixie-slim

# Write to disk by default
ENV YSWEET_STORE="data"

# Add relay binary
COPY --from=builder /build/target/release/relay /usr/local/bin/relay

# Add tailscale
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscale /usr/local/bin/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
RUN apt-get update && apt-get install -y ca-certificates

COPY ./run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
