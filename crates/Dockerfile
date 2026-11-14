# syntax=docker/dockerfile:1.7
FROM rust:1.89-slim-trixie AS builder

WORKDIR /build

ARG RELAY_VERSION
ARG TARGETARCH
ENV RELAY_VERSION=${RELAY_VERSION}

COPY . .
RUN --mount=type=cache,id=relay-public-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=relay-public-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=relay-public-target-rust1.89-release-${TARGETARCH},target=/build/target,sharing=locked \
    cargo build --release --locked --package relay && \
    install -Dm755 /build/target/release/relay /out/relay

FROM debian:trixie-slim

RUN mkdir -p /app/data

WORKDIR /app

# Add tailscale
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY --from=docker.io/tailscale/tailscale:stable /usr/local/bin/tailscale /usr/local/bin/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale
# Take the security updates published since the base image was built.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Add relay binary
COPY --from=builder /out/relay /app/relay
COPY ./run.sh /app/run.sh
COPY ./relay.toml /app/relay.toml
RUN chmod +x /app/run.sh

ENTRYPOINT ["./run.sh"]
