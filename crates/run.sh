#!/bin/bash
set -e  # Exit on error

# Handle signals properly
trap "exit" TERM INT

# Backwards compatibility for deprecated Y_SWEET_ variables
use_legacy_var() {
    local new_var=$1
    local old_var=$2
    if [ -z "$(eval echo \$$new_var)" ] && [ -n "$(eval echo \$$old_var)" ]; then
        echo "⚠️  $old_var is deprecated. Please use $new_var" >&2
        eval export $new_var="\$$old_var"
    fi
}

use_legacy_var RELAY_SERVER_URL Y_SWEET_URL_PREFIX
use_legacy_var RELAY_SERVER_STORAGE Y_SWEET_STORE
use_legacy_var RELAY_SERVER_AUTH Y_SWEET_AUTH

# If RELAY_SERVER_URL is not set but FLY_APP_NAME is, construct the URL
if [ -z "$RELAY_SERVER_URL" ] && [ -n "$FLY_APP_NAME" ]; then
    export RELAY_SERVER_URL="https://$FLY_APP_NAME.fly.dev"
    echo "🪽  Running on fly.io. Setting --url-prefix=$RELAY_SERVER_URL"
fi

# RELAY_SERVER_STORAGE is required
if [ -z "$RELAY_SERVER_STORAGE" ]; then
    echo "RELAY_SERVER_STORAGE environment variable is required" >&2
    exit 1
fi
echo "💾 Persisting data to $RELAY_SERVER_STORAGE"

if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "🔑 Joining tailnet..."
    if [ -n "$TAILSCALE_USERSPACE_NETWORKING" ]; then
        tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    else
        tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    fi
    tailscale up --auth-key=${TAILSCALE_AUTHKEY} --hostname=relay-server
    if [ -n "$TAILSCALE_SERVE" ]; then
        tailscale serve --bg localhost:8080
    fi
fi
echo "🛰️  Starting Relay Server..."
exec relay serve --host=0.0.0.0
