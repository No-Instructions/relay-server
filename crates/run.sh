#!/bin/bash
set -e  # Exit on error

# Handle signals properly
trap "exit" TERM INT

# Check if URL is provided as first argument
if [ -n "$1" ]; then
    echo "🔗 Using URL from argument: $1"
fi

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
./relay config validate
if [ -n "$1" ]; then
    exec ./relay serve --host=0.0.0.0 --url="$1"
else
    exec ./relay serve --host=0.0.0.0
fi
