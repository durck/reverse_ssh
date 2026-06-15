#!/bin/bash
set -euo pipefail

if [ ! -d "/data" ]; then
    echo "Please mount /data"
    exit 1
fi

if [ -z "${EXTERNAL_ADDRESS:-}" ]; then
    echo "Please specify EXTERNAL_ADDRESS"
    exit 1
fi

touch /data/authorized_keys /data/authorized_controllee_keys

# Allow user to seed the authorized_keys file
if [ -n "${SEED_AUTHORIZED_KEYS:-}" ]; then
    if [ -s /data/authorized_keys ]; then
        echo "authorized_keys is not empty, ignoring SEED_AUTHORIZED_KEYS"
    else
        echo "Seeding authorized_keys..."
        printf '%s\n' "$SEED_AUTHORIZED_KEYS" > /data/authorized_keys
    fi
fi

cd /app/bin

server_args=(
    --datadir /data
    --enable-client-downloads
    --tls
    --external_address "$EXTERNAL_ADDRESS"
)

if [ -n "${RSSH_WS_PATH:-}" ]; then
    server_args+=(--ws-path "$RSSH_WS_PATH")
fi

if [ -n "${RSSH_PUSH_PATH:-}" ]; then
    server_args+=(--push-path "$RSSH_PUSH_PATH")
fi

if [ -n "${RSSH_TRUSTED_PROXY_CIDR:-}" ]; then
    server_args+=(--trusted-proxy-cidr "$RSSH_TRUSTED_PROXY_CIDR")
fi

server_args+=(:2222)

exec ./server "${server_args[@]}"
