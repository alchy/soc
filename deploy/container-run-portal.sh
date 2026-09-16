#!/usr/bin/env bash
# Spustí soc-portal v kontejneru (rootless podman), stejný styl jako soc-api.
# Klíčový rozdíl: vault je montovaný READ-ONLY — portál do něj nikdy nezapíše.
set -euo pipefail

NAME="soc-portal"
IMAGE="${SOC_PORTAL_IMAGE:-soc-portal:latest}"
VAULT="${SOC_VAULT_HOST:-$HOME/vault}"
BIND="${SOC_PORTAL_BIND_ADDR:-127.0.0.1}"
PORT="${SOC_PORTAL_PORT:-8096}"

[ -d "$VAULT" ] || { echo "vault neexistuje: $VAULT" >&2; exit 1; }
: "${SOC_PORTAL_SESSION_SECRET:?nastav SOC_PORTAL_SESSION_SECRET (>=16 znaku)}"

podman rm -f "$NAME" >/dev/null 2>&1 || true

# POZOR SELinux (EL10): sdílený vault mezi soc-api a soc-portal potřebuje MALÉ 'z'
# (sdílený label). soc-api dnes používá velké 'Z' (privátní) — sjednoť oba na 'z',
# jinak portál dostane "permission denied" i s ':ro'.
exec podman run -d --name "$NAME" \
    --publish "$BIND:$PORT:8096" \
    --volume "$VAULT:/vault:ro,z,nosuid,nodev,noexec" \
    --env SOC_PORTAL_VAULT=/vault \
    --env SOC_PORTAL_BIND_HOST=0.0.0.0 \
    --env SOC_PORTAL_BIND_PORT=8096 \
    --env SOC_PORTAL_AUTH_BACKEND="${SOC_PORTAL_AUTH_BACKEND:-access_manager}" \
    --env SOC_PORTAL_AM_URL="${SOC_PORTAL_AM_URL:-http://169.254.1.2:22000}" \
    --env SOC_PORTAL_AM_KEY="${SOC_PORTAL_AM_KEY:?nastav klic aplikace portalu}" \
    --env SOC_PORTAL_REALM="${SOC_PORTAL_REALM:-soc.autumnpartials.com}" \
    --env SOC_PORTAL_REQUIRED_GROUP="${SOC_PORTAL_REQUIRED_GROUP:-users}" \
    --env SOC_PORTAL_SESSION_SECRET="$SOC_PORTAL_SESSION_SECRET" \
    --env SOC_PORTAL_SESSION_SECURE=1 \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    "$IMAGE"
