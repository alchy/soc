#!/bin/sh
# Vstupni bod portaloveho kontejneru.
#
# Konfigurace jde promennymi prostredi (viz soc_portal/config.py). Vychozi
# hodnoty UVNITR kontejneru se lisi od nativniho behu: cesty jsou kontejnerove
# a naslouchat je treba na 0.0.0.0, jinak publikovany port nevede nikam.
set -eu

# Cokoli za prikazem se spusti misto sluzby - pro ladeni (`podman run ... sh`).
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# Vault je pripojny bod READ-ONLY, ne hostitelska cesta.
export SOC_PORTAL_VAULT="${SOC_PORTAL_VAULT:-/vault}"

# 0.0.0.0 je ZAMER: na 127.0.0.1 by se poslouchalo na smycce KONTEJNERU a
# publikovany port by nevedl nikam. Ven vede jen to, co podman publikuje.
export SOC_PORTAL_BIND_HOST="${SOC_PORTAL_BIND_HOST:-0.0.0.0}"
export SOC_PORTAL_BIND_PORT="${SOC_PORTAL_BIND_PORT:-8096}"

# Access-manager bezi na smycce hostitele, kam kontejner primo nedosahne.
# Prekladovou adresu zaridi pasta (--map-host-loopback), viz soc-portal-container.
export SOC_PORTAL_AM_URL="${SOC_PORTAL_AM_URL:-http://169.254.1.2:22000}"

# Origin ACL: adresa, kterou portal posila AM v X-Forwarded-For. MUSI byt
# v ACL klice (k5), jinak AM vraci 403 forbidden. V kontejneru je jina nez
# 127.0.0.1 - nastavuje ji wrapper (soc-portal-container) z adresy hostitele.
if [ -z "${SOC_PORTAL_AM_CALL_ORIGIN:-}" ]; then
    echo "POZOR: SOC_PORTAL_AM_CALL_ORIGIN neni nastaveno - AM muze vratit 403 forbidden." >&2
fi

# Tvrde chybejici tajemstvi chytne az config.validate() v __main__ (fail-fast),
# ale radeji varujeme uz tady s jasnym jmenem promenne.
[ -n "${SOC_PORTAL_AM_KEY:-}" ] || echo "POZOR: SOC_PORTAL_AM_KEY neni nastaveno." >&2
[ -n "${SOC_PORTAL_SESSION_SECRET:-}" ] || echo "POZOR: SOC_PORTAL_SESSION_SECRET neni nastaveno." >&2

exec python -m soc_portal
