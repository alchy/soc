#!/bin/sh
# Vstupni bod kontejneru.
#
# Konfigurace jde promennymi prostredi (viz soc_api/config.py), takze se sem
# nic nemontuje krome vaultu. Vychozi hodnoty uvnitr kontejneru se ale lisi
# od nativniho behu - cesty jsou cesty UVNITR kontejneru a naslouchat je
# potreba na 0.0.0.0, jinak by publikovane porty nevedly nikam.
set -eu

# Cokoli za prikazem se spusti misto sluzby - pro ladeni (`podman run ... sh`).
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# Vault je pripojny bod, ne hostitelska cesta. Kdo sem propasiruje
# /www/soc/vault, dostane PermissionError na /www.
export SOC_VAULT="${SOC_VAULT:-/var/lib/soc/vault}"

# 0.0.0.0 je tu ZAMER: na 127.0.0.1 by se poslouchalo na smycce KONTEJNERU
# a publikovany port by nevedl nikam. Ven z kontejneru vede jen to, co
# podman publikuje - a to je 127.0.0.1 hostitele.
export SOC_BIND_HOST="${SOC_BIND_HOST:-0.0.0.0}"
export SOC_BIND_PORT="${SOC_BIND_PORT:-8095}"

# Kam Python odklada docasne soubory. Werkzeug pri multipartu spooluje telo
# pozadavku prave sem - a /tmp je tmpfs o par desitkach MB, takze 50MB vzorek
# ho pretece a pozadavek skonci na "No space left on device" (HTTP 500),
# i kdyz na disku je mista dost. TMPDIR proto miri do namontovaneho vaultu,
# kde je misto a kde to skaluje se `SOC_MAX_UPLOAD`.
#
# Adresar zacina teckou, takze ho vypis vzorku prehlizi.
export TMPDIR="${TMPDIR:-$SOC_VAULT/.tmp}"
mkdir -p "$TMPDIR"

# Po tvrdem padu (OOM, kill -9) tu zustanou rozdelane soubory. Sluzba je uz
# nikdy nedokonci a nikdo je neuklidi, takze by tise ubiraly misto ve vaultu.
# Start je jedine misto, kde se da bezpecne rict, ze uz nikomu nepatri.
find "$TMPDIR" -mindepth 1 -delete 2>/dev/null || true

# Totez pro nedokoncene prijmy - `storage.receive` zaklada docasny soubor
# primo ve vaultu, aby se dal presunout bez kopirovani pres hranici svazku.
find "$SOC_VAULT" -maxdepth 1 -name ".incoming-*" -delete 2>/dev/null || true

# Access-manager bezi na hostiteli a publikuje jen na jeho smycce, kam
# kontejner primo nedosahne. Prekladovou adresu zaridi pasta
# (--map-host-loopback), viz deploy/container-run.sh.
export SOC_AM_URL="${SOC_AM_URL:-http://169.254.1.2:22000}"

# Komu se veri X-Real-IP. Tahle hlavicka urcuje origin ACL v access-manageru,
# takze seznam MUSI odpovidat adrese, ze ktere k nam chodi vlastni proxy -
# a ta je v kontejneru jina nez 127.0.0.1. Spatna hodnota nic neohlasi:
# origin ACL zacne u kazdeho pozadavku merit adresu proxy misto klienta.
if [ -z "${SOC_TRUSTED_PROXIES:-}" ]; then
    cat >&2 <<'VAROVANI'
================================================================================
POZOR: SOC_TRUSTED_PROXIES neni nastaveno.

Bez nej se neveri hlavicce X-Real-IP a do access-manageru pujde jako origin
adresa proxy misto adresy klienta. Origin ACL pak nerozlisi nikoho a vypada
to pritom funkcne.

Spravnou hodnotu zjistite z logu: poslete pozadavek pres proxy a podivejte
se, jakou adresu sluzba zaznamenala jako peer.
================================================================================
VAROVANI
fi

exec python -m soc_api
