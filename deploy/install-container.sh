#!/bin/sh
# Pripravi hostitele pro beh soc-api v rootless kontejneru.
#
#     sudo deploy/install-container.sh
#
# Skript je idempotentni - da se pustit znovu, nic nerozbije. Ctyri veci,
# bez kterych rootless podman ze systemoveho unitu nenajede a z hlasek to
# neni poznat:
#
#   1. systemovy uzivatel a adresare (vault, logy),
#   2. delegovane subuid/subgid - bez nich podman nenamapuje UID dovnitr,
#   3. linger - bez nej po bootu neexistuje /run/user/<uid>,
#   4. container-run.sh jako /usr/local/bin/soc-api-container + systemd unit.
#
# Obraz se NESTAVI - to je krok navic, protoze se stavi jako uzivatel sluzby:
#
#     sudo -u soc -H XDG_RUNTIME_DIR=/run/user/$(id -u soc) \
#          deploy/container-build.sh
set -eu

UZIVATEL="${SOC_USER:-soc}"
DOMOV="${SOC_HOME:-/www/soc}"
SUBID_START="${SOC_SUBID_START:-300000}"
SUBID_COUNT="${SOC_SUBID_COUNT:-65536}"

KOREN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

[ "$(id -u)" -eq 0 ] || { echo "spustte jako root" >&2; exit 1; }

# --- 1. uzivatel a adresare ------------------------------------------------
if ! id "$UZIVATEL" >/dev/null 2>&1; then
    useradd --system --create-home --home-dir "$DOMOV" \
            --shell /bin/bash --user-group "$UZIVATEL"
    passwd -l "$UZIVATEL" >/dev/null
    echo "zalozen uzivatel $UZIVATEL"
fi

# Vault drzi cizi malware - 0700, nikdo krome sluzby tam nema co delat.
install -d -o "$UZIVATEL" -g "$UZIVATEL" -m 0700 "$DOMOV/vault"
install -d -o "$UZIVATEL" -g "$UZIVATEL" -m 0750 "$DOMOV/logs"

# --- 2. subuid/subgid ------------------------------------------------------
# Uvnitr obrazu existuje root (0), soc (1000) i nobody (65534); venku je jen
# jedno UID. Jadro proto uzivateli deleguje cely blok. Kdyby proces
# z kontejneru utekl, je venku uid ze zacatku bloku, ktere nikomu nepatri.
if ! grep -q "^$UZIVATEL:" /etc/subuid 2>/dev/null; then
    usermod --add-subuids "$SUBID_START-$((SUBID_START + SUBID_COUNT - 1))" \
            --add-subgids "$SUBID_START-$((SUBID_START + SUBID_COUNT - 1))" \
            "$UZIVATEL"
    echo "delegovany subuid/subgid od $SUBID_START"
fi

# --- 3. linger -------------------------------------------------------------
# Rootless podman potrebuje /run/user/<uid> a uzivatelsky systemd. Ty vznikaji
# az prihlasenim - a sluzba startujici pri bootu se nikam neprihlasuje.
loginctl enable-linger "$UZIVATEL"

# --- 4. skript a unit ------------------------------------------------------
install -m 0755 "$KOREN/deploy/container-run.sh" /usr/local/bin/soc-api-container

UID_SLUZBY=$(id -u "$UZIVATEL")
sed -e "s|user@978\.service|user@$UID_SLUZBY.service|g" \
    -e "s|/run/user/978|/run/user/$UID_SLUZBY|g" \
    -e "s|User=soc$|User=$UZIVATEL|" \
    -e "s|Group=soc$|Group=$UZIVATEL|" \
    -e "s|HOME=/www/soc|HOME=$DOMOV|" \
    "$KOREN/deploy/soc-api-container.service" \
    > /etc/systemd/system/soc-api-container.service

systemctl daemon-reload

cat <<HOTOVO

Hostitel je pripraveny. Dal:

  1. postavte obraz JAKO UZIVATEL SLUZBY (rootless podman ma uloziste
     obrazu v jeho domovskem adresari):

       sudo -u $UZIVATEL -H XDG_RUNTIME_DIR=/run/user/$UID_SLUZBY \\
            $KOREN/deploy/container-build.sh

  2. spustte sluzbu:

       systemctl enable --now soc-api-container

  3. postavte pred ni reverzni proxy s TLS - vzor je
     v deploy/nginx-soc.conf.example

HOTOVO
