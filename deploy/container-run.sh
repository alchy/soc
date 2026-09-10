#!/bin/sh
# Spusti sluzbu v kontejneru (rootless podman).
#
# Vsechny parametry maji vychozi hodnotu a jdou prebit promennou prostredi
# nebo prepinacem; systemd unit `soc-api-container.service` vola tenhle skript
# s `--foreground`, takze se provoz a rucni spusteni nemuzou rozejit.
#
#     deploy/container-run.sh --help
set -eu

IMAGE="${SOC_IMAGE:-localhost/soc-api:latest}"
NAME="${SOC_NAME:-soc-api}"
DOMOV="${HOME:-/www/soc}"
VAULT="${SOC_VAULT_HOST:-$DOMOV/vault}"
# Adresar logu. Montuje se dovnitr jako /var/log/soc, takze si tam sluzba
# pise vlastni access.log; podman do nej vedle toho pise service.log
# (stdout/stderr kontejneru). Oboji tedy prezije smazani kontejneru.
LOGDIR="${SOC_LOG:-$DOMOV/logs}"
PORT="${SOC_PORT:-8095}"
BIND="${SOC_BIND:-127.0.0.1}"

# Adresa, pod kterou kontejner vidi SMYCKU HOSTITELE. Access-manager publikuje
# porty jen na 127.0.0.1 hostitele, kam kontejner primo nedosahne; pasta tuhle
# adresu prelozi. Link-local rozsah je zvoleny zamerne - nekoliduje s nicim,
# co by sluzba mohla chtit skutecne oslovit, a na rozdil od vychoziho chovani
# (`--map-gw`) nezavisi na tom, jak vypada sit hostitele.
HOST_ADDR="${SOC_HOST_ADDR:-169.254.1.2}"
AM_PORT="${SOC_AM_PORT:-22000}"

# Komu se veri X-Real-IP.
#
# Tohle je nejzradnejsi misto celeho nasazeni. Nativni sluzba videla nginx
# prichazet z 127.0.0.1. Kontejner ho z 127.0.0.1 NEVIDI: pasta preklada
# zdrojovou adresu spojeni z hostitelske smycky na adresu hostitele na jeho
# vychozim rozhrani. Zjistujeme ji proto za behu - napevno zapsana by se
# pri zmene IP stroje tise rozesla se skutecnosti.
#
# Dusledek spatne hodnoty: sluzba prestane verit hlavicce X-Real-IP a do
# access-manageru pujde jako origin adresa proxy misto adresy klienta.
# Origin ACL pak nerozlisi nikoho - a nic to neohlasi, vypada to funkcne.
# `ip` lezi v /sbin, ktery systemove unity v PATH bezne nemaji - hledame ho
# proto vyslovne, at se detekce tise nevypne prave v provozu.
IP_BIN=$(command -v ip || echo /sbin/ip)
HOST_SRC=$("$IP_BIN" route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
TRUSTED="${SOC_TRUSTED_PROXIES:-${HOST_SRC:+$HOST_SRC,}$HOST_ADDR,127.0.0.1,::1}"

MAX_UPLOAD="${SOC_MAX_UPLOAD:-52428800}"
# Systemovy unit bezi v system slice, takze uzivatelsky systemd mu cgroup
# scope vyrobit nemuze a start skonci na `creating systemd unit ... got
# failed`. cgroupfs ten krok obchazi a zaklada cgroupy primo v delegovane
# skupine (Delegate=yes v unitu).
CGROUP_MANAGER="${SOC_CGROUP_MANAGER:-cgroupfs}"
AM_REALM="${SOC_AM_REALM:-soc.autumnpartials.com}"
TZ_ZONA="${SOC_TZ:-}"
FOREGROUND=0

napoveda() {
    cat <<'NAPOVEDA'
Pouziti: container-run.sh [prepinace]

  --image TAG        obraz (SOC_IMAGE)                 [localhost/soc-api:latest]
  --name JMENO       jmeno kontejneru (SOC_NAME)       [soc-api]
  --vault CESTA      vault na hostiteli (SOC_VAULT_HOST) [$HOME/vault]
  --log CESTA        adresar logu (SOC_LOG)            [$HOME/logs]
  --port PORT        port na hostiteli (SOC_PORT)      [8095]
  --bind ADRESA      na co publikovat (SOC_BIND)       [127.0.0.1]
  --host-addr ADRESA jak kontejner vidi smycku hostitele (SOC_HOST_ADDR)
                                                       [169.254.1.2]
  --am-port PORT     port access-manageru (SOC_AM_PORT) [22000]
  --realm NAZEV      ocekavany realm klice (SOC_AM_REALM)
  --tz ZONA          casova zona kontejneru (SOC_TZ)   [UTC]
  --foreground       nedemonizovat (pro systemd)
  --help

Port se publikuje na 127.0.0.1, tedy JEN pro tenhle stroj. Pred sluzbu patri
reverzni proxy s TLS - bez ni neni API dostupne odjinud.
NAPOVEDA
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        --name) NAME="$2"; shift 2 ;;
        --vault) VAULT="$2"; shift 2 ;;
        --log) LOGDIR="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --bind) BIND="$2"; shift 2 ;;
        --host-addr) HOST_ADDR="$2"; shift 2 ;;
        --am-port) AM_PORT="$2"; shift 2 ;;
        --realm) AM_REALM="$2"; shift 2 ;;
        --tz) TZ_ZONA="$2"; shift 2 ;;
        --foreground) FOREGROUND=1; shift ;;
        --help|-h) napoveda; exit 0 ;;
        *) echo "neznamy prepinac: $1" >&2; napoveda >&2; exit 2 ;;
    esac
done

[ -d "$VAULT" ] || { echo "vault neexistuje: $VAULT" >&2; exit 1; }
mkdir -p "$LOGDIR"

# Zbytek po predchozim behu. `--rm` uklizi po sobe, ale ne po padu stroje.
podman --cgroup-manager "$CGROUP_MANAGER" rm -f "$NAME" >/dev/null 2>&1 || true

set -- \
    --rm \
    --init \
    --name "$NAME" \
    --network "pasta:--map-host-loopback,$HOST_ADDR" \
    --publish "$BIND:$PORT:8095" \
    --userns "keep-id:uid=1000,gid=1000" \
    --volume "$VAULT:/var/lib/soc/vault:Z,nosuid,nodev,noexec" \
    --volume "$LOGDIR:/var/log/soc:Z,nosuid,nodev,noexec" \
    --env "SOC_AM_URL=http://$HOST_ADDR:$AM_PORT" \
    --env "SOC_LOG_DIR=/var/log/soc" \
    --env "SOC_AM_REALM=$AM_REALM" \
    --env "SOC_TRUSTED_PROXIES=$TRUSTED" \
    --env "SOC_MAX_UPLOAD=$MAX_UPLOAD" \
    --log-driver k8s-file \
    --log-opt "path=$LOGDIR/service.log" \
    --log-opt max-size=10m \
    --stop-timeout 15

# Sluzba rozbaluje cizi malware. Vsechno, co k tomu nepotrebuje, jde pryc:
# zadne schopnosti, zadne zvyseni opravneni, koren jen pro cteni.
#
# `nosuid,nodev,noexec` na obou mountech: ve vaultu lezi cizi malware a
# nic z nej se nesmi dat spustit ani pouzit ke zvyseni opravneni. Rozbalene
# soubory sice prichazeji o `x` bit uz pri rozbalovani, ale to je pojistka
# v kodu - tohle je pojistka v jadre.
set -- "$@" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m

[ -z "$TZ_ZONA" ] || set -- "$@" --env "TZ=$TZ_ZONA"
[ "$FOREGROUND" -eq 1 ] || set -- "$@" --detach

exec podman --cgroup-manager "$CGROUP_MANAGER" run "$@" "$IMAGE"
