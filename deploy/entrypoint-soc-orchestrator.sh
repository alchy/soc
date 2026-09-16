#!/bin/sh
# Vstupni bod orchestratoroveho kontejneru.
#
# Konfigurace jde promennymi prostredi (viz soc_orchestrator/config.py).
set -eu

# Cokoli za prikazem se spusti misto sluzby - pro ladeni (`podman run ... sh`,
# nebo `... --once --dry-run`).
if [ "$#" -gt 0 ]; then
    exec python -m soc_orchestrator "$@"
fi

# Vault je READ-WRITE pripojny bod (orchestrator pise analysis.json).
export SOC_ORCH_VAULT="${SOC_ORCH_VAULT:-/vault}"
# Heartbeat do tmpfs /tmp - HEALTHCHECK hlida jeho cerstvost.
export SOC_ORCH_HEARTBEAT="${SOC_ORCH_HEARTBEAT:-/tmp/soc-orchestrator.heartbeat}"

exec python -m soc_orchestrator
