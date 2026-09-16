#!/bin/sh
# Postavi obraz PORTALU z korene repozitare.
#
#     deploy/container-build-portal.sh [tag]
#
# Spousti se JAKO UZIVATEL, pod kterym pak kontejner pobezi (rootless podman
# ma uloziste obrazu v jeho domove).
set -eu

TAG="${1:-localhost/soc-portal:latest}"
KOREN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# --format docker NENI kosmetika: v nativnim OCI formatu podman instrukci
# HEALTHCHECK zahodi a kontejner nema jak rict, ze je nezdravy.
exec podman build --format docker -t "$TAG" -f "$KOREN/Dockerfile.portal" "$KOREN"
