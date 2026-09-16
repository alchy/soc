"""Konfigurace orchestratoru - vse z prostredi, fail-fast na startu."""
from __future__ import annotations

import os
from pathlib import Path


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


VAULT = Path(_env("SOC_ORCH_VAULT", "/vault"))
POLL_INTERVAL_S = int(_env("SOC_ORCH_POLL_S", "60"))        # perioda smycky
SAMPLE_TIMEOUT_S = int(_env("SOC_ORCH_SAMPLE_TIMEOUT_S", "120"))  # strop na 1 vzorek
RECLAIM_AFTER_S = int(_env("SOC_ORCH_RECLAIM_S", "900"))   # running dele = spadly worker
BATCH_MAX = int(_env("SOC_ORCH_BATCH_MAX", "500"))         # kolik pending za tick
HEARTBEAT = Path(_env("SOC_ORCH_HEARTBEAT", "/tmp/soc-orchestrator.heartbeat"))
SERVICE_NAME = _env("SOC_ORCH_SERVICE_NAME", "soc-orchestrator")

# Verze schematu reportu - jediny zdroj je soc_mail.report. Konzumenti (portal,
# soc_api) podle ni poznaji zastaralou analyzu a orchestrator ji preanalyzuje.
from soc_mail.report import REPORT_SCHEMA as SCHEMA  # noqa: E402


def validate() -> None:
    """Fail-fast: bez citelneho vaultu nema smysl start."""
    if not VAULT.is_dir():
        raise SystemExit(f"soc-orchestrator: vault neexistuje: {VAULT}")
