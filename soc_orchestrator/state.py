"""Stavovy automat nad manifest.analysis.state - pracovni fronta vzorku.

soc_api pri prijmu nastavi `analysis.state = pending`. Orchestrator to je
jediny "worker", takze o claim nesoutezi (zadny zavod); atomicky zapis presto
drzi, aby cteni (portal) nevidelo rozepsany manifest.

    pending  --claim-->  running  --> done | error
                          ^
              reclaim: running dele nez timeout (spadly worker) --> pending

Vysledek analyzy (skore, signaly) jde do analysis.json; manifest.analysis je
JEN stavova znacka.
"""
from __future__ import annotations

from datetime import UTC, datetime

from . import config, vault_rw


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _state(manifest: dict) -> str:
    return (manifest.get("analysis") or {}).get("state", "")


def iter_pending():
    """sha256 vzorku ve stavu pending (plny sken vaultu)."""
    for sha in vault_rw.iter_sample_ids():
        m = vault_rw.read_manifest(sha)
        if m and _state(m) == "pending":
            yield sha


def claim(sha256: str) -> bool:
    """pending -> running. Vrati False, kdyz uz neni pending (uklizeno jinde)."""
    m = vault_rw.read_manifest(sha256)
    if not m or _state(m) != "pending":
        return False
    m["analysis"] = {"state": "running", "started_at": _now()}
    vault_rw.write_manifest(sha256, m)
    return True


def mark_done(sha256: str) -> None:
    m = vault_rw.read_manifest(sha256) or {}
    m["analysis"] = {"state": "done", "schema": config.SCHEMA, "finished_at": _now()}
    vault_rw.write_manifest(sha256, m)


def mark_error(sha256: str, reason: str) -> None:
    m = vault_rw.read_manifest(sha256) or {}
    m["analysis"] = {"state": "error", "reason": reason[:300], "finished_at": _now()}
    vault_rw.write_manifest(sha256, m)


def reclaim_stale(reclaim_after_s: int) -> int:
    """running dele nez timeout = worker spadl uprostred -> zpet na pending.
    Vraci pocet vracenych vzorku."""
    cutoff = datetime.now(UTC).timestamp() - reclaim_after_s
    n = 0
    for sha in vault_rw.iter_sample_ids():
        m = vault_rw.read_manifest(sha)
        if not m or _state(m) != "running":
            continue
        started = (m.get("analysis") or {}).get("started_at", "")
        try:
            ts = datetime.fromisoformat(started).timestamp()
        except (ValueError, TypeError):
            ts = 0.0
        if ts < cutoff:
            m["analysis"] = {"state": "pending"}
            vault_rw.write_manifest(sha, m)
            n += 1
    return n
