"""Smycka orchestratoru: reclaim -> zpracuj pending -> heartbeat -> sleep.

Jednoduchy dlouhoběžici proces. Pad procesu resi restart kontejneru
(systemd Restart=always); ZASEKNUTI resi per-vzorek timeout (signal.alarm)
a heartbeat healthcheck. SIGTERM ukonci smycku cistě po aktualnim vzorku.

    python -m soc_orchestrator            # smycka (produkce)
    python -m soc_orchestrator --once     # jeden pruchod a konec
    python -m soc_orchestrator --dry-run  # spocitej, ale NIC nezapisuj (test)
"""
from __future__ import annotations

import argparse
import itertools
import json
import signal
import sys
import threading
from datetime import UTC, datetime

from . import config, runner, state, vault_rw

_stop = threading.Event()


def _log(msg: str, **kw) -> None:
    rec = {"component": config.SERVICE_NAME, "level": kw.pop("level", "info"),
           "msg": msg, "t": datetime.now(UTC).isoformat(timespec="seconds"), **kw}
    print(json.dumps(rec, ensure_ascii=False), flush=True)


class _SampleTimeout:
    """Strop na jeden vzorek - jeden pokriveny dokument nesmi zaseknout smycku.
    signal.alarm funguje v hlavnim vlakne (smycka je jednovlaknova)."""

    def __init__(self, seconds: int):
        self.seconds = seconds

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._fire)
        signal.alarm(self.seconds)

    def __exit__(self, *exc):
        signal.alarm(0)

    def _fire(self, *_):
        raise TimeoutError(f"sample timeout {self.seconds}s")


def _heartbeat() -> None:
    try:
        config.HEARTBEAT.write_text(
            datetime.now(UTC).isoformat(timespec="seconds"), encoding="utf-8")
    except OSError as e:
        _log("heartbeat_failed", level="warning", error=str(e))


def process_one(sha256: str, dry_run: bool) -> str:
    if dry_run:
        report = runner.analyze(sha256)
        _log("dry_run_sample", sha256=sha256, points=report["verdict"]["points"],
             band=report["verdict"]["band"], blocks=len(report["blocks"]))
        return "dry"
    if not state.claim(sha256):
        return "skip"
    try:
        with _SampleTimeout(config.SAMPLE_TIMEOUT_S):
            report = runner.analyze(sha256)
        vault_rw.write_analysis(sha256, report)
        state.mark_done(sha256)
        _log("analyzed", sha256=sha256, points=report["verdict"]["points"],
             band=report["verdict"]["band"])
        return "done"
    except Exception as e:  # vcetne TimeoutError - vzorek do error, smycka zije
        state.mark_error(sha256, f"{type(e).__name__}: {e}")
        _log("analyze_failed", level="warning", sha256=sha256,
             error=f"{type(e).__name__}: {e}")
        return "error"


def tick(dry_run: bool) -> None:
    reclaimed = 0 if dry_run else state.reclaim_stale(config.RECLAIM_AFTER_S)
    done = err = 0
    for sha in itertools.islice(state.iter_pending(), config.BATCH_MAX):
        if _stop.is_set():
            break
        outcome = process_one(sha, dry_run)
        done += outcome in ("done", "dry")
        err += outcome == "error"
    _heartbeat()
    if done or err or reclaimed:
        _log("tick", processed=done, errors=err, reclaimed=reclaimed)


def main() -> int:
    ap = argparse.ArgumentParser(prog="soc_orchestrator")
    ap.add_argument("--once", action="store_true", help="jeden pruchod a konec")
    ap.add_argument("--dry-run", action="store_true",
                    help="spocitej, ale nic nezapisuj do vaultu")
    args = ap.parse_args()

    config.validate()
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    _log("started", vault=str(config.VAULT), poll_s=config.POLL_INTERVAL_S,
         schema=config.SCHEMA, dry_run=args.dry_run, once=args.once)

    while not _stop.is_set():
        try:
            tick(args.dry_run)
        except Exception as e:  # jeden zly tick nesmi zabit demona
            _log("tick_failed", level="error", error=f"{type(e).__name__}: {e}")
        if args.once:
            break
        _stop.wait(config.POLL_INTERVAL_S)

    _log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
