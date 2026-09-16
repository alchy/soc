"""RW pristup k vaultu - zrcadli zapisovou pulku soc_api.storage.

Orchestrator je vedle soc_api DRUHY a posledni zapisovatel vaultu. Ctí stejny
invariant: kazdy zapis je ATOMICKY (temp soubor + os.replace), takze cteni
(portal) nikdy neuvidi rozepsany JSON.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from . import config

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sample_dir(sha256: str) -> Path:
    return config.VAULT / sha256[:2] / sha256


def read_manifest(sha256: str) -> dict | None:
    p = sample_dir(sha256) / "manifest.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, NotADirectoryError, json.JSONDecodeError, OSError):
        return None


def _atomic_write_json(path: Path, data: dict, prefix: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=prefix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_manifest(sha256: str, manifest: dict) -> None:
    _atomic_write_json(sample_dir(sha256) / "manifest.json", manifest, ".manifest-")


def write_analysis(sha256: str, analysis: dict) -> None:
    _atomic_write_json(sample_dir(sha256) / "analysis.json", analysis, ".analysis-")


def iter_sample_ids():
    """sha256 vsech vzorku ve vaultu (plny sken shardu, jako soc_api)."""
    if not config.VAULT.is_dir():
        return
    for shard in config.VAULT.iterdir():
        if not shard.is_dir() or len(shard.name) != 2:
            continue
        for d in shard.iterdir():
            if d.is_dir() and SHA256_RE.match(d.name):
                yield d.name
