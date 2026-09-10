"""Vault: obsahove adresovane uloziste vzorku.

Vzorek je identifikovany svym sha256 - tentyz obsah ma tedy vzdy tutez cestu
a poslani tehoz vzorku podruhe neni chyba ani duplikat. MD5 a SHA1 se pocitaji
taky, protoze v tom se vzorky mezi tymy bezne dohledavaji (VirusTotal, MISP),
ale identitou je sha256.

    vault/<sha256[:2]>/<sha256>/
        original/<puvodni-nazev>    puvodni blob, nikdy se nemeni
        extracted/                  rozbaleny obsah (kdyz to slo)
        manifest.json               metadata vzorku
        access.log                  JSONL: kdo, odkud, kdy, co

Sharding podle dvou znaku hashe drzi pocet polozek v jednom adresari rozumny
i po desetitisicich vzorku.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import config

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def sample_dir(sha256: str) -> Path:
    return config.VAULT / sha256[:2] / sha256


def safe_filename(name: str | None) -> str:
    """Puvodni jmeno je vstup od klienta - bere se z nej jen holy zaklad."""
    if not name:
        return "sample.bin"
    name = os.path.basename(name.replace("\\", "/")).strip()
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:200]
    return name.lstrip(".") or "sample.bin"


def receive(stream, max_bytes: int) -> tuple[Path, dict, bool]:
    """Nacte telo do docasneho souboru a spocita hashe za pochodu.

    Vraci (cesta, digesty, prekrocen_limit). Cte se po kouscich, aby se 50 MB
    nemuselo drzet v pameti; pri prekroceni limitu se cteni zastavi hned.
    """
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    over = False

    config.VAULT.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=config.VAULT, prefix=".incoming-")
    with os.fdopen(fd, "wb") as f:
        while chunk := stream.read(64 * 1024):
            size += len(chunk)
            if size > max_bytes:
                over = True
                break
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
            f.write(chunk)

    digests = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
               "sha256": sha256.hexdigest(), "size": size}
    return Path(tmp), digests, over


def free_bytes() -> int | None:
    """Volne misto na vaultu, nebo None kdyz to nejde zjistit."""
    try:
        st = os.statvfs(config.VAULT)
    except OSError:
        return None
    return st.f_bavail * st.f_frsize


def log_event(sha256: str, event: dict) -> None:
    """Prida radek do access.log vzorku. Jeden radek, jedna udalost."""
    d = sample_dir(sha256)
    d.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"t": now(), **event}, ensure_ascii=False, sort_keys=True)
    with open(d / "access.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def read_events(sha256: str) -> list[dict]:
    p = sample_dir(sha256) / "access.log"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"malformed": line[:200]})
    return out


def write_manifest(sha256: str, manifest: dict) -> None:
    d = sample_dir(sha256)
    d.mkdir(parents=True, exist_ok=True)
    # Zapis pres docasny soubor + rename: cteni nikdy neuvidi polovicni JSON.
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".manifest-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp, d / "manifest.json")


def read_manifest(sha256: str) -> dict | None:
    p = sample_dir(sha256) / "manifest.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def list_files(sha256: str) -> list[dict]:
    """Seznam rozbalenych souboru s velikosti a hashem."""
    root = sample_dir(sha256) / "extracted"
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(64 * 1024):
                h.update(chunk)
        out.append({"path": str(p.relative_to(root)),
                    "size": p.stat().st_size,
                    "sha256": h.hexdigest()})
    return out


def iter_samples():
    """Vsechny vzorky ve vaultu, od nejnovejsiho."""
    if not config.VAULT.is_dir():
        return []
    found = []
    for shard in config.VAULT.iterdir():
        if not shard.is_dir() or len(shard.name) != 2:
            continue
        for d in shard.iterdir():
            if d.is_dir() and SHA256_RE.match(d.name):
                m = read_manifest(d.name)
                if m:
                    found.append(m)
    found.sort(key=lambda m: m.get("received_at", ""), reverse=True)
    return found
