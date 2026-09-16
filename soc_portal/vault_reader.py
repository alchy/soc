"""READ-ONLY cteni vaultu.

Zrcadli ctecí pulku `soc_api.storage`, ale zamerne jen cteni - portal do vaultu
nikdy nesahne (a kontejner ma mount `:ro`, takze fyzicky nemuze). Layout vaultu
je sdileny kontrakt se soc-api; jeho tvar pripina test `tests/test_vault_reader.py`.

    vault/<sha256[:2]>/<sha256>/
        original/<blob>       puvodni prijaty archiv
        extracted/            rozbaleny obsah (kdyz to slo)
        manifest.json         metadata vzorku (zapisovano atomicky -> cteni je bezpecne)
        access.log            JSONL udalosti

BEZPECNOST: `sha256` i relativni cesta souboru se validuji, aby se nedalo vylezt
z adresare vzorku (path traversal). Obsah `extracted/` pochazi z nepratelskeho
vzorku - nikdy se neinterpretuje, jen cte jako bajty.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import config

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VaultError(Exception):
    """Neplatny vstup nebo pokus o vystup z adresare vzorku."""


def _require_sha256(sha256: str) -> str:
    if not SHA256_RE.match(sha256 or ""):
        raise VaultError(f"neplatny sha256: {sha256!r}")
    return sha256


def sample_dir(sha256: str) -> Path:
    return config.VAULT / _require_sha256(sha256)[:2] / sha256


def read_manifest(sha256: str) -> dict | None:
    """Manifest vzorku, nebo None kdyz chybi/je poskozeny. Nikdy nevyhodi."""
    p = sample_dir(sha256) / "manifest.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (json.JSONDecodeError, OSError):
        return None


def read_metadata(sha256: str) -> dict | None:
    """Lidsky citelna hlavicka e-mailu z extracted/metadata.json (kdyz existuje).

    Soubory maji UTF-8 BOM (utf-8-sig ho snese). U vzorku, ktere nejsou e-mail
    (napr. holy .zip), metadata chybi - vracime None, ne chybu.
    """
    p = sample_dir(sha256) / "extracted" / "metadata.json"
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (json.JSONDecodeError, OSError):
        return None


def read_events(sha256: str) -> list[dict]:
    """Radky access.log. Posledni radek muze byt rozepsany zapisovatelem -
    poskozeny radek se preskoci, ne aby spadl cely vypis."""
    p = sample_dir(sha256) / "access.log"
    out: list[dict] = []
    try:
        text = p.read_text(encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError):
        return out
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"malformed": line[:200]})
    return out


def list_files(sha256: str) -> list[dict]:
    """Rozbalene soubory: relativni cesta + velikost. Bez hashovani - pro vypis
    v UI staci velikost; hashovani 47 MB souboru pri kazdem zobrazeni je zbytecne."""
    root = sample_dir(sha256) / "extracted"
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        out.append({"path": str(p.relative_to(root)), "size": size})
    return out


def extracted_path(sha256: str, relpath: str) -> Path:
    """Bezpecna absolutni cesta k jednomu rozbalenemu souboru.

    Vyhodi VaultError pri pokusu vylezt z `extracted/` (napr. '../../etc/passwd').
    """
    root = (sample_dir(sha256) / "extracted").resolve()
    target = (root / relpath).resolve()
    # target musi lezet uvnitr root - jinak jde o path traversal.
    if root != target and root not in target.parents:
        raise VaultError(f"cesta mimo extracted/: {relpath!r}")
    if not target.is_file() or target.is_symlink():
        raise FileNotFoundError(relpath)
    return target


def iter_samples() -> list[dict]:
    """Vsechny manifesty, od nejnovejsiho.

    POZOR (znama mez): plny sken vsech shardu pri kazdem volani, bez indexu -
    stejne jako soc-api. Pro desetitisice vzorku (viz sharding) je to jeste ok;
    az to prestane stacit, patri sem index, ne dalsi hack. Zatim YAGNI.
    """
    if not config.VAULT.is_dir():
        return []
    found: list[dict] = []
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


def summarize(manifest: dict) -> dict:
    """Radek pro dashboard: sloucí manifest s hlavickou e-mailu (kdyz existuje).

    Odstinuje sablonu od tvaru JSONu - sablona cte jen tato plocha pole.
    """
    sha256 = manifest.get("sha256", "")
    md = read_metadata(sha256) or {}
    extraction = manifest.get("extraction", {})
    return {
        "sha256": sha256,
        "received_at": manifest.get("received_at", ""),
        "filename": manifest.get("filename", ""),
        "size": manifest.get("size", 0),
        "state": manifest.get("state", ""),
        "analysis_state": manifest.get("analysis", {}).get("state", "?"),
        "extraction_status": extraction.get("status", ""),
        "encrypted": bool(extraction.get("encrypted", False)),
        "file_count": extraction.get("file_count", 0),
        "sender": md.get("SenderEmail") or md.get("SenderName") or "",
        "subject": md.get("Subject") or "",
    }


def human_size(n: int | float) -> str:
    """Bajty na citelnou velikost - drobnost pro sablony."""
    step = 1024.0
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if abs(n) < step:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PB"
