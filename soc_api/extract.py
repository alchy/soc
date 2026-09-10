"""Bezpecne rozbaleni prijateho archivu.

Rozbaluje se CIZI, zamerne skodlivy archiv - kazda polozka je tvrzeni utocnika,
ne fakt. Proto se nic nebere na slovo:

* cesta mimo cilovy adresar (`../`, absolutni cesta, disk `C:`) = odmitnuto,
* symlink i hardlink = preskoceno (mohly by ukazat kamkoli do systemu),
* zarizeni, fifo, socket = preskoceno,
* tri nezavisle stropy proti dekompresnim bombam,
* z vysledku se odebira `x` bit - rozbaleny vzorek nema byt spustitelny.

Kdyz to nejde, NENI to chyba prijmu: original je ulozeny a vzorek dostane
stav `cannot_decompress` s lidskym duvodem. Hesla se nehadaji.
"""
from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config


@dataclass
class Result:
    """Vysledek pokusu o rozbaleni - jde rovnou do manifestu."""

    status: str                       # extracted | cannot_decompress | not_an_archive | corrupt
    info: str = ""
    file_count: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {"status": self.status, "info": self.info,
             "file_count": self.file_count, "total_bytes": self.total_bytes}
        if self.skipped:
            # Jen prvnich par - seznam 10 000 preskocenych polozek nikomu nepomuze.
            d["skipped"] = self.skipped[:20]
            d["skipped_total"] = len(self.skipped)
        return d


def _safe_target(dest: Path, name: str) -> Path | None:
    """Prelozi jmeno polozky na cilovou cestu, nebo None kdyz vede ven.

    Kontrola je az na VYSLEDNE ceste (resolve), ne na retezci - retezcove
    kontroly na `..` obchazi kdejaka kombinace oddelovacu a symlinku.
    """
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    target = (dest / name).resolve()
    try:
        target.relative_to(dest.resolve())
    except ValueError:
        return None
    return target


def _budget_exceeded(total: int, count: int, original_size: int) -> str | None:
    if total > config.MAX_EXTRACT_BYTES:
        return f"rozbaleno pres {config.MAX_EXTRACT_BYTES} B"
    if count > config.MAX_EXTRACT_FILES:
        return f"vic nez {config.MAX_EXTRACT_FILES} polozek"
    if original_size and total > original_size * config.MAX_EXTRACT_RATIO:
        return f"pomer dekomprese pres {config.MAX_EXTRACT_RATIO}:1"
    return None


def _finish(dest: Path) -> None:
    """Odebere `x` bit ze vseho rozbaleneho.

    Adresare `x` potrebuji (jinak do nich nejde vstoupit), soubory ne.
    """
    for p in dest.rglob("*"):
        if p.is_symlink():
            continue
        p.chmod(0o750 if p.is_dir() else 0o640)


def _extract_zip(src: Path, dest: Path, original_size: int) -> Result:
    skipped: list[str] = []
    total = count = 0
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Horni bity external_attr nesou unixovy mod; S_IFLNK == 0xA000.
            mode = info.external_attr >> 16
            if mode and (mode & 0xF000) == 0xA000:
                skipped.append(f"{info.filename} (symlink)")
                continue
            target = _safe_target(dest, info.filename)
            if target is None:
                skipped.append(f"{info.filename} (cesta mimo adresar)")
                continue
            total += info.file_size
            count += 1
            if (why := _budget_exceeded(total, count, original_size)):
                return Result("cannot_decompress", f"zastaveno: {why}",
                              count - 1, total - info.file_size, skipped)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as s, open(target, "wb") as d:
                while chunk := s.read(64 * 1024):
                    d.write(chunk)
    _finish(dest)
    return Result("extracted", "", count, total, skipped)


def _extract_tar(src: Path, dest: Path, original_size: int) -> Result:
    skipped: list[str] = []
    total = count = 0
    with tarfile.open(src) as tf:
        for member in tf:
            if member.isdir():
                continue
            if not member.isfile():
                # symlink, hardlink, zarizeni, fifo - nic z toho nechceme na disku
                skipped.append(f"{member.name} ({member.type.decode(errors='replace')})")
                continue
            target = _safe_target(dest, member.name)
            if target is None:
                skipped.append(f"{member.name} (cesta mimo adresar)")
                continue
            total += member.size
            count += 1
            if (why := _budget_exceeded(total, count, original_size)):
                return Result("cannot_decompress", f"zastaveno: {why}",
                              count - 1, total - member.size, skipped)
            target.parent.mkdir(parents=True, exist_ok=True)
            src_f = tf.extractfile(member)
            if src_f is None:
                skipped.append(f"{member.name} (nelze cist)")
                count -= 1
                total -= member.size
                continue
            with src_f, open(target, "wb") as d:
                while chunk := src_f.read(64 * 1024):
                    d.write(chunk)
    _finish(dest)
    return Result("extracted", "", count, total, skipped)


def extract(src: Path, dest: Path) -> Result:
    """Rozbali `src` do `dest`. Nikdy nevyhodi vyjimku - vraci stav."""
    dest.mkdir(parents=True, exist_ok=True)
    original_size = src.stat().st_size

    try:
        if zipfile.is_zipfile(src):
            return _extract_zip(src, dest, original_size)
        if tarfile.is_tarfile(src):
            return _extract_tar(src, dest, original_size)
        return Result("not_an_archive", "soubor neni zip ani tar - ulozen jen original")
    except RuntimeError as e:
        # zipfile hlasi heslovany archiv prave takhle
        if "encrypted" in str(e).lower() or "password" in str(e).lower():
            return Result("cannot_decompress",
                          "archiv je chraneny heslem - nelze rozbalit")
        return Result("cannot_decompress", f"chyba pri rozbalovani: {e}")
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as e:
        return Result("corrupt", f"archiv je poskozeny: {e}")
    except OSError as e:
        return Result("cannot_decompress", f"chyba uloziste: {e}")
