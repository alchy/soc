"""Bezpecne rozbaleni prijateho archivu.

Rozbaluje se CIZI, zamerne skodlivy archiv - kazda polozka je tvrzeni utocnika,
ne fakt. Proto se nic nebere na slovo:

* cesta mimo cilovy adresar (`../`, absolutni cesta, disk `C:`) = odmitnuto,
* symlink i hardlink = preskoceno (mohly by ukazat kamkoli do systemu),
* zarizeni, fifo, socket = preskoceno,
* tri nezavisle stropy proti dekompresnim bombam,
* z vysledku se odebira `x` bit - rozbaleny vzorek nema byt spustitelny.

Prijima se **jen ZIP** - jediny bezny format, ktery umi heslo a ktery
zvladneme rozbalit bez externich nastroju. Musi to potvrdit obojí:

* suffix jmena, ktere posila klient (`.zip`),
* magicke bajty obsahu.

Suffix je tvrzeni klienta, magicke bajty jsou fakt. Neshoda neni chyba
prenosu, ale zprava sama o sobe - vrati se stav `format_mismatch`
a nerozbaluje se. RAR, 7z a tar se poznaji podle hlavicky a odmitnou se
pojmenovane, at klient vi, co poslal.

Heslo se predava v pozadavku, nikdy se nehada a nikam se neloguje. Sifrovany
ZIP nese bud stare ZipCrypto, nebo AES (7-Zip, WinRAR) - `pyzipper` zvlada
oboje, standardni `zipfile` jen to prvni.

Kdyz to nejde, NENI to chyba prijmu: original je ulozeny a vzorek dostane
stav s lidskym duvodem.
"""
from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import pyzipper

from . import config

# Jediny prijimany format.
SUFFIX = ".zip"

# Magicke bajty formatu, ktere umime POJMENOVAT, i kdyz je neprijimame.
# Bez toho by klient posilajici RAR dostal jen "neni to zip" a hadal proc.
MAGIE: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),          # prazdny archiv
    (b"PK\x07\x08", "zip"),          # spanned
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
)


@dataclass
class Result:
    """Vysledek pokusu o rozbaleni - jde rovnou do manifestu."""

    status: str
    info: str = ""
    format: str | None = None
    encrypted: bool = False
    file_count: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {"status": self.status, "info": self.info,
             "format": self.format, "encrypted": self.encrypted,
             "file_count": self.file_count, "total_bytes": self.total_bytes}
        if self.skipped:
            # Jen prvnich par - seznam 10 000 preskocenych polozek nikomu nepomuze.
            d["skipped"] = self.skipped[:20]
            d["skipped_total"] = len(self.skipped)
        return d


def ma_zip_suffix(filename: str) -> bool:
    """Tvrdi klient, ze posila ZIP?"""
    return filename.lower().endswith(SUFFIX)


def format_z_obsahu(src: Path) -> str | None:
    """Format podle magickych bajtu. Tohle je fakt, na rozdil od suffixu.

    Vraci i formaty, ktere NEPRIJIMAME - aby se dalo rict, co klient poslal,
    misto abychom mu vratili holé "neni to zip".
    """
    try:
        with open(src, "rb") as f:
            zacatek = f.read(8)
    except OSError:
        return None
    for magie, jmeno in MAGIE:
        if zacatek.startswith(magie):
            return jmeno
    # tar nema magii na zacatku - ma ji az na offsetu 257
    if tarfile.is_tarfile(src):
        return "tar"
    return None


def _je_sifrovany(src: Path) -> bool:
    """Nese ZIP aspon jednu sifrovanou polozku? (bit 0 v flag_bits)"""
    try:
        with zipfile.ZipFile(src) as zf:
            return any(i.flag_bits & 0x1 for i in zf.infolist())
    except (zipfile.BadZipFile, OSError):
        return False


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


def _extract_zip(src: Path, dest: Path, original_size: int,
                 password: str | None, encrypted: bool) -> Result:
    skipped: list[str] = []
    total = count = 0

    # pyzipper zvlada ZipCrypto i AES; standardni zipfile jen to prvni
    # a na AES spadne na NotImplementedError.
    with pyzipper.AESZipFile(src) as zf:
        if password:
            zf.setpassword(password.encode())
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
                              "zip", encrypted, count - 1, total - info.file_size, skipped)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as s, open(target, "wb") as d:
                while chunk := s.read(64 * 1024):
                    d.write(chunk)
    _finish(dest)
    return Result("extracted", "", "zip", encrypted, count, total, skipped)


def extract(src: Path, filename: str, dest: Path,
            password: str | None = None) -> Result:
    """Rozbali ZIP `src`. Nikdy nevyhodi vyjimku - vraci stav.

    Prijima se jen ZIP a musi to potvrdit suffix jmena i magicke bajty.
    `password` se nikdy nikam neloguje.
    """
    dest.mkdir(parents=True, exist_ok=True)
    original_size = src.stat().st_size

    skutecny = format_z_obsahu(src)

    # Suffix je tvrzeni klienta, magicke bajty jsou fakt. Rozhoduji obojí,
    # protoze kazde chyti jinou chybu: spatne pojmenovany archiv i podvrzeny
    # obsah.
    if not ma_zip_suffix(filename):
        detail = f", obsah vypada jako {skutecny}" if skutecny else ""
        return Result("unsupported_format",
                      f"prijima se jen .zip, prislo '{filename}'{detail} "
                      f"- ulozen jen original",
                      skutecny)

    if skutecny is None:
        return Result("corrupt", "suffix slibuje zip, ale obsah neni platny archiv", None)

    if skutecny != "zip":
        return Result("format_mismatch",
                      f"suffix slibuje zip, ale obsah je {skutecny} - nerozbaluji",
                      skutecny)

    # Az sem se dostane jen skutecny ZIP. `is_zipfile` cte centralni adresar,
    # takze potvrdi i to, ze archiv neni jen useknuty zacatek.
    if not zipfile.is_zipfile(src):
        return Result("corrupt", "zip nema platny centralni adresar", "zip")

    encrypted = _je_sifrovany(src)

    if encrypted and not password:
        return Result("password_required",
                      "archiv je sifrovany, heslo nebylo v pozadavku",
                      "zip", True)

    try:
        return _extract_zip(src, dest, original_size, password, encrypted)
    except RuntimeError as e:
        # pyzipper hlasi spatne heslo prave takhle
        text = str(e).lower()
        if "password" in text or "encrypted" in text:
            return Result("bad_password",
                          "heslo k archivu nesouhlasi" if password
                          else "archiv je sifrovany, heslo nebylo v pozadavku",
                          "zip", True)
        return Result("cannot_decompress", f"chyba pri rozbalovani: {e}", "zip", encrypted)
    except NotImplementedError as e:
        return Result("cannot_decompress",
                      f"nepodporovana kompresni metoda v archivu: {e}", "zip", encrypted)
    except (zipfile.BadZipFile, pyzipper.BadZipFile, EOFError) as e:
        # pyzipper.BadZipFile NENI podtrida zipfile.BadZipFile - musi se
        # jmenovat obe, jinak poskozeny archiv shodi cely pozadavek na 500
        # misto toho, aby dostal stav.
        return Result("corrupt", f"archiv je poskozeny: {e}", "zip", encrypted)
    except OSError as e:
        return Result("cannot_decompress", f"chyba uloziste: {e}", "zip", encrypted)
