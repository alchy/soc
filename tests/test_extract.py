"""Obrany rozbalovaci vrstvy.

Kazdy test tu odpovida na otazku "co kdyz je archiv nepratelsky" - to je
jediny druh archivu, ktery tahle sluzba dostava.
"""
from __future__ import annotations

import subprocess
import tarfile
import zipfile

import pytest
import pyzipper

from soc_api import config, extract


@pytest.fixture
def dest(tmp_path):
    return tmp_path / "extracted"


MA_ZIP = subprocess.run(["which", "zip"], capture_output=True).returncode == 0


def zip_s_heslem(cesta, heslo: str, aes: bool, obsah="tajny obsah"):
    """Sifrovany ZIP - bud stare ZipCrypto, nebo AES jako 7-Zip a WinRAR.

    AES umi zapsat pyzipper. ZipCrypto ne (a standardni zipfile neumi zapsat
    sifrovany archiv vubec), takze na nej je potreba nastroj `zip`.
    """
    if aes:
        with pyzipper.AESZipFile(cesta, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as z:
            z.setpassword(heslo.encode())
            z.writestr("payload.txt", obsah)
        return cesta

    if not MA_ZIP:
        pytest.skip("nastroj zip neni k dispozici (ZipCrypto nejde vyrobit)")
    payload = cesta.parent / "payload.txt"
    payload.write_text(obsah)
    subprocess.run(["zip", "-q", "-j", "-P", heslo, str(cesta), str(payload)],
                   check=True)
    return cesta


# ── format: prijima se jen ZIP a musi to potvrdit obojí ──────────────────────

def test_prijima_se_jen_zip(tmp_path, dest):
    archive = tmp_path / "archiv.tgz"
    with tarfile.open(archive, "w:gz") as t:
        p = tmp_path / "a.txt"; p.write_text("obsah")
        t.add(p, arcname="a.txt")

    result = extract.extract(archive, "archiv.tgz", dest)

    assert result.status == "unsupported_format"
    assert ".zip" in result.info


def test_rar_se_odmitne_pojmenovane(tmp_path, dest):
    """Klient ma vedet, ze poslal RAR - ne jen ze to neni zip."""
    archive = tmp_path / "vzorek.rar"
    archive.write_bytes(b"Rar!\x1a\x07\x00" + b"x" * 100)

    result = extract.extract(archive, "vzorek.rar", dest)

    assert result.status == "unsupported_format"
    assert result.format == "rar"
    assert "rar" in result.info


def test_podvrzeny_suffix_neprojde(tmp_path, dest):
    """Suffix je tvrzeni klienta, magicke bajty jsou fakt."""
    archive = tmp_path / "vzorek.zip"
    archive.write_bytes(b"Rar!\x1a\x07\x00" + b"x" * 100)

    result = extract.extract(archive, "vzorek.zip", dest)

    assert result.status == "format_mismatch"
    assert result.format == "rar"


def test_poskozeny_zip(tmp_path, dest):
    archive = tmp_path / "broken.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.txt", "obsah")
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0xFF          # rozbij prostredek
    archive.write_bytes(bytes(data))

    result = extract.extract(archive, "broken.zip", dest)

    assert result.status in ("corrupt", "cannot_decompress")


# ── heslo: predava se, nikdy se nehada ──────────────────────────────────────

@pytest.mark.parametrize("aes", [False, True], ids=["zipcrypto", "aes"])
def test_sifrovany_zip_se_spravnym_heslem(tmp_path, dest, aes):
    archive = zip_s_heslem(tmp_path / "secret.zip", "infected", aes)

    result = extract.extract(archive, "secret.zip", dest, password="infected")

    assert result.status == "extracted"
    assert result.encrypted is True
    assert (dest / "payload.txt").read_text() == "tajny obsah"


@pytest.mark.parametrize("aes", [False, True], ids=["zipcrypto", "aes"])
def test_sifrovany_zip_bez_hesla(tmp_path, dest, aes):
    """Heslo se NEHADA - vzorek dostane stav, ne pokus o 'infected'."""
    archive = zip_s_heslem(tmp_path / "secret.zip", "infected", aes)

    result = extract.extract(archive, "secret.zip", dest)

    assert result.status == "password_required"
    assert result.encrypted is True


@pytest.mark.parametrize("aes", [False, True], ids=["zipcrypto", "aes"])
def test_spatne_heslo(tmp_path, dest, aes):
    archive = zip_s_heslem(tmp_path / "secret.zip", "infected", aes)

    result = extract.extract(archive, "secret.zip", dest, password="spatne")

    assert result.status == "bad_password"


def test_heslo_u_nesifrovaneho_archivu_nevadi(tmp_path, dest):
    archive = tmp_path / "plain.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.txt", "obsah")

    result = extract.extract(archive, "plain.zip", dest, password="zbytecne")

    assert result.status == "extracted"
    assert result.encrypted is False


# ── obrany proti nepratelskemu obsahu ───────────────────────────────────────

def test_zip_slip_nezapise_ven(tmp_path, dest):
    """Polozka s `../` nesmi opustit cilovy adresar."""
    archive = tmp_path / "slip.zip"
    outside = tmp_path / "PWNED.txt"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../PWNED.txt", "uteklo ven")
        z.writestr("ok.txt", "v poradku")

    result = extract.extract(archive, "slip.zip", dest)

    assert not outside.exists(), "zip-slip zapsal soubor mimo cilovy adresar"
    assert result.status == "extracted"
    assert result.file_count == 1
    assert any("mimo adresar" in s for s in result.skipped)


def test_absolutni_cesta_je_odmitnuta(tmp_path, dest):
    archive = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("/etc/passwd", "ne")
        z.writestr("ok.txt", "ano")

    result = extract.extract(archive, "abs.zip", dest)

    assert result.file_count == 1
    assert (dest / "ok.txt").exists()


def test_dekompresni_bomba_se_zastavi(tmp_path, dest, monkeypatch):
    """Prekroceni pomeru dekomprese zastavi rozbalovani, nedojde misto."""
    monkeypatch.setattr(config, "MAX_EXTRACT_RATIO", 5)

    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("velky.bin", b"\0" * (2 * 1024 * 1024))

    result = extract.extract(archive, "bomb.zip", dest)

    assert result.status == "cannot_decompress"
    assert "pomer" in result.info


def test_prilis_mnoho_polozek(tmp_path, dest, monkeypatch):
    monkeypatch.setattr(config, "MAX_EXTRACT_FILES", 3)

    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for i in range(10):
            z.writestr(f"f{i}.txt", "x")

    result = extract.extract(archive, "many.zip", dest)

    assert result.status == "cannot_decompress"
    assert "polozek" in result.info


def test_rozbalene_soubory_nejsou_spustitelne(tmp_path, dest):
    archive = tmp_path / "exe.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("malware.sh", "#!/bin/sh\necho ahoj\n")

    extract.extract(archive, "exe.zip", dest)

    mode = (dest / "malware.sh").stat().st_mode
    assert not mode & 0o111, "rozbaleny soubor si nechal x bit"


def test_original_zustava_nedotceny(tmp_path, dest):
    archive = tmp_path / "clean.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.txt", "obsah")
    before = archive.read_bytes()

    extract.extract(archive, "clean.zip", dest)

    assert archive.read_bytes() == before
