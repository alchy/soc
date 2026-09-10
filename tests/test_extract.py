"""Obrany rozbalovaci vrstvy.

Kazdy test tu odpovida na otazku "co kdyz je archiv nepratelsky" - to je
jediny druh archivu, ktery tahle sluzba dostava.
"""
from __future__ import annotations

import os
import subprocess
import tarfile
import zipfile

import pytest

from soc_api import config, extract


@pytest.fixture
def dest(tmp_path):
    return tmp_path / "extracted"


def test_zip_slip_nezapise_ven(tmp_path, dest):
    """Polozka s `../` nesmi opustit cilovy adresar."""
    archive = tmp_path / "slip.zip"
    outside = tmp_path / "PWNED.txt"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../PWNED.txt", "uteklo ven")
        z.writestr("ok.txt", "v poradku")

    result = extract.extract(archive, dest)

    assert not outside.exists(), "zip-slip zapsal soubor mimo cilovy adresar"
    assert result.status == "extracted"
    assert result.file_count == 1
    assert any("mimo adresar" in s for s in result.skipped)


def test_absolutni_cesta_je_odmitnuta(tmp_path, dest):
    archive = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("/etc/passwd", "ne")
        z.writestr("ok.txt", "ano")

    result = extract.extract(archive, dest)

    assert result.file_count == 1
    assert (dest / "ok.txt").exists()


def test_tar_symlink_se_preskoci(tmp_path, dest):
    """Symlink by mohl ukazovat kamkoli - na disk se nedostane."""
    archive = tmp_path / "link.tar"
    with tarfile.open(archive, "w") as t:
        info = tarfile.TarInfo("odkaz")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/shadow"
        t.addfile(info)

        payload = tmp_path / "data.txt"
        payload.write_text("obycejny obsah")
        t.add(payload, arcname="data.txt")

    result = extract.extract(archive, dest)

    assert not (dest / "odkaz").is_symlink()
    assert result.file_count == 1
    assert any("odkaz" in s for s in result.skipped)


def test_dekompresni_bomba_se_zastavi(tmp_path, dest, monkeypatch):
    """Prekroceni pomeru dekomprese zastavi rozbalovani, nedojde misto."""
    monkeypatch.setattr(config, "MAX_EXTRACT_RATIO", 5)

    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("velky.bin", b"\0" * (2 * 1024 * 1024))

    result = extract.extract(archive, dest)

    assert result.status == "cannot_decompress"
    assert "pomer" in result.info


def test_prilis_mnoho_polozek(tmp_path, dest, monkeypatch):
    monkeypatch.setattr(config, "MAX_EXTRACT_FILES", 3)

    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for i in range(10):
            z.writestr(f"f{i}.txt", "x")

    result = extract.extract(archive, dest)

    assert result.status == "cannot_decompress"
    assert "polozek" in result.info


@pytest.mark.skipif(subprocess.run(["which", "zip"], capture_output=True).returncode != 0,
                    reason="nastroj zip neni k dispozici")
def test_heslovany_archiv_se_nehada(tmp_path, dest):
    """Heslo se NEHADA - vzorek dostane stav a lidsky duvod."""
    payload = tmp_path / "tajne.txt"
    payload.write_text("obsah")
    archive = tmp_path / "secret.zip"
    subprocess.run(["zip", "-q", "-P", "infected", str(archive), str(payload)],
                   check=True, cwd=tmp_path)

    result = extract.extract(archive, dest)

    assert result.status == "cannot_decompress"
    assert "heslem" in result.info


def test_neni_archiv(tmp_path, dest):
    plain = tmp_path / "vzorek.bin"
    plain.write_bytes(b"MZ\x90\x00 tohle neni archiv")

    result = extract.extract(plain, dest)

    assert result.status == "not_an_archive"


def test_poskozeny_archiv(tmp_path, dest):
    archive = tmp_path / "broken.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.txt", "obsah")
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0xFF          # rozbij prostredek
    archive.write_bytes(bytes(data))

    result = extract.extract(archive, dest)

    assert result.status in ("corrupt", "cannot_decompress")


def test_rozbalene_soubory_nejsou_spustitelne(tmp_path, dest):
    archive = tmp_path / "exe.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("malware.sh", "#!/bin/sh\necho ahoj\n")

    extract.extract(archive, dest)

    mode = (dest / "malware.sh").stat().st_mode
    assert not mode & 0o111, "rozbaleny soubor si nechal x bit"


def test_original_zustava_nedotceny(tmp_path, dest):
    archive = tmp_path / "clean.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("a.txt", "obsah")
    before = archive.read_bytes()

    extract.extract(archive, dest)

    assert archive.read_bytes() == before
