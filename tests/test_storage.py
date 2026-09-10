"""Uloziste: obsahove adresovani, hashe, access.log."""
from __future__ import annotations

import io

import pytest

from soc_api import config, storage


@pytest.fixture(autouse=True)
def vault(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT", tmp_path / "vault")
    return config.VAULT


def test_jmeno_souboru_je_vstup_od_klienta(tmp_path):
    """Z puvodniho jmena se bere jen holy zaklad."""
    assert storage.safe_filename("../../etc/passwd") == "passwd"
    assert storage.safe_filename("C:\\Windows\\evil.exe") == "evil.exe"
    # metaznaky shellu se nahradi podtrzitkem
    assert storage.safe_filename("a b;rm -rf.zip") == "a_b_rm_-rf.zip"
    # skryty soubor se skrytym byt neprestane jmenovat, ale prestane byt skryty
    assert storage.safe_filename(".bashrc") == "bashrc"
    assert storage.safe_filename("") == "sample.bin"
    assert storage.safe_filename(None) == "sample.bin"
    assert storage.safe_filename("...") == "sample.bin"
    # vse pred poslednim lomitkem je cesta, ne jmeno - basename ji zahodi
    assert storage.safe_filename("a/b/c/sample.zip") == "sample.zip"


def test_prijem_pocita_vsechny_tri_hashe():
    data = b"testovaci vzorek"
    tmp, digests, over = storage.receive(io.BytesIO(data), max_bytes=1024)

    assert not over
    assert digests["size"] == len(data)
    assert len(digests["sha256"]) == 64
    assert len(digests["sha1"]) == 40
    assert len(digests["md5"]) == 32
    assert tmp.read_bytes() == data


def test_prekroceni_limitu_se_pozna_hned():
    tmp, digests, over = storage.receive(io.BytesIO(b"x" * 5000), max_bytes=100)
    assert over


def test_tentyz_obsah_ma_tutez_cestu():
    """Obsahove adresovani: identita vzorku je jeho sha256."""
    a = storage.receive(io.BytesIO(b"stejny obsah"), 1024)[1]["sha256"]
    b = storage.receive(io.BytesIO(b"stejny obsah"), 1024)[1]["sha256"]

    assert a == b
    assert storage.sample_dir(a) == storage.sample_dir(b)


def test_sharding_podle_dvou_znaku():
    sha = "ab" + "c" * 62
    assert storage.sample_dir(sha).parent.name == "ab"


def test_access_log_je_jeden_radek_jedna_udalost():
    sha = "a" * 64
    storage.log_event(sha, {"event": "upload", "remote_ip": "192.0.2.1"})
    storage.log_event(sha, {"event": "extract", "status": "extracted"})

    events = storage.read_events(sha)

    assert [e["event"] for e in events] == ["upload", "extract"]
    assert all("t" in e for e in events)


def test_manifest_se_zapisuje_atomicky():
    """Cteni nikdy nesmi videt polovicni JSON."""
    sha = "b" * 64
    storage.write_manifest(sha, {"sha256": sha, "state": "received"})
    storage.write_manifest(sha, {"sha256": sha, "state": "extracted"})

    assert storage.read_manifest(sha)["state"] == "extracted"
    # zadny docasny soubor nezustal lezet
    assert not list(storage.sample_dir(sha).glob(".manifest-*"))
