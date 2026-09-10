"""Overeni volajiciho u access-manageru.

Bezi bez site - odpovedi access-manageru se podstrcuji. Jde o to, jak se
jeho verdikty prekladaji na chovani sluzby, ne o nej sameho.
"""
from __future__ import annotations

import urllib.error

import pytest

from soc_api import auth, config


@pytest.fixture(autouse=True)
def cista_cache():
    auth._cache.clear()
    yield
    auth._cache.clear()


def whoami(monkeypatch, odpoved):
    """Podstrci odpoved access-manageru; `odpoved` smi byt i vyjimka."""
    volani = []

    def falesny(key, ip):
        volani.append((key, ip))
        if isinstance(odpoved, Exception):
            raise odpoved
        return odpoved

    monkeypatch.setattr(auth, "_whoami", falesny)
    return volani


OK = {"component": "socupload", "key_id": "k1", "realm": config.AM_REALM}


def test_platny_klic_projde(monkeypatch):
    whoami(monkeypatch, OK)
    assert auth.authenticate("am_k1_x", "192.0.2.1")["component"] == "socupload"


def test_chybejici_klic_je_401(monkeypatch):
    whoami(monkeypatch, OK)
    with pytest.raises(auth.AuthError) as e:
        auth.authenticate(None, "192.0.2.1")
    assert e.value.status == 401


def test_neplatny_klic_je_401(monkeypatch):
    whoami(monkeypatch, None)
    with pytest.raises(auth.AuthError) as e:
        auth.authenticate("am_k1_cizi", "192.0.2.1")
    assert e.value.status == 401


def test_klic_z_jineho_realmu_je_403(monkeypatch):
    whoami(monkeypatch, {**OK, "realm": "jiny.example.com"})
    with pytest.raises(auth.AuthError) as e:
        auth.authenticate("am_k1_x", "192.0.2.1")
    assert e.value.status == 403 and e.value.error == "wrong_realm"


def test_nedostupny_access_manager_je_502(monkeypatch):
    whoami(monkeypatch, auth.AuthError(502, "auth_backend_error", "nedostupny"))
    with pytest.raises(auth.AuthError) as e:
        auth.authenticate("am_k1_x", "192.0.2.1")
    assert e.value.status == 502


# ── cache ───────────────────────────────────────────────────────────────────

def test_druhe_volani_jde_z_cache(monkeypatch):
    volani = whoami(monkeypatch, OK)

    auth.authenticate("am_k1_x", "192.0.2.1")
    auth.authenticate("am_k1_x", "192.0.2.1")

    assert len(volani) == 1, "druhy dotaz mel prijit z cache"


def test_tyz_klic_z_jine_adresy_se_overi_znovu(monkeypatch):
    """Jinak by cache obchazela origin ACL."""
    volani = whoami(monkeypatch, OK)

    auth.authenticate("am_k1_x", "192.0.2.1")
    auth.authenticate("am_k1_x", "198.51.100.9")

    assert len(volani) == 2


def test_cache_vyprsi(monkeypatch):
    volani = whoami(monkeypatch, OK)
    monkeypatch.setattr(config, "AM_CACHE_S", 0)

    auth.authenticate("am_k1_x", "192.0.2.1")
    auth.authenticate("am_k1_x", "192.0.2.1")

    assert len(volani) == 2


def test_cache_si_nepamatuje_klic_v_citelne_podobe(monkeypatch):
    whoami(monkeypatch, OK)
    auth.authenticate("am_k1_tajemstvi", "192.0.2.1")

    assert not any("am_k1_tajemstvi" in k for k in auth._cache), \
        "klic se nesmi drzet v pameti v citelne podobe"


def test_odmitnuti_se_cachuje_taky(monkeypatch):
    volani = whoami(monkeypatch, None)

    for _ in range(2):
        with pytest.raises(auth.AuthError):
            auth.authenticate("am_k1_cizi", "192.0.2.1")

    assert len(volani) == 1
