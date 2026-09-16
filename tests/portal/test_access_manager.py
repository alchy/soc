"""AccessManagerAuthProvider: mapovani verdiktu AM na AuthResult.

Sit se nedotykame - monkeypatchem podstrcime _post/_get, presne jak to dela
soc-api ve svych testech. Nepotrebujeme bezici access-manager.
"""
import logging

import pytest

from soc_portal.auth.access_manager import (AccessManagerAuthProvider,
                                            AccessManagerError)
from soc_portal.auth.provider import DENIED, ERROR, OK, THROTTLED

_LOG = logging.getLogger("test")


def _provider():
    return AccessManagerAuthProvider(
        url="http://am.local", auth_path="/v1/authenticate",
        whoami_path="/v1/whoami", key="am_k4_test",
        realm="soc.autumnpartials.com", timeout_s=5, log=_LOG)


def test_outcome_ok(monkeypatch):
    p = _provider()
    monkeypatch.setattr(p, "_post", lambda path, body: {
        "outcome": "ok", "subject_id": "user:portaldemo",
        "principals": ["group:public", "group:users", "user:portaldemo"], "gen": 41})
    r = p.authenticate("portaldemo", "825633", "193.0.231.250")
    assert r.outcome == OK
    assert r.identity.subject_id == "user:portaldemo"
    assert "group:users" in r.identity.principals


def test_outcome_denied(monkeypatch):
    p = _provider()
    monkeypatch.setattr(p, "_post", lambda path, body: {"outcome": "denied", "gen": 41})
    assert p.authenticate("portaldemo", "000000", "1.2.3.4").outcome == DENIED


def test_outcome_throttled(monkeypatch):
    p = _provider()
    monkeypatch.setattr(p, "_post", lambda path, body: {
        "outcome": "throttled", "retry_after": 27, "gen": 41})
    r = p.authenticate("portaldemo", "000000", "1.2.3.4")
    assert r.outcome == THROTTLED
    assert r.retry_after == 27


def test_backend_error_is_not_denial(monkeypatch):
    p = _provider()

    def boom(path, body):
        raise AccessManagerError("access-manager nedostupny")

    monkeypatch.setattr(p, "_post", boom)
    # Nedostupny backend != spatny kod. Musime vratit ERROR, ne DENIED.
    assert p.authenticate("portaldemo", "825633", "1.2.3.4").outcome == ERROR


def test_verify_key_rejects_wrong_realm(monkeypatch):
    p = _provider()
    monkeypatch.setattr(p, "_get", lambda path: {"realm": "jiny.realm", "key_id": "k4"})
    with pytest.raises(AccessManagerError):
        p.verify_key()


def test_verify_key_accepts_matching_realm(monkeypatch):
    p = _provider()
    monkeypatch.setattr(p, "_get", lambda path: {
        "realm": "soc.autumnpartials.com", "key_id": "k4", "component": "soc-portal"})
    assert p.verify_key()["key_id"] == "k4"


def test_verify_key_rejects_wrong_component(monkeypatch):
    # Spravny realm, ale klic patri JINE aplikaci - fail-fast na startu.
    p = _provider()
    monkeypatch.setattr(p, "_get", lambda path: {
        "realm": "soc.autumnpartials.com", "key_id": "k9", "component": "jina-app"})
    with pytest.raises(AccessManagerError):
        p.verify_key()
