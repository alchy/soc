"""MockAuthProvider + autorizacni brana (autentizace != autorizace)."""
import logging

from soc_portal.auth import authz
from soc_portal.auth.mock import MockAuthProvider
from soc_portal.auth.provider import Identity

_LOG = logging.getLogger("test")


def _provider():
    return MockAuthProvider("jindrich", "demo", "users", _LOG)


def test_mock_login_ok():
    r = _provider().authenticate("jindrich", "demo", "1.2.3.4")
    assert r.ok
    assert r.identity.subject_id == "user:jindrich"
    assert authz.is_authorized(r.identity, "users")


def test_mock_wrong_password_denied():
    assert not _provider().authenticate("jindrich", "spatne", "1.2.3.4").ok


def test_mock_wrong_user_denied():
    assert not _provider().authenticate("nekdo", "demo", "1.2.3.4").ok


def test_authz_denies_user_outside_group():
    ident = Identity("user:ucetni", ("group:ucetni", "user:ucetni"))
    assert not authz.is_authorized(ident, "users")
