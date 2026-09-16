"""Session: zalozeni, klouzavy idle timeout, absolutni strop.

flask.session potrebuje request context - zakladame minimalni Flask app.
`now` do current() vlozime rucne, at se expirace testuje bez cekani.
"""
import time

from flask import Flask

from soc_portal.auth import session as S
from soc_portal.auth.provider import Identity


def _app():
    app = Flask(__name__)
    app.secret_key = "x" * 16
    return app


def test_establish_and_read_back():
    with _app().test_request_context():
        S.establish(Identity("user:portaldemo", ("group:users", "user:portaldemo")))
        got = S.current(3600, 1800)
        assert got is not None
        assert got.subject_id == "user:portaldemo"
        assert "group:users" in got.principals


def test_absolute_ttl_expires():
    with _app().test_request_context():
        S.establish(Identity("user:x"))
        future = int(time.time()) + 200
        assert S.current(abs_ttl_s=100, idle_ttl_s=100, now=future) is None


def test_idle_ttl_expires():
    with _app().test_request_context():
        S.establish(Identity("user:x"))
        future = int(time.time()) + 120
        assert S.current(abs_ttl_s=100000, idle_ttl_s=60, now=future) is None


def test_touch_extends_idle():
    with _app().test_request_context():
        S.establish(Identity("user:x"))
        base = int(time.time())
        # aktivita v ramci idle okna posune 'seen'
        assert S.current(abs_ttl_s=100000, idle_ttl_s=60, now=base + 30) is not None
        # dalsi pozadavek 30 s po te aktivite je stale v okne
        assert S.current(abs_ttl_s=100000, idle_ttl_s=60, now=base + 55) is not None


def test_no_session_returns_none():
    with _app().test_request_context():
        assert S.current(100, 100) is None


def test_destroy_clears():
    with _app().test_request_context():
        S.establish(Identity("user:x"))
        S.destroy()
        assert S.current(100, 100) is None
