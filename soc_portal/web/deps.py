"""Sdilene zavislosti rout: prihlaseni-nutne guard, klient IP, pristup k provideru.

Drzi web vrstvu tenkou - routy se nestaraji o mechaniku session ani proxy.
"""
from __future__ import annotations

from functools import wraps

from flask import current_app, g, redirect, request, url_for

from .. import config
from ..auth import session as session_mod


def client_ip() -> str:
    """Skutecna adresa klienta. Za nginx ji doda ProxyFix z X-Forwarded-For
    (viz create_app); `remote_addr` uz je pak realny klient, ne proxy."""
    return request.remote_addr or "-"


def provider():
    """Aktivni AuthProvider (mock nebo access_manager), vlozeny v create_app."""
    return current_app.config["AUTH_PROVIDER"]


def login_required(view):
    """Pusti dal jen s platnou session; jinak presmeruje na /login s navratem."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        identity = session_mod.current(config.SESSION_ABS_TTL_S, config.SESSION_IDLE_S)
        if identity is None:
            return redirect(url_for("auth.login", next=request.full_path))
        g.identity = identity  # k dispozici sablonam pres context processor
        return view(*args, **kwargs)
    return wrapped
