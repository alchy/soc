"""Overeni volajiciho proti access-manageru.

Klient posila aplikacni klic realmu (`Authorization: Bearer am_k1_...`).
Overuje se u autority, ktera ho vydala - volanim `GET /v1/whoami`. Klic sam
nikam neukladame a do logu se nedostane.

Podstatny detail: pri tom volani se PREPOSILA skutecna adresa klienta
v `X-Forwarded-For`. Access-manager ji (jako duveryhodna proxy) pouzije pro
origin ACL komponenty, takze rozsahy u `socupload` omezuji, odkud smi vzorky
chodit - uniky klice mimo ne jsou bezcenne. Bez tohoto prepsani by se meril
nas vlastni server a origin ACL by nic neznamenal.
"""
from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
import json

from . import config

# key_hash -> (cas, verdikt). Klic sam se necachuje ani v pameti.
_cache: dict[str, tuple[float, dict | None]] = {}


class AuthError(Exception):
    def __init__(self, status: int, error: str, detail: str = ""):
        super().__init__(error)
        self.status = status
        self.error = error
        self.detail = detail


def _whoami(key: str, client_ip: str) -> dict | None:
    """Vraci telo /v1/whoami, nebo None kdyz klic neplati. 403 = origin ACL."""
    req = urllib.request.Request(
        f"{config.AM_URL}/v1/whoami",
        headers={"Authorization": f"Bearer {key}",
                 "X-Forwarded-For": client_ip},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise AuthError(403, "origin_denied",
                            "adresa neni v povolenych rozsazich klice") from e
        if e.code == 401:
            return None
        raise AuthError(502, "auth_backend_error", f"access-manager: HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise AuthError(502, "auth_backend_error", f"access-manager nedostupny: {e}") from e


def authenticate(key: str | None, client_ip: str) -> dict:
    """Overi klic a vrati {'component','realm','key_id'}. Jinak vyhodi AuthError."""
    if not key:
        raise AuthError(401, "unauthorized", "chybi hlavicka Authorization")

    # Cache je klicovana otiskem, aby se klic nedrzel v pameti v citelne podobe.
    # Klicem cache je i adresa - tyz klic z jine site musi projit origin ACL znovu.
    ck = hashlib.sha256(f"{key}|{client_ip}".encode()).hexdigest()
    hit = _cache.get(ck)
    if hit and time.monotonic() - hit[0] < config.AM_CACHE_S:
        if hit[1] is None:
            raise AuthError(401, "unauthorized", "neplatny klic")
        return hit[1]

    who = _whoami(key, client_ip)
    _cache[ck] = (time.monotonic(), who)

    if who is None:
        raise AuthError(401, "unauthorized", "neplatny klic")
    if who.get("realm") != config.AM_REALM:
        raise AuthError(403, "wrong_realm",
                        f"klic patri realmu {who.get('realm')}, ocekavan {config.AM_REALM}")
    return who
