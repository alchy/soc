"""AccessManagerAuthProvider - realne overeni uzivatele pres TOTP.

Kontrakt (viz https://github.com/alchy/access-manager, docs/api.md):

    POST /v1/authenticate     Authorization: Bearer <klic aplikace>
    { "username": ..., "credentials": {"totp": ...},
      "purpose": "login", "client_origin": "<ip klienta>" }

    -> vzdy HTTP 200, vetvime podle "outcome":
       ok         {subject_id, principals[], gen}
       denied     {gen}  (+reason kdyz detail)
       need_factor{required[], gen}
       throttled  {retry_after, gen}   <- lockout resi AM, my jen cecekeame

DULEZITE: "Nedostanete relaci, dostanete verdikt." Session si portal spravuje
sam (viz session.py). Anti-replay je per `purpose`, proto posilame purpose="login".
Klic ani TOTP se NIKDY nedostanou do logu.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from ..logging_setup import event
from .provider import (DENIED, ERROR, NEED_FACTOR, OK, THROTTLED, AuthResult,
                       Identity)


class AccessManagerError(Exception):
    pass


class AccessManagerAuthProvider:
    name = "access_manager"
    credential_label = "TOTP kod"

    def __init__(self, url: str, auth_path: str, whoami_path: str, key: str,
                 realm: str, timeout_s: int, log: logging.Logger,
                 call_origin: str = "127.0.0.1", component: str = "soc-portal"):
        self._url = url.rstrip("/")
        self._auth_path = auth_path
        self._whoami_path = whoami_path
        self._key = key
        self._realm = realm
        self._timeout = timeout_s
        self._log = log
        # X-Forwarded-For pro origin ACL klice - AM bez nej vraci 403 forbidden.
        self._call_origin = call_origin
        # Ocekavana komponenta klice - startovni kontrola v verify_key().
        self._component = component

    # ── verejne API ──────────────────────────────────────────────────────────
    def authenticate(self, username: str, credential: str, client_ip: str) -> AuthResult:
        body = {
            "username": username,
            "credentials": {"totp": credential},
            "purpose": "login",
            "client_origin": client_ip,
        }
        try:
            resp = self._post(self._auth_path, body)
        except AccessManagerError as e:
            # Backend nedostupny NENI zamitnuti - nechceme uzivateli rikat
            # "spatny kod", kdyz je problem u nas. Logujeme jako chybu procesu.
            event(self._log, logging.ERROR, "auth_backend_error",
                  user=username, remote_ip=client_ip, detail=str(e))
            return AuthResult(ERROR, reason="auth_backend_error")

        outcome = resp.get("outcome")
        if outcome == OK:
            ident = Identity(
                subject_id=resp.get("subject_id", f"user:{username}"),
                principals=tuple(resp.get("principals", [])),
            )
            event(self._log, logging.INFO, "login_ok", backend="access_manager",
                  user=username, subject_id=ident.subject_id, remote_ip=client_ip,
                  gen=resp.get("gen"))
            return AuthResult(OK, identity=ident)

        if outcome == THROTTLED:
            retry = int(resp.get("retry_after", 0))
            event(self._log, logging.WARNING, "login_throttled",
                  user=username, remote_ip=client_ip, retry_after=retry)
            return AuthResult(THROTTLED, retry_after=retry)

        if outcome == NEED_FACTOR:
            return AuthResult(NEED_FACTOR, reason="need_factor")

        # denied (nebo neznamy outcome - fail-closed jako zamitnuti)
        reason = resp.get("reason", "")
        event(self._log, logging.WARNING, "login_denied", backend="access_manager",
              user=username, remote_ip=client_ip, reason=reason or outcome)
        return AuthResult(DENIED, reason=reason)

    def verify_key(self) -> dict:
        """Startovni self-check: overi, ze nas klic plati a patri spravnemu realmu.

        Vyhodi AccessManagerError - volajici (__main__) na tom fail-fast zastavi
        start, at nezjistime az pri prvnim prihlaseni, ze klic je spatny.
        """
        who = self._get(self._whoami_path)
        realm = who.get("realm")
        if realm != self._realm:
            raise AccessManagerError(
                f"klic patri realmu {realm!r}, ocekavan {self._realm!r}")
        component = who.get("component")
        if component != self._component:
            raise AccessManagerError(
                f"klic patri komponente {component!r}, ocekavana {self._component!r}")
        return who

    # ── HTTP (urllib, stejne jako soc_api/auth.py - zadny requests navic) ─────
    def _request(self, method: str, path: str, body: dict | None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{self._url}{path}", data=data, method=method,
            headers={
                "Authorization": f"Bearer {self._key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                # Origin klice: AM nas (jako duveryhodnou proxy) meri podle XFF.
                # Bez nej 403 forbidden i s platnym klicem.
                "X-Forwarded-For": self._call_origin,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            # /v1/authenticate vraci 200 vzdy; 401 tu znamena spatny klic aplikace.
            raise AccessManagerError(f"HTTP {e.code} z {path}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise AccessManagerError(f"access-manager nedostupny: {e}") from e

    def _post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, body)

    def _get(self, path: str) -> dict:
        return self._request("GET", path, None)
