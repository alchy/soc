"""MockAuthProvider - prihlaseni pro vyvoj a demo (jindrich/demo).

Nenahrazuje bezpecnost, jen odblokuje stavbu UI drive, nez mame klic k AM.
Vydava identitu s clenstvim v pozadovane skupine, aby prosla i autorizacni brana.
"""
from __future__ import annotations

import hmac
import logging

from ..logging_setup import event
from .provider import DENIED, OK, AuthResult, Identity


class MockAuthProvider:
    name = "mock"
    credential_label = "Password (demo)"

    def __init__(self, user: str, password: str, group: str, log: logging.Logger):
        self._user = user
        self._password = password
        self._group = group
        self._log = log

    def authenticate(self, username: str, credential: str, client_ip: str) -> AuthResult:
        # hmac.compare_digest: konstantni cas, at se heslo nedа uhodnout casem odezvy.
        ok_user = hmac.compare_digest(username or "", self._user)
        ok_pass = hmac.compare_digest(credential or "", self._password)
        if ok_user and ok_pass:
            ident = Identity(
                subject_id=f"user:{username}",
                principals=(f"group:{self._group}", f"user:{username}"),
            )
            event(self._log, logging.INFO, "login_ok", backend="mock",
                  user=username, remote_ip=client_ip)
            return AuthResult(OK, identity=ident)

        event(self._log, logging.WARNING, "login_denied", backend="mock",
              user=username, remote_ip=client_ip, reason="bad_credentials")
        return AuthResult(DENIED, reason="bad_credentials")
