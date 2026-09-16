"""Routy prihlaseni/odhlaseni.

Tenka slupka: precti formular -> provider.authenticate -> autorizacni brana ->
zaloz session. Vetveni podle outcome (denied/throttled/error/neopravnen) se mapuje
na srozumitelnou hlasku; detail duvodu se loguje, uzivateli se nedava vic, nez
potrebuje (nechceme napovidat, ktery udaj byl spatne).
"""
from __future__ import annotations

import logging

from flask import (Blueprint, current_app, redirect, render_template, request,
                   url_for)

from .. import config
from ..auth import authz
from ..auth import session as session_mod
from ..auth.provider import ERROR, OK, THROTTLED
from ..logging_setup import event
from .deps import client_ip, provider

bp = Blueprint("auth", name := "auth")

# Zpravy pro uzivatele - zamerne obecne (krome throttle, kde ma smysl rict "za N s").
_MSG_BAD = "Neplatne prihlaseni. Zkuste to znovu."
_MSG_BACKEND = "Overovaci sluzba je docasne nedostupna. Zkuste to za chvili."
_MSG_FORBIDDEN = "Overeno, ale nemate opravneni do tohoto portalu."


def _is_safe_next(target: str | None) -> bool:
    """Otevreny redirect je klasicka dira - povolime jen lokalni cestu."""
    return bool(target) and target.startswith("/") and not target.startswith("//")


@bp.get("/login")
def login():
    if session_mod.current(config.SESSION_ABS_TTL_S, config.SESSION_IDLE_S):
        return redirect(url_for("samples.dashboard"))
    return render_template("login.html", cred_label=provider().credential_label,
                           error=None, retry_after=None)


@bp.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    credential = request.form.get("credential") or ""
    ip = client_ip()
    prov = provider()

    result = prov.authenticate(username, credential, ip)

    def fail(message, status=401, retry_after=None):
        return render_template("login.html", cred_label=prov.credential_label,
                               error=message, retry_after=retry_after), status

    if result.outcome == THROTTLED:
        return fail(f"Prilis mnoho pokusu. Zkuste to za {result.retry_after} s.",
                    status=429, retry_after=result.retry_after)
    if result.outcome == ERROR:
        return fail(_MSG_BACKEND, status=502)
    if result.outcome != OK or result.identity is None:
        return fail(_MSG_BAD)

    # Autentizace prosla - ted autorizace (clenstvi ve skupine). Fail-closed.
    if not authz.is_authorized(result.identity, config.REQUIRED_GROUP):
        event(current_app.logger_soc, logging.WARNING, "authz_denied",
              subject_id=result.identity.subject_id, remote_ip=ip,
              required_group=config.REQUIRED_GROUP)
        return fail(_MSG_FORBIDDEN, status=403)

    session_mod.establish(result.identity)
    event(current_app.logger_soc, logging.INFO, "session_established",
          subject_id=result.identity.subject_id, remote_ip=ip)

    nxt = request.args.get("next")
    return redirect(nxt if _is_safe_next(nxt) else url_for("samples.dashboard"))


@bp.post("/logout")
def logout():
    session_mod.destroy()
    return redirect(url_for("auth.login"))
