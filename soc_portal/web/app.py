"""Kompozicni koren: sestavi Flask aplikaci, vlozi provider, zapoji vrstvy.

Zde se rozhoduje jedina vec navic oproti "obycejnemu" Flasku: ktery AuthProvider
bezi (mock vs. access_manager). Zamena je jeden radek v build_provider().
"""
from __future__ import annotations

import logging
import secrets

from flask import Flask, g
from werkzeug.middleware.proxy_fix import ProxyFix

from .. import config, vault_reader
from ..auth.access_manager import AccessManagerAuthProvider
from ..auth.mock import MockAuthProvider
from ..logging_setup import event, setup
from . import routes_auth, routes_samples


def build_provider(log: logging.Logger):
    """Jednoradkovy prepinac identity. Pri access_manager overi klic uz TED
    (fail-fast): radeji spadnout na startu nez az uzivateli pri prihlaseni."""
    if config.AUTH_BACKEND == "access_manager":
        prov = AccessManagerAuthProvider(
            url=config.AM_URL, auth_path=config.AM_AUTH_PATH,
            whoami_path=config.AM_WHOAMI_PATH, key=config.AM_KEY,
            realm=config.REALM, timeout_s=config.AM_TIMEOUT_S, log=log,
            call_origin=config.AM_CALL_ORIGIN, component=config.SERVICE_NAME)
        who = prov.verify_key()  # vyhodi AccessManagerError pri spatnem klici/realmu
        event(log, logging.INFO, "am_key_ok", realm=who.get("realm"),
              key_id=who.get("key_id"), component=who.get("component"))
        return prov

    event(log, logging.WARNING, "using_mock_auth",
          hint="MockAuthProvider je jen pro vyvoj/demo, ne pro produkci")
    return MockAuthProvider(config.MOCK_USER, config.MOCK_PASSWORD,
                            config.REQUIRED_GROUP, log)


def create_app() -> Flask:
    log = setup()

    app = Flask(__name__)
    app.logger_soc = log  # strukturovany logger dostupny routam pres current_app

    # Podpis session cookie. V mock rezimu bez tajemstvi vygenerujeme docasne
    # (sessions neprezijou restart) a HLASITE varujeme - lepsi nez tichy default.
    secret = config.SESSION_SECRET
    if not secret:
        secret = secrets.token_urlsafe(32)
        event(log, logging.WARNING, "ephemeral_session_secret",
              hint="SOC_PORTAL_SESSION_SECRET neni nastaven; session neprezije restart")
    app.secret_key = secret

    app.config.update(
        SESSION_COOKIE_NAME=config.SESSION_COOKIE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=config.SESSION_SECURE,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=1024 * 1024,  # POST /login je maly; nic velkeho neprijimame
    )

    # Za nginx: skutecnou adresu klienta bereme z X-Forwarded-For (jeden duveryhodny
    # hop). Bez toho by remote_addr byla adresa proxy a audit i client_origin by lhaly.
    # x_proto: spravne https ve Secure cookie a redirectech.
    # x_prefix: kdyz nginx montuje portal pod /portal (hlavicka X-Forwarded-Prefix),
    #           url_for vygeneruje /portal/... - jinak by odkazy mirily na koren.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config.TRUSTED_PROXY_HOPS,
                            x_proto=config.TRUSTED_PROXY_HOPS,
                            x_prefix=config.TRUSTED_PROXY_HOPS)

    app.config["AUTH_PROVIDER"] = build_provider(log)

    # Drobne pomocky pro sablony
    app.jinja_env.filters["human_size"] = vault_reader.human_size

    @app.context_processor
    def inject_identity():
        return {"identity": g.get("identity")}

    app.register_blueprint(routes_auth.bp)
    app.register_blueprint(routes_samples.bp)

    event(log, logging.INFO, "app_ready", backend=config.AUTH_BACKEND,
          vault=str(config.VAULT), realm=config.REALM,
          required_group=config.REQUIRED_GROUP)
    return app
