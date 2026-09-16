"""Konfigurace soc-portal.

Vsechno jde prebit promennou prostredi - provoz se nesaha do kodu. Vychozi
hodnoty jsou bezpecne pro lokalni beh za nginx. Poradne veci (podpisovy klic
session, klic k access-manageru) se NEvalidji az za behu, ale hlasite na startu
- viz `validate()`. Rana a hlasita chyba > ticha diira.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


# ── uloziste (READ-ONLY mount vaultu) ────────────────────────────────────────
# Tentyz vault jako soc-api, ale montovany read-only. Portal jej nikdy nezapisuje.
VAULT = Path(_env("SOC_PORTAL_VAULT", "/vault"))

# ── access-manager (identita uzivatele) ──────────────────────────────────────
AM_URL = _env("SOC_PORTAL_AM_URL", "http://127.0.0.1:22000")
AM_AUTH_PATH = _env("SOC_PORTAL_AM_AUTH_PATH", "/v1/authenticate")
AM_WHOAMI_PATH = _env("SOC_PORTAL_AM_WHOAMI_PATH", "/v1/whoami")
AM_TIMEOUT_S = int(_env("SOC_PORTAL_AM_TIMEOUT_S", "5"))
AM_KEY = _env("SOC_PORTAL_AM_KEY")  # token aplikace; povinny pri access_manager

# Origin ACL: access-manager overuje, ODKUD se nas klic pouziva - podle
# X-Forwarded-For, ktere jako duveryhodna proxy dostane. Portal proto pri KAZDEM
# volani AM posila XFF se svou vlastni adresou (musi byt v ACL klice). Bez toho
# vraci AM 403 forbidden (overeno). Adresa uzivatele jde zvlast v tele (client_origin).
AM_CALL_ORIGIN = _env("SOC_PORTAL_AM_CALL_ORIGIN", "127.0.0.1")

# Jmeno teto sluzby/komponenty. Jediny zdroj pravdy pro: (1) pole "component"
# ve strukturovanych logach, (2) startovni kontrolu, ze nas klic opravdu patri
# teto aplikaci - AM /v1/whoami vraci "component" a my ho proti tomuto porovname.
SERVICE_NAME = _env("SOC_PORTAL_SERVICE_NAME", "soc-portal")

# ── autorizace (autentizace != autorizace) ───────────────────────────────────
# Uspesne TOTP overeni rika "jsi to ty", NE "smis sem". Do portalu pustime jen
# clena teto skupiny v tomto realmu. Fail-closed: neni-li v ni, dovnitr nesmi.
REALM = _env("SOC_PORTAL_REALM", "soc.autumnpartials.com")
# Realny slug skupiny v realmu je "user" (jednotne cislo) - overeno s klientem.
REQUIRED_GROUP = _env("SOC_PORTAL_REQUIRED_GROUP", "user")

# ── vyber providera (jednoradkovy prepinac mock <-> realny AM) ────────────────
AUTH_BACKEND = _env("SOC_PORTAL_AUTH_BACKEND", "mock")  # "mock" | "access_manager"

# Mock prihlaseni pro vyvoj/demo. V produkci se AUTH_BACKEND prepne na
# access_manager a tyto hodnoty se ignoruji.
MOCK_USER = _env("SOC_PORTAL_MOCK_USER", "jindrich")
MOCK_PASSWORD = _env("SOC_PORTAL_MOCK_PASSWORD", "demo")

# ── session (nase, ne AM: "nedostanete relaci, dostanete verdikt") ────────────
SESSION_COOKIE = _env("SOC_PORTAL_SESSION_COOKIE", "soc_portal_session")
SESSION_SECRET = _env("SOC_PORTAL_SESSION_SECRET")  # podpis cookie; povinny
SESSION_ABS_TTL_S = int(_env("SOC_PORTAL_SESSION_ABS_TTL_S", str(8 * 3600)))
SESSION_IDLE_S = int(_env("SOC_PORTAL_SESSION_IDLE_S", str(30 * 60)))
# Za nginx s TLS chceme Secure cookie; pri lokalnim http vyvoji ji lze vypnout.
SESSION_SECURE = _env("SOC_PORTAL_SESSION_SECURE", "1") == "1"

# ── sit / proxy (stejna disciplina jako soc-api) ──────────────────────────────
BIND_HOST = _env("SOC_PORTAL_BIND_HOST", "127.0.0.1")
BIND_PORT = int(_env("SOC_PORTAL_BIND_PORT", "8096"))
# Pred nami stoji jen nginx na tomtez stroji. Duverujeme jednomu X-Forwarded-For
# hopu, abychom v auditu i v client_origin meli skutecnou adresu klienta.
TRUSTED_PROXY_HOPS = int(_env("SOC_PORTAL_TRUSTED_PROXY_HOPS", "1"))

# ── vypisy ───────────────────────────────────────────────────────────────────
DEFAULT_LIMIT = int(_env("SOC_PORTAL_DEFAULT_LIMIT", "50"))
MAX_LIMIT = int(_env("SOC_PORTAL_MAX_LIMIT", "500"))

MIN_SECRET_LEN = 16


def validate() -> list[str]:
    """Vrati seznam fatalnich problemu konfigurace. Prazdny seznam = ok.

    Vola se na startu (viz __main__). Nechceme spadnout az pri prvnim prihlaseni
    uzivatele kvuli chybejicimu klici nebo slabemu podpisovemu tajemstvi.
    """
    problems: list[str] = []

    if not SESSION_SECRET or len(SESSION_SECRET) < MIN_SECRET_LEN:
        problems.append(
            f"SOC_PORTAL_SESSION_SECRET musi mit aspon {MIN_SECRET_LEN} znaku "
            "(podpisuje session cookie)")

    if AUTH_BACKEND not in ("mock", "access_manager"):
        problems.append(f"neznamy SOC_PORTAL_AUTH_BACKEND={AUTH_BACKEND!r}")

    if AUTH_BACKEND == "access_manager" and not AM_KEY:
        problems.append(
            "SOC_PORTAL_AM_KEY je povinny pri SOC_PORTAL_AUTH_BACKEND=access_manager")

    if SESSION_IDLE_S > SESSION_ABS_TTL_S:
        problems.append(
            "SOC_PORTAL_SESSION_IDLE_S nesmi byt vetsi nez SOC_PORTAL_SESSION_ABS_TTL_S")

    return problems
