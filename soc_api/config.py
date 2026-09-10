"""Konfigurace soc-api.

Vsechno jde prebit promennou prostredi, aby se provoz nemusel sahat do kodu.
Vychozi hodnoty jsou ty dohodnute: 50 MB na vzorek, zadna automaticka retence.
"""
from __future__ import annotations

import os
from pathlib import Path

# ── uloziste ─────────────────────────────────────────────────────────────────
# Vault lezi ZAMERNE mimo /www/soc/public_html. Kdyby byl pod webrootem,
# byl by kazdy prijaty vzorek stazitelny z internetu pres staticky web.
VAULT = Path(os.environ.get("SOC_VAULT", "/www/soc/vault"))

# ── limity prijmu ────────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES = int(os.environ.get("SOC_MAX_UPLOAD", 50 * 1024 * 1024))

# ── limity rozbalovani (obrana proti dekompresnim bombam) ────────────────────
# Tri nezavisle stropy: celkova velikost, pomer k originalu a pocet polozek.
# Bomba obvykle prekroci jeden z nich davno pred tim, nez dojde misto na disku.
MAX_EXTRACT_BYTES = int(os.environ.get("SOC_MAX_EXTRACT", 1024 * 1024 * 1024))
MAX_EXTRACT_RATIO = int(os.environ.get("SOC_MAX_RATIO", 100))
MAX_EXTRACT_FILES = int(os.environ.get("SOC_MAX_FILES", 10_000))

# ── access-manager ───────────────────────────────────────────────────────────
AM_URL = os.environ.get("SOC_AM_URL", "http://127.0.0.1:22000")
AM_REALM = os.environ.get("SOC_AM_REALM", "soc.autumnpartials.com")

# Kratka cache verdiktu o klici. Odvolani klice se projevi az po jejim vyprseni
# - proto vteriny, ne minuty. Bez cache by kazdy upload znamenal kolo po siti.
AM_CACHE_S = int(os.environ.get("SOC_AM_CACHE_S", 30))

# ── sit ──────────────────────────────────────────────────────────────────────
BIND_HOST = os.environ.get("SOC_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("SOC_BIND_PORT", 8095))

# Odkud smi prijit X-Forwarded-For, kteremu verime. Pred nami stoji jen nginx
# na tomtez stroji; cokoli jineho si smi hlavicku psat jak chce a nesmi se ji
# verit, protoze urcuje origin poslany do access-manageru.
TRUSTED_PROXIES = tuple(
    p.strip() for p in os.environ.get("SOC_TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if p.strip()
)

# Kolik mista musi na vaultu zustat volne, aby se prijimaly nove vzorky.
# Vault roste bez retence, takze bez teto pojistky by se disk jednou zaplnil
# a sluzba by zacala selhavat az uprostred zapisu.
MIN_FREE_BYTES = int(os.environ.get("SOC_MIN_FREE", 2 * 1024 * 1024 * 1024))

# ── logy ─────────────────────────────────────────────────────────────────────
# Adresar pro access.log sluzby. Prazdna hodnota = pise se jen na stdout
# (a odtud do logu kontejneru). V kontejneru se sem montuje adresar
# z hostitele, takze zaznamy prezijou i smazani kontejneru.
#
# Rotace je vlastni (RotatingFileHandler), ne logrotate: v kontejneru zadny
# logrotate nebezi a na hostiteli by musel umet dat sluzbe vedet.
LOG_DIR = os.environ.get("SOC_LOG_DIR", "")
LOG_MAX_BYTES = int(os.environ.get("SOC_LOG_MAX_BYTES", 50 * 1024 * 1024))
LOG_BACKUPS = int(os.environ.get("SOC_LOG_BACKUPS", 10))

# ── vypisy ───────────────────────────────────────────────────────────────────
DEFAULT_LIMIT = 20
MAX_LIMIT = 200
