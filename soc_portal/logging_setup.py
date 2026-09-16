"""Strukturovane logovani - jeden radek, jeden JSON objekt.

Zamerne stejny tvar jako u soc-api a access-manageru, aby se logy celeho
systemu daly cist a filtrovat stejne. Bezny provoz na stdout, potize na stderr
(triaz pres `grep stderr`). NIKDY nelogujeme TOTP kod ani aplikacni klic -
proto se do `event()` predavaji jen vyslovne vyjmenovana pole.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from . import config

LOGGER_NAME = "soc.portal"


class _JsonLine(logging.Formatter):
    def __init__(self, component: str):
        super().__init__()
        self._component = component

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "t": datetime.now(UTC).isoformat(timespec="seconds"),
            "level": record.levelname.lower(),
            "component": self._component,  # konfigurovatelne jmeno sluzby
            "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if fields:
            base.update(fields)
        return json.dumps(base, ensure_ascii=False, sort_keys=True)


def setup() -> logging.Logger:
    """Zalozi logger. Idempotentni - opakovane volani nezdvoji handlery."""
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False

    fmt = _JsonLine(config.SERVICE_NAME)

    out = logging.StreamHandler(sys.stdout)
    out.setFormatter(fmt)
    out.addFilter(lambda r: r.levelno < logging.WARNING)

    err = logging.StreamHandler(sys.stderr)
    err.setFormatter(fmt)
    err.setLevel(logging.WARNING)

    logger.addHandler(out)
    logger.addHandler(err)
    return logger


def event(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    """Strukturovana udalost. Priklad: event(log, logging.INFO, 'login_ok', user=..)."""
    logger.log(level, msg, extra={"fields": fields})
