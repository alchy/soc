"""Spusteni portalu: python -m soc_portal

TLS terminuje nginx pred nami, tady stoji holy waitress na smycce (stejne jako
soc-api). Na startu tvrde zvalidujeme konfiguraci - radeji hlasity pad ted nez
tichou diru za behu.
"""
from __future__ import annotations

import sys

from . import config
from .logging_setup import setup


def main() -> int:
    log = setup()

    problems = config.validate()
    if problems:
        for p in problems:
            log.error("config_invalid", extra={"fields": {"problem": p}})
        return 2

    # Import az po validaci: create_app() pri access_manager rovnou overuje klic.
    from waitress import serve

    from .web.app import create_app
    try:
        app = create_app()
    except Exception as e:  # napr. AccessManagerError z verify_key()
        log.error("startup_failed", extra={"fields": {"detail": str(e)}})
        return 3

    serve(app, host=config.BIND_HOST, port=config.BIND_PORT,
          channel_timeout=120, cleanup_interval=60, ident="soc-portal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
