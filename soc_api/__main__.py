"""Spusteni sluzby: python -m soc_api

TLS terminuje nginx pred nami, tady stoji holy waitress na smycce.
"""
from waitress import serve

from . import config
from .app import app

if __name__ == "__main__":
    serve(app, host=config.BIND_HOST, port=config.BIND_PORT,
          # 50 MB telo se nesmi utnout na kratkem timeoutu pomale linky
          channel_timeout=300, cleanup_interval=60, ident="soc-api")
