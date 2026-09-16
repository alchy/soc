"""Spolecne nastaveni testu.

config.py cte prostredi pri importu - proto ho musime nastavit DRIV, nez se
kterykoli modul soc_portal naimportuje. conftest pytest nacte jako prvni.
"""
import os

os.environ.setdefault("SOC_PORTAL_SESSION_SECRET", "test-secret-0123456789abcdef")
os.environ.setdefault("SOC_PORTAL_VAULT", "/www/soc/vault")
os.environ.setdefault("SOC_PORTAL_AUTH_BACKEND", "mock")
os.environ.setdefault("SOC_PORTAL_SESSION_SECURE", "0")
