"""Nase server-side session nad podepsanou Flask cookie.

Flask cookie je jen PODEPSANA (ne sifrovana) - proto do ni davame vyhradne
needucitelne udaje (subject_id, principals, casova razitka), zadne tajemstvi.
Zivotnost hlidame sami, protoze chceme DVA nezavisle stropy:

    abs_ttl  = absolutni strop od prihlaseni (delka smeny)
    idle_ttl = strop necinnosti (od posledniho pozadavku)

Cas bereme jako celociselny UNIX epoch (monotonie tu neni potreba a epoch se
snadno testuje). `touch` posouva jen idle, nikdy ne absolutni strop.
"""
from __future__ import annotations

import time

from flask import session

from .provider import Identity

_SUB = "sub"
_PRINCIPALS = "principals"
_IAT = "iat"    # issued-at
_SEEN = "seen"  # last-seen


def establish(identity: Identity) -> None:
    """Zalozi novou session po uspesnem prihlaseni + autorizaci."""
    now = int(time.time())
    session.clear()
    session[_SUB] = identity.subject_id
    session[_PRINCIPALS] = list(identity.principals)
    session[_IAT] = now
    session[_SEEN] = now
    session.permanent = True  # cookie prezije zavreni tabu; TTL resime sami nize


def current(abs_ttl_s: int, idle_ttl_s: int, now: int | None = None) -> Identity | None:
    """Vrati platnou Identity, nebo None kdyz session chybi/vyprsela.

    Pri platne session posune `seen` (klouzavy idle timeout). `now` jde vlozit
    kvuli testum.
    """
    if _SUB not in session:
        return None
    now = int(time.time()) if now is None else now

    if now - session.get(_IAT, 0) > abs_ttl_s:
        session.clear()
        return None
    if now - session.get(_SEEN, 0) > idle_ttl_s:
        session.clear()
        return None

    session[_SEEN] = now
    return Identity(session[_SUB], tuple(session.get(_PRINCIPALS, [])))


def destroy() -> None:
    session.clear()
