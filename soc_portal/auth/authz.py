"""Autorizacni brana: autentizace != autorizace.

Access-manager rekne "jsi to ty" (outcome=ok). Jestli SMIS do tohoto portalu,
rozhodujeme MY - clenstvim v pozadovane skupine. Fail-closed: kdo v ni neni,
dovnitr nesmi, i kdyz se TOTP overil.

Realm resime uz na urovni klice aplikace (verify_key() na startu overi, ze nas
klic patri spravnemu realmu), takze tady staci kontrola skupiny.
"""
from __future__ import annotations

from .provider import Identity


def is_authorized(identity: Identity, required_group: str) -> bool:
    return f"group:{required_group}" in identity.principals
