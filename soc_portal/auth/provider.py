"""Rozhrani autentizacniho provideru a jeho datove modely.

Zamerne bez Flasku a bez site - ciste jadro, testovatelne bez behu serveru.
`credential` je genericky: u mocku heslo, u access-manageru TOTP kod. Web vrstva
diky tomu nemusi vedet, ktery provider bezi.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Vysledky, ktere umi vratit authenticate(). Kopiruji verdikty access-manageru
# (ok/denied/need_factor/throttled) + nas vlastni "error" pro nedostupny backend.
OK = "ok"
DENIED = "denied"
NEED_FACTOR = "need_factor"
THROTTLED = "throttled"
ERROR = "error"


@dataclass(frozen=True)
class Identity:
    """Kdo je uzivatel. `principals` je tranzitivni uzaver clenstvi ze skupin
    (napr. ('group:users', 'user:portaldemo')) - pouziva ho autorizacni brana."""
    subject_id: str
    principals: tuple[str, ...] = field(default_factory=tuple)

    @property
    def display_name(self) -> str:
        return self.subject_id.split(":", 1)[-1] if ":" in self.subject_id else self.subject_id


@dataclass(frozen=True)
class AuthResult:
    outcome: str
    identity: Identity | None = None
    reason: str = ""       # detail zamitnuti (bad_code, unknown_user, replay, ...)
    retry_after: int = 0   # sekundy, jen u THROTTLED

    @property
    def ok(self) -> bool:
        return self.outcome == OK


@runtime_checkable
class AuthProvider(Protocol):
    name: str
    credential_label: str  # popisek pole ve formulari ("Heslo" / "TOTP kod")

    def authenticate(self, username: str, credential: str, client_ip: str) -> AuthResult:
        ...
