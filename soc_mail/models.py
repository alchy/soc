"""Sdilene datove typy knihovny.

Leaf modul BEZ zavislosti na ostatnich soc_mail komponentach - proto z nej
smi importovat i headers.py i detectors.py, aniz vznikne cyklus.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """Jeden nalez: strojovy kod + kategorie + text + sila SIGNALU.

    `level` klasifikuje jednotlivy signal na petistupnove skale
    'info' < 'low' < 'medium' < 'high' < 'critical' - to je domenova znalost
    o hlavickach, ne verdikt o zprave. Vazeni vsech signalu dohromady zustava
    na analytikovi (a scoring.py).
    `title` je kratka kategorie pro UI (SPF, DKIM, PHP script, ...).
    """
    code: str
    title: str
    text: str
    level: str = "medium"           # info|low|medium|high|critical


@dataclass(frozen=True)
class MailContext:
    """Rozparsovana fakta zpravy predavana detektorum signalu.

    `msg` je `email.message.Message` pro pristup k libovolne hlavicce; ostatni
    pole jsou uz normalizovana, aby je detektory nemusely tahat znovu.
    """
    msg: object                     # email.message.Message
    from_display: str
    from_addr: str
    from_domain: str
    reply_to: str
    return_path: str
    message_id: str
    hops: tuple                     # tuple[received.Hop, ...] - cesta doruceni


def domain_of(addr: str) -> str:
    """Domenova cast adresy (za '@'), malymi pismeny; "" kdyz adresa neni."""
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""
