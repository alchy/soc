"""Cteni Outlook .msg (OLE/CFB kontejner) do neutralniho modelu.

Nad knihovnou `extract_msg` (standard pro .msg; stavi na olefile, umi
dekomprimovat RTF a vytahnout plaintext i HTML telo). Tenhle modul ji
obaluje ze dvou duvodu:
  - volajici dostane stabilni, uzky model (ParsedMessage) misto celeho
    API extract_msg - kdyz knihovnu vymenime, zmena zustane tady,
  - extract_msg pri poskozenem vstupu vyhazuje ruznorode vyjimky napric
    vrstvami (olefile, struct, unicode...) - sjednocujeme na MailParseError.

BEZPECNOST: vstup je nepratelsky (reportovany spam/phishing). Knihovna obsah
NEinterpretuje - vraci text a bajty tak, jak jsou ulozeny. Escapovani,
sandbox a CSP jsou odpovednost prezentacni vrstvy volajiciho.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import extract_msg

log = logging.getLogger(__name__)


class MailParseError(Exception):
    """Soubor nejde precist jako Outlook .msg (poskozeny nebo jiny format)."""


@dataclass(frozen=True)
class MailAttachment:
    """Priloha vnorene zpravy - jen popis, data se nenacitaji."""
    name: str
    size: int


@dataclass(frozen=True)
class ParsedMessage:
    """Neutralni pohled na jednu zpravu. Vsechna pole jsou NEDUVERYHODNA."""
    sender: str
    subject: str
    date: str                       # ISO-8601, nebo "" kdyz v .msg chybi
    body_text: str                  # plaintext telo ("" kdyz chybi)
    body_html: bytes | None         # HTML telo tak, jak je ulozeno v .msg
    attachments: tuple[MailAttachment, ...]
    headers_text: str = ""          # RFC 5322 hlavicky - vstup pro headers.analyze


def parse_msg(path: str | Path) -> ParsedMessage:
    """Precte .msg soubor. Vyhodi MailParseError, kdyz to neni citelny .msg."""
    p = Path(path)
    try:
        msg = extract_msg.openMsg(str(p))
    except Exception as e:  # viz docstring: extract_msg nema spolecneho predka chyb
        log.warning("parse_msg: %s nejde otevrit jako .msg: %s", p.name, e)
        raise MailParseError(f"{p.name}: {e}") from e

    try:
        return ParsedMessage(
            sender=msg.sender or "",
            subject=msg.subject or "",
            date=msg.date.isoformat() if msg.date else "",
            body_text=msg.body or "",
            body_html=msg.htmlBody or None,
            attachments=tuple(_describe_attachment(a) for a in msg.attachments),
            headers_text=str(msg.header) if msg.header else "",
        )
    except MailParseError:
        raise
    except Exception as e:
        log.warning("parse_msg: %s ma necitelny obsah: %s", p.name, e)
        raise MailParseError(f"{p.name}: {e}") from e
    finally:
        msg.close()


def _describe_attachment(att) -> MailAttachment:
    """Jmeno + velikost; u vnorene zpravy jako prilohy neni `data` bytes."""
    name = att.longFilename or att.shortFilename or "(bez jmena)"
    data = att.data
    size = len(data) if isinstance(data, (bytes, bytearray)) else 0
    return MailAttachment(name=str(name), size=size)
