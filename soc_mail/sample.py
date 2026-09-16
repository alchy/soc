"""Vysokourovnova analyza jedne zpravy - sestavi vsechny komponenty.

Sdilene MISTO, kde se drati dohromady hlavicky + prilohy + makra pres
komponentni pipeline s IZOLACI PADU. Volaji ho backendy (orchestrator dnes,
portal az cist bude z baliku) - zadna duplikace draotovani komponent.

Vstupy jsou uz NACTENA data (text hlavicek, prilohy, Office bajty); vault I/O
zustava na volajicim (orchestrator vs portal maji jiny pristup k vaultu).
"""
from __future__ import annotations

from collections.abc import Iterable

from .attachments import analyze_attachments
from .headers import HeaderAnalysis, analyze
from .macros import analyze_macros
from .msg import MailAttachment
from .pipeline import ComponentFailure
from .pipeline import run as run_components
from .scoring import Score, score_headers


def _macro_findings(office_docs: Iterable[tuple[str, bytes]]) -> list:
    out = []
    for name, data in office_docs:
        out.extend(analyze_macros(name, data))
    return out


def analyze_message(
    headers_text: str,
    attachments: Iterable[MailAttachment] = (),
    office_docs: Iterable[tuple[str, bytes]] = (),
) -> tuple[HeaderAnalysis, Score, list[ComponentFailure]]:
    """Hlavicky + prilohy + makra pres pipeline s izolaci padu.

    Vraci (HeaderAnalysis fakta, Score, seznam selhanych komponent). Pad
    jedne komponenty se objevi ve failures, nezhrouti analyzu.
    """
    attachments = tuple(attachments)
    office_docs = tuple(office_docs)
    header = analyze(headers_text)     # detektory hlavicek uz izolovane uvnitr

    findings, failures = run_components([
        ("attachments", lambda: analyze_attachments(attachments)),
        ("macros", lambda: _macro_findings(office_docs)),
    ])
    score = score_headers(header, extra_findings=findings)
    return header, score, list(header.failures) + failures
