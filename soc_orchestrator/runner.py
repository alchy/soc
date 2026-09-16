"""Analyza jednoho vzorku -> report (prezentacni bloky, soc_mail.report).

Reads-only cast: najde vstupy ve vaultu (vnorena reportovana .msg, nebo
extracted/headers.txt), pusti sdilenou soc_mail.analyze_message a slozi report.
Vault I/O je tady; komponentni logika je v soc_mail (zadna duplikace).
"""
from __future__ import annotations

from dataclasses import asdict

import soc_mail

from . import vault_rw


def _nested_msg(sha256: str):
    d = vault_rw.sample_dir(sha256) / "extracted" / "attachments"
    if not d.is_dir():
        return None
    for p in sorted(d.iterdir()):
        if p.is_file() and p.name.lower().endswith((".msg", ".msg.norun")):
            return p
    return None


def _headers_txt(sha256: str) -> str:
    p = vault_rw.sample_dir(sha256) / "extracted" / "headers.txt"
    try:
        return p.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""


def analyze(sha256: str) -> dict:
    """Sestavi report pro vzorek. Muze vyhodit (necitelny vzorek) - volajici
    to zachyti a nastavi stav error."""
    manifest = vault_rw.read_manifest(sha256) or {}
    received_at = manifest.get("received_at", "")

    reported = None
    headers_text, attachments, office_docs = "", (), ()
    nested = _nested_msg(sha256)
    if nested:
        try:
            parsed = soc_mail.parse_msg(nested)
            headers_text = parsed.headers_text
            attachments = parsed.attachments
            office_docs = soc_mail.office_attachments(nested)
            reported = {
                "sender": parsed.sender, "subject": parsed.subject,
                "date": parsed.date,
                "attachments": [asdict(a) for a in parsed.attachments],
                "has_html_body": bool(parsed.body_html),
            }
        except soc_mail.MailParseError:
            nested = None       # fallback na obalove hlavicky nize
    if not nested:
        headers_text = _headers_txt(sha256)

    header, score, failures = soc_mail.analyze_message(
        headers_text, attachments, office_docs)
    return soc_mail.build_report(
        sha256, header, score, reported=reported,
        received_at=received_at, failures=failures)
