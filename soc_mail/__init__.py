"""soc_mail - KNIHOVNA pro cteni e-mailovych formatu, bez sluzebnich zavislosti.

Extrakcni/analyticke komponenty stavime jako knihovny a backendy (portal dnes,
orchestrator analyzy zitra) je volaji jako moduly - segregace kodu: zadny
Flask, zadna znalost vaultu ani HTTP. Vstupem je soubor/bajty, vystupem
neutralni datovy model.
"""
from .attachments import analyze_attachments
from .defang import defang_html, defang_text
from .headers import AuthResult, Finding, HeaderAnalysis, analyze
from .macros import analyze_macros
from .msg import (MailAttachment, MailParseError, ParsedMessage,
                  office_attachments, parse_msg)
from .pipeline import ComponentFailure
from .pipeline import run as run_components
from .received import Hop, parse_chain
from .report import REPORT_SCHEMA, build_report
from .sample import analyze_message
from .scoring import Contribution, Score, score_headers

__all__ = ["MailAttachment", "MailParseError", "ParsedMessage", "parse_msg",
           "office_attachments",
           "defang_html", "defang_text",
           "AuthResult", "Finding", "HeaderAnalysis", "analyze",
           "analyze_attachments", "analyze_macros", "analyze_message",
           "ComponentFailure", "run_components",
           "Hop", "parse_chain",
           "REPORT_SCHEMA", "build_report",
           "Contribution", "Score", "score_headers"]
