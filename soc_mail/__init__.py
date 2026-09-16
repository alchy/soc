"""soc_mail - KNIHOVNA pro cteni e-mailovych formatu, bez sluzebnich zavislosti.

Extrakcni/analyticke komponenty stavime jako knihovny a backendy (portal dnes,
orchestrator analyzy zitra) je volaji jako moduly - segregace kodu: zadny
Flask, zadna znalost vaultu ani HTTP. Vstupem je soubor/bajty, vystupem
neutralni datovy model.
"""
from .attachments import analyze_attachments
from .defang import defang_html, defang_text
from .headers import AuthResult, Finding, HeaderAnalysis, analyze
from .msg import MailAttachment, MailParseError, ParsedMessage, parse_msg
from .received import Hop, parse_chain
from .scoring import Contribution, Score, score_headers

__all__ = ["MailAttachment", "MailParseError", "ParsedMessage", "parse_msg",
           "defang_html", "defang_text",
           "AuthResult", "Finding", "HeaderAnalysis", "analyze",
           "analyze_attachments",
           "Hop", "parse_chain",
           "Contribution", "Score", "score_headers"]
