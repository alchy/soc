"""Offline analyza e-mailovych hlavicek (faze A, viz docs/portal/header-analysis.md).

Tenhle modul ROZPARSUJE hlavicky na fakta (odesilatel, autentizace, cesta
doruceni, prijemce) a spusti nad nimi DETEKTORY signalu z `detectors.py`.
Detekcni pravidla zamerne NEZIJI tady - kazde je mala funkce v registru
`detectors.DETECTORS`, aby knihovna nerostla do jednoho velkeho `analyze()`.

Pokryte signaly: A1 autentizace (SPF/DKIM/DMARC), A2 nesoulad identit (vc.
Sender != From, punycode/IDN, duplicitni hlavicky), A3 cesta doruceni
(received.py), A4 odesilaci software (vc. hromadneho maileru), A5 verdikty
bran (vc. cloudove kategorie CAT), A6 casova anomalie, A7 technika obsahu,
A8 prijemce, plus DMARC politika p=none. Detaily kazdeho pravidla: detectors.py.

Zadna sit, zadne API. Vstup je text hlavicek (RFC 5322) - stejny tvar ma
headers.txt z vaultu i ParsedMessage.headers_text z .msg. Knihovna nic
neskoruje (to dela scoring.py); vraci fakta + nalezy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from email import message_from_string
from email.utils import parseaddr

from .detectors import DETECTORS
from .models import Finding, MailContext, domain_of
from .received import Hop, parse_chain

# Finding se re-exportuje pro zpetnou kompatibilitu (soc_mail.headers.Finding).
__all__ = ["AuthResult", "Finding", "HeaderAnalysis", "analyze"]

_MECH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthResult:
    """Verdikt jednoho overovatele.

    Kazda brana po ceste pridava VLASTNI Authentication-Results hlavicku,
    proto jich zprava miva vic. `original=True` znamena hlavicku
    Authentication-Results-Original - verdikt VSTUPNI brany, zachovany
    pozdejsi branou (hybridem) pred prepsanim.

    `authoritative=True` oznacuje verdikt, ktery se smi pouzit pro skore:
    SPF ma vypovidaci hodnotu JEN u brany, ktera videla skutecnou IP
    z internetu - pozdejsi overovatele (napr. EOP za hybridem) uz vidi IP
    naseho vlastniho serveru a jejich SPF je artefakt. Autoritativni jsou
    proto -Original verdikty; bez nich nejspodnejsi (puvodu nejblizsi) AR.
    """
    server: str                     # kdo overoval (authserv-id; "" kdyz chybi)
    spf: str                        # pass/fail/softfail/none/permerror/... nebo ""
    dkim: str
    dmarc: str
    original: bool = False
    authoritative: bool = False


@dataclass(frozen=True)
class HeaderAnalysis:
    auth: tuple[AuthResult, ...]    # A1 - po jednom za kazdou AR hlavicku
    from_display: str               # A2 - fakta
    from_addr: str
    sender: str                     # Sender: adresa ("" kdyz == From / chybi)
    reply_to: str
    return_path: str
    message_id: str
    mailer: str                     # A4 - X-Mailer/User-Agent ("" kdyz chybi)
    hops: tuple[Hop, ...]           # A3 - cesta doruceni, puvod prvni
    to: str                         # A8 - skutecny prijemce
    findings: tuple[Finding, ...]   # nalezy z detectors.DETECTORS


def _auth_results(msg) -> tuple[AuthResult, ...]:
    out = []
    for name in ("Authentication-Results", "Authentication-Results-Original"):
        for raw in msg.get_all(name) or []:
            raw = str(raw)
            mechs = {m.group(1).lower(): m.group(2).lower()
                     for m in _MECH_RE.finditer(raw)}
            # authserv-id je prvni segment PRED strednikem; nektere servery
            # (outlook.com) ho vynechavaji a zacinaji rovnou "spf=..." - pak
            # zadne jmeno nemame a nevydavame za nej kus verdiktu.
            first = raw.split(";", 1)[0].strip()
            out.append(AuthResult(
                server="" if "=" in first else first,
                spf=mechs.get("spf", ""), dkim=mechs.get("dkim", ""),
                dmarc=mechs.get("dmarc", ""),
                original=name.endswith("-Original")))

    # Autorita (viz docstring AuthResult): -Original verdikty vstupni brany;
    # kdyz zadne nejsou, nejspodnejsi AR hlavicka (hlavicky se pridavaji
    # nahoru, takze posledni v poradi je puvodu nejbliz).
    if out:
        if any(r.original for r in out):
            out = [replace(r, authoritative=r.original) for r in out]
        else:
            out[-1] = replace(out[-1], authoritative=True)
    return tuple(out)


def analyze(headers_text: str) -> HeaderAnalysis:
    """Rozebere text hlavicek. Tolerantni ke smeti - vraci, co se precist dalo."""
    msg = message_from_string(headers_text or "")

    from_display, from_addr = parseaddr(str(msg.get("From", "")))
    _, sender = parseaddr(str(msg.get("Sender", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    message_id = str(msg.get("Message-ID", "")).strip("<> \n")
    mailer = str(msg.get("X-Mailer", "") or msg.get("User-Agent", "")).strip()
    hops = parse_chain(msg.get_all("Received"))

    ctx = MailContext(
        msg=msg, from_display=from_display, from_addr=from_addr,
        from_domain=domain_of(from_addr), sender=sender, reply_to=reply_to,
        return_path=return_path, message_id=message_id, hops=hops)

    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(ctx))

    return HeaderAnalysis(
        auth=_auth_results(msg),
        from_display=from_display, from_addr=from_addr, sender=sender,
        reply_to=reply_to, return_path=return_path, message_id=message_id,
        mailer=mailer, hops=hops, to=str(msg.get("To", "")).strip(),
        findings=tuple(findings))
