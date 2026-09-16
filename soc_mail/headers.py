"""Offline vyteznost e-mailovych hlavicek (faze A, viz docs/portal/header-analysis.md).

Zadna sit, zadne API - jen to, co je v hlavickach samotnych:
  A1  verdikt autentizace (SPF / DKIM / DMARC z Authentication-Results*),
  A2  nesoulad identit (From vs Reply-To vs Return-Path vs domena Message-ID,
      adresa schovana v display-name),
  A4  odesilaci software (X-Mailer / User-Agent / X-PHP-Originating-Script).

Vstup je text hlavicek (RFC 5322) - stejny tvar ma headers.txt z vaultu
i ParsedMessage.headers_text z .msg. Vystup jsou fakta + nalezy; co je
"podezrele" rozhoduje analytik, knihovna nic neskoruje.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from email import message_from_string
from email.utils import parseaddr

_MECH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthResult:
    """Verdikt jednoho overovatele.

    Kazda brana po ceste pridava VLASTNI Authentication-Results hlavicku,
    proto jich zprava mivá vic. `original=True` znamena hlavicku
    Authentication-Results-Original - verdikt prvni (vnitrni) brany,
    zachovany pozdejsi branou pred prepsanim.
    """
    server: str                     # kdo overoval (authserv-id; "" kdyz chybi)
    spf: str                        # pass/fail/softfail/none/permerror/... nebo ""
    dkim: str
    dmarc: str
    original: bool = False


@dataclass(frozen=True)
class Finding:
    """Jeden nalez: strojovy kod + kategorie + text + sila SIGNALU.

    `level` klasifikuje jednotlivy signal na petistupnove skale
    'info' < 'low' < 'medium' < 'high' < 'critical' - to je domenova znalost
    o hlavickach, ne verdikt o zprave. Vazeni vsech signalu dohromady zustava
    na analytikovi (a scoringu/orchestratoru).
    `title` je kratka kategorie pro UI (SPF, DKIM, PHP skript, ...).
    """
    code: str
    title: str
    text: str
    level: str = "medium"           # info|low|medium|high|critical


@dataclass(frozen=True)
class HeaderAnalysis:
    auth: tuple[AuthResult, ...]    # A1 - po jednom za kazdou AR hlavicku
    from_display: str               # A2 - fakta
    from_addr: str
    reply_to: str
    return_path: str
    message_id: str
    mailer: str                     # A4 - X-Mailer/User-Agent ("" kdyz chybi)
    findings: tuple[Finding, ...]   # nesoulady a pozoruhodnosti


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


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
    return tuple(out)


def analyze(headers_text: str) -> HeaderAnalysis:
    """Rozebere text hlavicek. Tolerantni ke smeti - vraci, co se precist dalo."""
    msg = message_from_string(headers_text or "")

    from_display, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    message_id = str(msg.get("Message-ID", "")).strip("<> \n")
    mailer = str(msg.get("X-Mailer", "") or msg.get("User-Agent", "")).strip()
    php_script = str(msg.get("X-PHP-Originating-Script", "")).strip()

    findings: list[Finding] = []
    fd = _domain(from_addr)

    if reply_to and fd and _domain(reply_to) != fd:
        findings.append(Finding("reply_to_mismatch", "Reply-To",
            f"odpovedi miri do jine domeny ({reply_to}) nez From ({from_addr})",
            level="high"))
    if return_path and fd and _domain(return_path) != fd:
        findings.append(Finding("return_path_mismatch", "Return-Path",
            f"bounce adresa ({return_path}) je z jine domeny nez From ({from_addr})",
            level="medium"))
    if message_id and fd and _domain(message_id) and _domain(message_id) != fd:
        findings.append(Finding("msgid_mismatch", "Message-ID",
            f"domena ID ({_domain(message_id)}) nesedi s From ({fd}); "
            "u velkych provideru bezne", level="info"))
    # Klasika: "ucetni@banka.cz <utocnik@evil.ru>" - adresa schovana ve jmene.
    disp_addr = parseaddr(f"x <{from_display}>")[1] if "@" in from_display else ""
    if disp_addr and _domain(disp_addr) != fd:
        findings.append(Finding("display_impersonation", "Display-name",
            f"jmeno odesilatele obsahuje adresu {from_display!r}, skutecny "
            f"odesilatel je {from_addr} - pokus o impersonaci", level="critical"))
    if php_script:
        findings.append(Finding("php_script", "PHP skript",
            f"odeslano skriptem {php_script} - typicky kompromitovany web",
            level="high"))

    return HeaderAnalysis(
        auth=_auth_results(msg),
        from_display=from_display, from_addr=from_addr,
        reply_to=reply_to, return_path=return_path, message_id=message_id,
        mailer=mailer, findings=tuple(findings))
