"""Detektory signalu z hlavicek - kazdy je mala funkce `(ctx) -> list[Finding]`.

Registr `DETECTORS` je poradi, v jakem je `headers.analyze()` spousti. Pridat
signal = napsat funkci a zapsat ji do DETECTORS; `headers.py` se nemeni. Tim
knihovna neroste do jednoho velkeho `analyze()` (pokyn: soc_mail ma mit vic
komponent, ne monolit).

Kazdy detektor je bezstavovy, cte jen `ctx`, a kdyz prislusna hlavicka chybi,
vrati prazdny seznam - nic se nepredstira.
"""
from __future__ import annotations

import re
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime

from .models import Finding, MailContext, domain_of

_DATE_SKEW_LIMIT_S = 6 * 3600   # od jakeho rozdilu Date vs doruceni je to signal
_SCL_SPAM = 5                   # Exchange SCL: 5-6 spam, 7+ spam s vysokou jistotou
_SCL_HIGH = 7

# X-Mailer, ktery prozrazuje skriptove/hromadne odesilani (ne bezny klient).
_BULK_MAILER_RE = re.compile(r"phpmailer|swiftmailer|phpmail|mailchimp|sendgrid|"
                             r"powermta|mailer-?lite|python-?smtplib|nodemailer",
                             re.IGNORECASE)
# Cloudova kategorie (X-Forefront-Antispam-Report CAT:) -> sila signalu.
_CLOUD_CAT_LEVEL = {"MALW": "critical", "PHSH": "high", "SPM": "medium",
                    "BULK": "info"}
_DUP_HEADERS = ("From", "Subject", "Date")


def detect_identity(ctx: MailContext) -> list[Finding]:
    """A2: nesoulad identit - Reply-To / Return-Path / Message-ID / display-name
    proti domene From."""
    out: list[Finding] = []
    fd = ctx.from_domain
    if ctx.reply_to and fd and domain_of(ctx.reply_to) != fd:
        out.append(Finding("reply_to_mismatch", "Reply-To",
            f"replies go to a different domain ({ctx.reply_to}) than From ({ctx.from_addr})",
            level="high"))
    if ctx.return_path and fd and domain_of(ctx.return_path) != fd:
        out.append(Finding("return_path_mismatch", "Return-Path",
            f"bounce address ({ctx.return_path}) is from a different domain than "
            f"From ({ctx.from_addr})", level="medium"))
    if ctx.message_id and fd and domain_of(ctx.message_id) \
            and domain_of(ctx.message_id) != fd:
        out.append(Finding("msgid_mismatch", "Message-ID",
            f"ID domain ({domain_of(ctx.message_id)}) does not match From ({fd}); "
            "common with large providers", level="info"))
    # Klasika: "ucetni@banka.cz <utocnik@evil.ru>" - adresa schovana ve jmene.
    disp_addr = parseaddr(f"x <{ctx.from_display}>")[1] if "@" in ctx.from_display else ""
    if disp_addr and domain_of(disp_addr) != fd:
        out.append(Finding("display_impersonation", "Display name",
            f"sender display name contains address {ctx.from_display!r} but the actual "
            f"sender is {ctx.from_addr} - impersonation attempt", level="critical"))
    # Sender: != From: - zpravu fyzicky odeslala jina domena nez autor. Legitimni
    # (sekretarka, ticketing), ale u autentizovane cizi domeny je to tell po
    # kompromitovanem hostiteli (napr. odeslano z shared-hostingu).
    if ctx.sender and fd and domain_of(ctx.sender) != fd:
        out.append(Finding("sender_mismatch", "Sender",
            f"message was submitted by {ctx.sender} ({domain_of(ctx.sender)}), a different "
            f"domain than the From author ({fd})", level="low"))
    # Punycode / IDN v domene From - moznost homoglyfu znacky (paypa1, xn--...).
    if fd and ("xn--" in fd or ".xn--" in fd):
        out.append(Finding("punycode_domain", "IDN/punycode",
            f"From domain {fd!r} uses punycode/IDN - verify it is not a homoglyph "
            "of a known brand", level="medium"))
    return out


def detect_software(ctx: MailContext) -> list[Finding]:
    """A4: odesilaci software - PHP skript / hromadny mailer misto klienta."""
    out: list[Finding] = []
    php = str(ctx.msg.get("X-PHP-Originating-Script", "")).strip()
    if php:
        out.append(Finding("php_script", "PHP script",
            f"sent by script {php} - typically a compromised website", level="high"))
    mailer = str(ctx.msg.get("X-Mailer", "")).strip()
    if mailer and _BULK_MAILER_RE.search(mailer):
        out.append(Finding("bulk_mailer", "X-Mailer",
            f"sent via a scripting/bulk mail library ({mailer}) rather than a mail client",
            level="low"))
    return out


def detect_dmarc_policy(ctx: MailContext) -> list[Finding]:
    """DMARC politika p=none: domena sice muze projit DMARC, ale nic NEVYNUCUJE
    (utocnik s vlastni p=none domenou projde a nikdo ho nezastavi). Vytazeno
    primo z Authentication-Results, tedy staticke."""
    for name in ("Authentication-Results", "Authentication-Results-Original"):
        for raw in ctx.msg.get_all(name) or []:
            m = re.search(r"dmarc=[^;]*?\bp=(\w+)", str(raw), re.IGNORECASE)
            if m and m.group(1).lower() == "none":
                return [Finding("dmarc_policy_none", "DMARC policy",
                    "domain publishes DMARC p=none - it does not enforce alignment",
                    level="info")]
    return []


def detect_cloud_category(ctx: MailContext) -> list[Finding]:
    """A5 (cloud): X-Forefront-Antispam-Report CAT: kategorie od M365 (PHSH,
    MALW, SPM, BULK). Nezavisly verdikt cloudu."""
    report = str(ctx.msg.get("X-Forefront-Antispam-Report", ""))
    m = re.search(r"\bCAT:(\w+)", report, re.IGNORECASE)
    if not m:
        return []
    cat = m.group(1).upper()
    level = _CLOUD_CAT_LEVEL.get(cat)
    if not level:
        return []
    return [Finding("cloud_category", "Cloud verdict",
        f"Microsoft 365 categorized the message as {cat}", level=level)]


def detect_header_injection(ctx: MailContext) -> list[Finding]:
    """Duplicitni From/Subject/Date = header injection / DKIM replay - klienti
    poslou kazdou z nich prave jednou."""
    dup = [h for h in _DUP_HEADERS if len(ctx.msg.get_all(h) or []) > 1]
    if dup:
        return [Finding("header_injection", "Header injection",
            f"duplicate {', '.join(dup)} header(s) - possible header injection or "
            "DKIM replay", level="critical")]
    return []


def detect_gateway(ctx: MailContext) -> list[Finding]:
    """A5: co si o zprave myslely brany, kterymi prosla - "second opinion"
    zdarma. Verdikt ciziho filtru je silny signal, ale zadna z hlavicek neni
    povinna - kdyz chybi, nic se nerekne."""
    msg = ctx.msg
    out: list[Finding] = []
    if str(msg.get("X-Spam-Flag", "")).strip().upper().startswith("YES"):
        status = str(msg.get("X-Spam-Status", "")).split(",", 2)[:2]
        out.append(Finding("gateway_spam_flag", "Gateway filter",
            "an upstream filter flagged the message as spam"
            + (f" ({', '.join(s.strip() for s in status)})" if status else ""),
            level="high"))
    verdict = str(msg.get("X-ThreatScanner-Verdict", "")).strip()
    if verdict and verdict.lower() not in ("negative", "clean"):
        out.append(Finding("gateway_threatscanner", "ThreatScanner",
            f"upstream scanner verdict: {verdict}", level="high"))
    try:
        scl = int(str(msg.get("X-MS-Exchange-Organization-SCL", "")).strip())
    except ValueError:
        scl = None
    if scl is not None and scl >= _SCL_SPAM:
        out.append(Finding("gateway_scl", "Exchange SCL",
            f"spam confidence level {scl} (5-6 spam, 7+ high confidence)",
            level="high" if scl >= _SCL_HIGH else "medium"))
    return out


def detect_date_skew(ctx: MailContext) -> list[Finding]:
    """A6: Date si pise odesilatel - kdyz se rozchazi s casem doruceni
    (posledni Received), je bud zfalsovane, nebo zprava nekde dlouho lezela."""
    try:
        date = parsedate_to_datetime(str(ctx.msg.get("Date", "")))
    except (ValueError, TypeError):
        return []
    delivered = next((h.when for h in reversed(ctx.hops) if h.when), "")
    if not (date and date.tzinfo and delivered):
        return []
    skew = abs((datetime.fromisoformat(delivered) - date).total_seconds())
    if skew <= _DATE_SKEW_LIMIT_S:
        return []
    return [Finding("date_skew", "Date",
        f"Date header differs from delivery time by {skew / 3600:.0f} h", level="low")]


def detect_content(ctx: MailContext) -> list[Finding]:
    """A7: cele telo text/html v base64 bez plaintext alternativy - legitimni
    klienti posilaji multipart/alternative; tohle je bezny vzor spam kitu."""
    ctype = str(ctx.msg.get("Content-Type", "")).split(";", 1)[0].strip().lower()
    cte = str(ctx.msg.get("Content-Transfer-Encoding", "")).strip().lower()
    if ctype == "text/html" and cte == "base64":
        return [Finding("base64_html", "Content",
            "entire body is base64-encoded text/html with no plaintext "
            "alternative - a common spam-kit pattern", level="low")]
    return []


# Poradi = poradi zobrazeni signalu. Novy signal? Funkce + radek sem.
DETECTORS = [detect_identity, detect_software, detect_dmarc_policy,
             detect_gateway, detect_cloud_category, detect_date_skew,
             detect_content, detect_header_injection]
