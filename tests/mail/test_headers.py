"""Testy soc_mail.headers - offline analyza hlavicek (faze A).

Syntenticke hlavicky pripinaji jednotliva pravidla; realny vzorek z vaultu
overuje, ze analyza funguje na skutecnem reportovanem spamu.
"""
from pathlib import Path

import pytest

import soc_mail

VAULT = Path("/www/soc/vault")


def _codes(analysis):
    return {f.code for f in analysis.findings}


# ── A1: autentizace ─────────────────────────────────────────────────────────
def test_auth_results_se_parsuji():
    a = soc_mail.analyze(
        "Authentication-Results: mx.example.com; spf=pass "
        "smtp.mailfrom=a.cz; dkim=fail (bad sig); dmarc=none\n"
        "From: X <x@a.cz>\n")
    assert len(a.auth) == 1
    assert (a.auth[0].spf, a.auth[0].dkim, a.auth[0].dmarc) == ("pass", "fail", "none")
    assert a.auth[0].server == "mx.example.com"


def test_vice_ar_hlavicek_vcetne_original():
    a = soc_mail.analyze(
        "Authentication-Results: outer.example; spf=none\n"
        "Authentication-Results-Original: inner.example; spf=fail; dkim=permerror\n")
    assert len(a.auth) == 2
    assert a.auth[0].original is False
    assert a.auth[1].server == "inner.example"
    assert a.auth[1].dkim == "permerror"
    assert a.auth[1].original is True


# ── A2: nesoulad identit ────────────────────────────────────────────────────
def test_reply_to_mismatch():
    a = soc_mail.analyze("From: Ucto <ucto@firma.cz>\nReply-To: podvod@evil.ru\n")
    assert "reply_to_mismatch" in _codes(a)


def test_display_impersonation():
    a = soc_mail.analyze('From: "reditel@banka.cz" <x@evil.ru>\n')
    assert "display_impersonation" in _codes(a)


def test_cisty_mail_bez_nalezu():
    a = soc_mail.analyze(
        "From: Jan Novak <jan@firma.cz>\nReply-To: jan@firma.cz\n"
        "Return-Path: jan@firma.cz\nMessage-ID: <abc@firma.cz>\n")
    assert a.findings == ()


# ── A4: odesilaci software ──────────────────────────────────────────────────
def test_php_skript_je_nalez():
    a = soc_mail.analyze("From: x <x@a.cz>\nX-PHP-Originating-Script: 10225:mdm.php\n")
    assert "php_script" in _codes(a)
    assert "mdm.php" in [f.text for f in a.findings if f.code == "php_script"][0]


def test_mailer_se_vytahne():
    assert soc_mail.analyze("X-Mailer: Foo 1.2\n").mailer == "Foo 1.2"


# ── realny vzorek ───────────────────────────────────────────────────────────
def test_realny_reportovany_spam():
    nested = None
    for p in sorted(VAULT.glob("*/*/extracted/attachments/*")):
        if p.name.lower().endswith((".msg", ".msg.norun")):
            nested = p
            break
    if nested is None:
        pytest.skip("vault nema zadny vzorek s vnorenym .msg")
    parsed = soc_mail.parse_msg(nested)
    assert parsed.headers_text, ".msg ma nest transportni hlavicky"
    a = soc_mail.analyze(parsed.headers_text)
    assert a.auth, "reportovany spam prosel branami - AR hlavicky museji existovat"
    assert a.from_addr
