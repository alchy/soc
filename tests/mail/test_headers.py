"""Testy soc_mail.headers - offline analyza hlavicek (faze A).

HERMETICKE: syntenticke hlavicky pripinaji jednotliva pravidla, plny pipeline
overuje COMMITNUTY fixture tests/fixtures/reported_spam.headers.txt. Zadna
zavislost na zivem vaultu - realny .msg by navic nesl skutecne interni adresy
a hostnames (PII), takze se do repa nekomituje; integracni beh proti vaultu
resi tests s markerem [vault] jinde.
"""
from pathlib import Path

import soc_mail

_FIXTURE = (Path(__file__).resolve().parent.parent / "fixtures"
            / "reported_spam.headers.txt").read_text(encoding="utf-8")


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
    assert a.auth[0].authoritative is False   # prepocet za hybridem
    assert a.auth[1].server == "inner.example"
    assert a.auth[1].dkim == "permerror"
    assert a.auth[1].original is True
    assert a.auth[1].authoritative is True    # verdikt vstupni brany


def test_jediny_overovatel_je_autoritativni():
    a = soc_mail.analyze("Authentication-Results: mx; spf=pass\n")
    assert a.auth[0].authoritative is True


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


# ── A5: verdikty bran ───────────────────────────────────────────────────────
def test_spam_flag_brany_je_silny_signal():
    a = soc_mail.analyze("X-Spam-Flag: YES\nX-Spam-Status: YES, hits=9 required=5\n")
    f = [f for f in a.findings if f.code == "gateway_spam_flag"][0]
    assert f.level == "high"
    assert "hits=9" in f.text


def test_scl_pod_prahem_neboduje():
    a = soc_mail.analyze("X-MS-Exchange-Organization-SCL: -1\n")
    assert "gateway_scl" not in _codes(a)


def test_scl_vysoky():
    a = soc_mail.analyze("X-MS-Exchange-Organization-SCL: 8\n")
    f = [f for f in a.findings if f.code == "gateway_scl"][0]
    assert f.level == "high"


# ── A6: casova anomalie ─────────────────────────────────────────────────────
def test_date_skew():
    a = soc_mail.analyze(
        "Received: from a by b; Tue, 16 Sep 2026 10:00:00 +0000\n"
        "Date: Mon, 15 Sep 2026 10:00:00 +0000\n")
    assert "date_skew" in _codes(a)


def test_maly_rozdil_neni_signal():
    a = soc_mail.analyze(
        "Received: from a by b; Tue, 16 Sep 2026 10:30:00 +0000\n"
        "Date: Tue, 16 Sep 2026 10:00:00 +0000\n")
    assert "date_skew" not in _codes(a)


# ── A7: technika obsahu ─────────────────────────────────────────────────────
def test_base64_html_bez_alternativy():
    a = soc_mail.analyze("Content-Type: text/html; charset=utf-8\n"
                         "Content-Transfer-Encoding: base64\n")
    assert "base64_html" in _codes(a)


def test_multipart_neni_signal():
    a = soc_mail.analyze("Content-Type: multipart/alternative; boundary=x\n"
                         "Content-Transfer-Encoding: base64\n")
    assert "base64_html" not in _codes(a)


# ── plny pipeline nad commitnutym fixturem ──────────────────────────────────
def test_fixture_vytezi_vsechny_ocekavane_signaly():
    """Cely retez na realistickem (ale syntetickem) reportovanem spamu."""
    a = soc_mail.analyze(_FIXTURE)
    assert a.from_addr == "webmaster@spammer.example"
    assert a.to == "victim@corp.example"
    assert a.hops and a.hops[0].from_host == "spammer.example"  # puvod prvni
    assert _codes(a) >= {
        "reply_to_mismatch", "return_path_mismatch", "display_impersonation",
        "php_script", "gateway_spam_flag", "gateway_scl", "base64_html",
        "date_skew"}


def test_fixture_autorita_ma_original_verdikt():
    a = soc_mail.analyze(_FIXTURE)
    orig = [r for r in a.auth if r.original][0]
    assert orig.authoritative is True
    assert orig.spf == "softfail"
    # vnejsi prepocet (spf=pass) NENI autoritativni
    assert all(not r.authoritative for r in a.auth if not r.original)
