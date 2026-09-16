"""Testy jednotlivych novych detektoru (Sender, mailer, DMARC politika, CAT,
punycode, header injection) - kazdy izolovane a hermeticky."""
import soc_mail


def _codes(text):
    return {f.code for f in soc_mail.analyze(text).findings}


def test_sender_mismatch():
    assert "sender_mismatch" in _codes(
        "From: A <a@firma.cz>\nSender: <bot@hosting.example>\n")


def test_sender_stejna_domena_neni_signal():
    assert "sender_mismatch" not in _codes(
        "From: A <a@firma.cz>\nSender: <system@firma.cz>\n")


def test_bulk_mailer_phpmailer():
    f = [f for f in soc_mail.analyze(
        "From: a <a@b.cz>\nX-Mailer: PHPMailer 7.1.1\n").findings
        if f.code == "bulk_mailer"][0]
    assert f.level == "low"


def test_bezny_klient_neni_bulk():
    assert "bulk_mailer" not in _codes("X-Mailer: Microsoft Outlook 16.0\n")


def test_dmarc_policy_none():
    assert "dmarc_policy_none" in _codes(
        "Authentication-Results: mx; dmarc=pass (p=none dis=none) d=b.cz\n")


def test_dmarc_reject_neni_signal():
    assert "dmarc_policy_none" not in _codes(
        "Authentication-Results: mx; dmarc=pass (p=reject) d=b.cz\n")


def test_cloud_category_phish():
    f = [f for f in soc_mail.analyze(
        "X-Forefront-Antispam-Report: CIP:1.2.3.4;CAT:PHSH;SFV:SPM\n").findings
        if f.code == "cloud_category"][0]
    assert f.level == "high"


def test_cloud_category_none_neni_signal():
    assert "cloud_category" not in _codes("X-Forefront-Antispam-Report: CAT:NONE\n")


def test_punycode_domain():
    assert "punycode_domain" in _codes("From: A <a@xn--80ak6aa92e.com>\n")


def test_header_injection_duplicitni_from():
    assert "header_injection" in _codes(
        "From: a <a@b.cz>\nFrom: b <x@evil.ru>\nSubject: hi\n")
