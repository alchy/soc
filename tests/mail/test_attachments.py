"""Testy soc_mail.attachments - staticke riziko ze jmena prilohy (hermeticke)."""
import soc_mail
from soc_mail import MailAttachment


def _find(names):
    atts = [MailAttachment(n, 1000) for n in names]
    return {f.code: f for f in soc_mail.analyze_attachments(atts)}


def test_spustitelna_priloha_je_kriticka():
    f = _find(["update.exe"])["dangerous_attachment"]
    assert f.level == "critical"


def test_dvojita_pripona():
    f = _find(["Invoice_502217.pdf.exe"])["double_extension"]
    assert f.level == "critical"
    assert "pdf" in f.text.lower()


def test_svg_je_aktivni_obsah():
    assert _find(["logo.svg"])["active_svg"].level == "high"


def test_makro_dokument():
    assert _find(["order.xlsm"])["macro_document"].level == "high"


def test_archiv_je_info():
    assert _find(["files.zip"])["archive_attachment"].level == "info"


def test_bezne_pdf_neni_signal():
    assert _find(["Invoice_502217.pdf"]) == {}


def test_bez_pripony_nespadne():
    assert soc_mail.analyze_attachments([MailAttachment("noext", 10)]) == []


def test_skore_zahrne_prilohy():
    a = soc_mail.analyze("From: x <x@a.cz>\n")
    att = soc_mail.analyze_attachments([MailAttachment("run.exe", 10)])
    s = soc_mail.score_headers(a, extra_findings=att)
    assert s.band == "high"
    assert any(c.code == "dangerous_attachment" for c in s.contributions)
