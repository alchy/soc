"""Testy knihovny soc_mail - .msg parsovani + defang.

Defang testy jsou HERMETICKE (jen retezce). Parsovani .msg potrebuje binarni
OLE soubor - ten se do repa nekomituje: realny .msg nese skutecne interni
adresy/hostnames (PII) a syntetizovat validni OLE by byl neumerny naklad.
Proto je `test_parse_msg_realny_vzorek` INTEGRACNI: bezi jen kdyz je vault
po ruce, jinak se preskoci.
"""
from pathlib import Path

import pytest

import soc_mail

VAULT = Path("/www/soc/vault")


def _first_nested_msg() -> Path | None:
    for p in sorted(VAULT.glob("*/*/extracted/attachments/*")):
        if p.name.lower().endswith((".msg", ".msg.norun")):
            return p
    return None


# ── parse_msg ────────────────────────────────────────────────────────────────
def test_parse_msg_realny_vzorek():
    p = _first_nested_msg()
    if p is None:
        pytest.skip("vault nema zadny vzorek s vnorenym .msg")
    m = soc_mail.parse_msg(p)
    assert m.sender, "reportovany spam ma mit odesilatele"
    assert m.subject
    assert m.body_text or m.body_html, "zprava ma mit aspon jedno telo"


def test_parse_msg_odmitne_nemsg_soubor(tmp_path):
    fake = tmp_path / "neni.msg"
    fake.write_bytes(b'{"tohle": "je json, ne OLE"}')
    with pytest.raises(soc_mail.MailParseError):
        soc_mail.parse_msg(fake)


# ── defang ───────────────────────────────────────────────────────────────────
def test_defang_text_url():
    out = soc_mail.defang_text("klikni: https://evil.example.com/pay?id=1 hned")
    assert "hxxps://evil[.]example[.]com/pay?id=1" in out
    assert "https://" not in out


def test_defang_text_nemeni_okolni_text():
    assert soc_mail.defang_text("bez odkazu, jen text 1.2") == "bez odkazu, jen text 1.2"


def test_defang_html_odzbroji_odkaz_a_ukaze_cil():
    html = b'<p>Pay <a href="https://evil.example.com/x">here</a> now</p>'
    out = soc_mail.defang_html(html)
    assert 'href' not in out
    assert "hxxps://evil[.]example[.]com/x" in out
    assert "here" in out  # text odkazu zustava


def test_defang_html_odstrani_script_a_defanguje_text():
    html = b'<script>alert(1)</script><p>viz https://a.b/c</p>'
    out = soc_mail.defang_html(html)
    assert "<script>" not in out
    assert "hxxps://a[.]b/c" in out


def test_defang_html_vlozi_css_volajiciho_na_konec():
    out = soc_mail.defang_html(b"<body><p>x</p></body>",
                               inject_css="table { width: auto !important; }")
    assert out.rstrip().endswith("</style></body>")
    assert "width: auto !important" in out
