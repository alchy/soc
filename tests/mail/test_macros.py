"""Testy soc_mail.macros - mapovani olevba vysledku + graceful degradace.

Mapovani (_map_analysis) je ciste a testuje se bez oletools. Realny beh olevba
overuje jen na cistem Office dokumentu z vaultu (integracni, skip bez vaultu) -
vzorek s realnym makrem v repu nemame a syntetizovat validni OLE s VBA je
neumerne.
"""
from pathlib import Path

import pytest

import soc_mail
from soc_mail.macros import _map_analysis

VAULT = Path("/www/soc/vault")


def _codes(has_vba, has_xlm, results):
    return {f.code: f for f in _map_analysis(has_vba, has_xlm, results)}


def test_xlm_makro_je_kriticke():
    assert _codes(False, True, [])["xlm_macro"].level == "critical"


def test_autoexec_se_suspicious_je_kriticke():
    c = _codes(True, False, [("AutoExec", "AutoOpen", ""),
                             ("Suspicious", "Shell", "")])
    assert c["macro_autoexec"].level == "critical"
    assert "Shell" in c["macro_autoexec"].text


def test_jen_autoexec_je_vysoke():
    assert _codes(True, False, [("AutoExec", "Document_Open", "")])["macro_autoexec"].level == "high"


def test_jen_suspicious_je_vysoke():
    assert _codes(True, False, [("Suspicious", "powershell", "")])["macro_suspicious"].level == "high"


def test_obfuskace_je_vysoka():
    assert "macro_obfuscation" in _codes(True, False, [("Base64 String", "…", "")])


def test_makro_bez_priznaku_je_stredni():
    assert _codes(True, False, [])["macro_present"].level == "medium"


def test_bez_maker_zadny_nalez():
    assert _map_analysis(False, False, []) == []


def test_analyze_macros_size_cap():
    assert soc_mail.analyze_macros("big.docm", b"x" * (26 * 1024 * 1024)) == []


def test_realny_office_dokument_projde():
    """Cisty .docx z vaultu: analyze_macros nesmi vyhodit a vrati [] (bez maker)."""
    import extract_msg
    for p in sorted(VAULT.glob("*/*/extracted/attachments/*")):
        if not p.name.lower().endswith((".msg", ".msg.norun")):
            continue
        for name, data in soc_mail.office_attachments(p):
            assert soc_mail.analyze_macros(name, data) == []
            return
    pytest.skip("vault nema zadnou Office prilohu")
