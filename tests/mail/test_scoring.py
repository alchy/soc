"""Testy soc_mail.scoring - pruhledny soucet bodu za signaly + semafor."""
import soc_mail


def _score(headers_text):
    return soc_mail.score_headers(soc_mail.analyze(headers_text))


def test_cisty_mail_ma_nulu_a_zelenou():
    s = _score("Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
               "From: Jan <jan@firma.cz>\n")
    assert s.points == 0
    assert s.band == "ok"
    assert s.contributions == ()


def test_selhana_autentizace_boduje():
    s = _score("Authentication-Results: mx; spf=fail; dkim=none; dmarc=none\n")
    codes = {c.code: c for c in s.contributions}
    assert codes["spf_fail"].points == 4 and codes["spf_fail"].level == "high"
    assert codes["spf_fail"].title == "SPF"
    assert codes["dkim_none"].points == 2 and codes["dkim_none"].level == "low"
    assert s.points == 8            # fail(4) + none(2) + none(2)
    assert s.band == "high"


def test_bere_se_nejhorsi_vysledek_napric_overovateli():
    s = _score("Authentication-Results: vnejsi; spf=pass\n"
               "Authentication-Results-Original: vnitrni; spf=fail\n")
    assert {c.code for c in s.contributions} == {"spf_fail"}


def test_slaby_signal_je_porad_signal():
    s = _score("From: x <x@a.cz>\nMessage-ID: <1@jinde.net>\n")
    assert s.points == 1
    assert s.band == "info"


def test_nalezy_z_hlavicek_se_scitaji():
    s = _score("From: Ucto <ucto@firma.cz>\nReply-To: podvod@evil.ru\n"
               "X-PHP-Originating-Script: 1:mdm.php\n")
    assert s.points == 8           # reply_to_mismatch (4) + php_script (4)
    assert s.band == "high"


def test_impersonace_je_kriticka():
    s = _score('From: "reditel@banka.cz" <x@evil.ru>\n')
    c = {c.code: c for c in s.contributions}["display_impersonation"]
    assert c.level == "critical" and c.points == 6
    assert s.band == "high"


def test_realny_reportovany_spam_je_podezrely():
    from pathlib import Path
    import pytest
    nested = None
    for p in sorted(Path("/www/soc/vault").glob("*/*/extracted/attachments/*")):
        if p.name.lower().endswith((".msg", ".msg.norun")):
            nested = p
            break
    if nested is None:
        pytest.skip("vault nema zadny vzorek s vnorenym .msg")
    parsed = soc_mail.parse_msg(nested)
    s = soc_mail.score_headers(soc_mail.analyze(parsed.headers_text))
    assert s.points > 0, "reportovany spam nesmi vyjit jako cisty"
