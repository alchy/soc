"""Testy soc_mail.scoring - pruhledny soucet bodu za signaly + semafor.

Hermeticke: syntenticke hlavicky + commitnuty fixture, zadny vault.
"""
from pathlib import Path

import soc_mail

_FIXTURE = (Path(__file__).resolve().parent.parent / "fixtures"
            / "reported_spam.headers.txt").read_text(encoding="utf-8")


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


def test_rozhoduje_verdikt_vstupni_brany():
    s = _score("Authentication-Results: vnejsi; spf=pass\n"
               "Authentication-Results-Original: vnitrni; spf=fail\n")
    assert {c.code for c in s.contributions} == {"spf_fail"}


def test_spf_pozdejsiho_overovatele_se_nikdy_neboduje():
    # vstupni brana (Original) rekla pass; EOP za hybridem meri nasi IP a
    # rekne fail - to je artefakt a nesmi generovat body
    s = _score("Authentication-Results: vnejsi; spf=fail\n"
               "Authentication-Results-Original: vnitrni; spf=pass\n")
    assert not any(c.code.startswith("spf") for c in s.contributions)


def test_dmarc_fallback_na_pozdejsiho_je_oznaceny():
    # vstupni brana DMARC nemerila (IronPort validskip); bere se od EOP
    s = _score("Authentication-Results: vnejsi; dmarc=none\n"
               "Authentication-Results-Original: vnitrni; spf=pass\n")
    c = [c for c in s.contributions if c.code == "dmarc_none"][0]
    assert "later verifier" in c.text


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


def test_fixture_je_cerveny_s_rozpadem():
    """Bohaty reportovany spam ma vyjit vysoce a s citelnym rozpadem.
    POZOR (limit faze A): spam z kompromitovane, ale korektne nastavene domeny
    muze byt header-cisty a vyjit zelene - to neni chyba scoringu; takovy pripad
    chyti az faze B (stari domeny, reputace)."""
    s = _score(_FIXTURE)
    assert s.band == "high"
    assert s.points > 0 and s.contributions
    # SPF se bere z autoritativniho (softfail), ne z vnejsiho prepoctu (pass)
    spf = [c for c in s.contributions if c.title == "SPF"]
    assert len(spf) == 1 and spf[0].code == "spf_softfail"
