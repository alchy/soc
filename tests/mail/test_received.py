"""Testy soc_mail.received - cesta doruceni z Received retezu (A3)."""
import soc_mail

# poradi jako ve zprave: nejnovejsi (posledni hop) prvni
_CHAIN = [
    "from gw.firma.cz (gw.firma.cz [10.0.0.1]) by mx.firma.cz with ESMTP;"
    " Tue, 15 Sep 2026 15:28:05 +0000",
    "from evil-host (cloudhost.nxcli.net [203.0.113.9]) by gw.firma.cz;"
    " Tue, 15 Sep 2026 15:27:00 +0000",
]


def test_puvod_je_prvni():
    hops = soc_mail.parse_chain(_CHAIN)
    assert hops[0].from_host == "evil-host"
    assert hops[0].from_info == "cloudhost.nxcli.net [203.0.113.9]"
    assert hops[-1].by_host == "mx.firma.cz"


def test_timestamp_se_parsuje_do_iso():
    hops = soc_mail.parse_chain(_CHAIN)
    assert hops[0].when.startswith("2026-09-15T15:27:00")


def test_identicke_hopy_se_slucuji():
    hops = soc_mail.parse_chain([_CHAIN[0]] * 3 + [_CHAIN[1]])
    assert len(hops) == 2
    assert hops[1].count == 3


def test_smeti_neshodi_parser():
    hops = soc_mail.parse_chain(["uplne rozbity radek bez struktury", ""])
    assert len(hops) >= 1          # vrati aspon prazdne hopy, nevyhodi
