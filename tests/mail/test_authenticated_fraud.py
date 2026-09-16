"""Regresni test na "autentizovany podvod" (BEC / zmena bankovnich udaju).

Vzor: report beranek@ans.cz. Utocnik korektne autentizoval VLASTNI throwaway
domenu (SPF/DKIM/DMARC pass), takze samotna autentizace = 0 bodu = zelena.
Staticke NEtextove signaly (Sender != From, hromadny mailer, DMARC p=none)
musi zpravu zvednout z ZELENE - jinak se analytikovi jevi jako bezpecna.

Poctivy limit: staticke hlavicky to zvednou na ZLUTOU (pozor), ne na cervenou.
Jadro podvodu (znacka v predmetu, zadost o zmenu uctu) je TEXT a plna jistota
zada fazi B (stari/reputace domeny). Test tvrdi jen "uz to neni zelene".
"""
from pathlib import Path

import soc_mail

_FIXTURE = (Path(__file__).resolve().parent.parent / "fixtures"
            / "authenticated_fraud.headers.txt").read_text(encoding="utf-8")


def test_autentizace_sama_o_sobe_projde():
    a = soc_mail.analyze(_FIXTURE)
    orig = [r for r in a.auth if r.original][0]
    assert orig.authoritative and orig.spf == "pass" and orig.dkim == "pass"
    # zadny bodovany autentizacni prispevek - vse pass
    s = soc_mail.score_headers(a)
    assert not any(c.title in ("SPF", "DKIM", "DMARC") for c in s.contributions)


def test_staticke_signaly_zvednou_z_zelene():
    a = soc_mail.analyze(_FIXTURE)
    codes = {f.code for f in a.findings}
    assert {"sender_mismatch", "bulk_mailer", "dmarc_policy_none"} <= codes
    s = soc_mail.score_headers(a)
    assert s.points > 0
    assert s.band != "ok", "autentizovany podvod se nesmi jevit jako zeleny"


def test_sender_mismatch_najde_skutecneho_odesilatele():
    a = soc_mail.analyze(_FIXTURE)
    assert a.sender == "efineykw@server209.web-hosting.example"
    f = [f for f in a.findings if f.code == "sender_mismatch"][0]
    assert "web-hosting.example" in f.text
