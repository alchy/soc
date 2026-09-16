"""Testy komponentniho systemu - IZOLACE PADU (pipeline.run)."""
import soc_mail
from soc_mail.models import Finding


def test_pad_jedne_komponenty_nezastavi_ostatni():
    findings, failures = soc_mail.run_components([
        ("ok1", lambda: [Finding("a", "A", "x", "info")]),
        ("boom", lambda: (_ for _ in ()).throw(ValueError("prasklo"))),
        ("ok2", lambda: [Finding("b", "B", "y", "high")]),
    ])
    # obe zdrave komponenty dobehly
    assert {f.code for f in findings} == {"a", "b"}
    # pad se ohlasil, ne propadl
    assert len(failures) == 1
    assert failures[0].component == "boom"
    assert "prasklo" in failures[0].error


def test_prazdny_vysledek_je_v_poradku():
    findings, failures = soc_mail.run_components([("nic", lambda: None)])
    assert findings == [] and failures == []


def test_detektor_hlavicek_je_izolovany(monkeypatch):
    # nasimuluj pad jednoho detektoru; analyze nesmi spadnout
    import soc_mail.detectors as det
    import soc_mail.headers as headers

    def boom(ctx):
        raise RuntimeError("detektor selhal")

    # headers.analyze bere DETECTORS pres svuj import - patchujeme tam
    monkeypatch.setattr(headers, "DETECTORS", [boom, det.detect_identity])
    a = soc_mail.analyze("From: Ucto <ucto@firma.cz>\nReply-To: x@evil.ru\n")
    # zdravy detektor dobehl (nasel reply_to_mismatch)
    assert any(f.code == "reply_to_mismatch" for f in a.findings)
    # pad se ohlasil
    assert any(f.component == "boom" for f in a.failures)
