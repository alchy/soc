"""Baseline testy ctecí vrstvy proti REALNYM vzorkum ve vaultu.

Zaroven pripinaji sdileny kontrakt s soc-api: kdyby se zmenil tvar manifestu
nebo layout adresaru, spadne to tady - drive nez v produkci na UI.
"""
import pytest

from soc_portal import vault_reader as V

# Stabilni vzorek ve vaultu (phishing "dobrozemsky") - je to e-mail, ma metadata.
EMAIL_SHA = "29b4af99e7a85f8537667c5926f79a30717e946cf1566102029503accb225840"


def test_iter_samples_nonempty_and_sorted():
    samples = V.iter_samples()
    assert samples, "vault by mel obsahovat vzorky"
    received = [m.get("received_at", "") for m in samples]
    assert received == sorted(received, reverse=True), "od nejnovejsiho"


def test_manifest_schema_contract():
    m = V.read_manifest(EMAIL_SHA)
    assert m is not None
    for key in ("sha256", "state", "analysis", "extraction", "received_at"):
        assert key in m, f"manifest musi mit pole {key}"
    assert m["sha256"] == EMAIL_SHA
    assert "state" in m["analysis"]


def test_summarize_enriches_email_fields():
    m = V.read_manifest(EMAIL_SHA)
    row = V.summarize(m)
    assert row["sha256"] == EMAIL_SHA
    assert row["subject"], "u e-mailu ma summarize vytahnout predmet z metadata.json"
    assert row["sender"], "u e-mailu ma summarize vytahnout odesilatele"


def test_read_metadata_handles_bom():
    md = V.read_metadata(EMAIL_SHA)
    assert md is not None and "Subject" in md  # cteno pres utf-8-sig (BOM)


def test_extracted_path_valid():
    p = V.extracted_path(EMAIL_SHA, "body.html")
    assert p.is_file()


def test_extracted_path_blocks_traversal():
    with pytest.raises(V.VaultError):
        V.extracted_path(EMAIL_SHA, "../../../../etc/passwd")


def test_bad_sha_rejected():
    with pytest.raises(V.VaultError):
        V.sample_dir("nonhex")


def test_human_size():
    assert V.human_size(0) == "0 B"
    assert V.human_size(2048) == "2.0 kB"
    assert V.human_size(47200495).endswith("MB")
