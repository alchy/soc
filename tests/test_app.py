"""HTTP vrstva: prijem, vypisy, chybove stavy.

Bezi bez site a bez access-manageru - overeni klice se podstrcuje
monkeypatchem, protoze tady jde o chovani API, ne o autoritu.
"""
from __future__ import annotations

import base64
import io
import json
import zipfile

import pytest

from soc_api import app as app_modul
from soc_api import auth, config

KLIC = "am_k1_testovaci"
HLAVICKY = {"Authorization": f"Bearer {KLIC}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    vault = tmp_path / "vault"
    vault.mkdir()                       # healthz kontroluje, ze existuje
    monkeypatch.setattr(config, "VAULT", vault)
    monkeypatch.setattr(config, "TRUSTED_PROXIES", ("127.0.0.1", "::1"))
    # realm se bere z konfigurace, at test nezavisi na jejim vychozim obsahu
    kdo = {"component": "socupload", "key_id": "k1", "realm": config.AM_REALM}
    monkeypatch.setattr(auth, "_whoami", lambda key, ip: kdo if key == KLIC else None)
    auth._cache.clear()
    app_modul.app.config["TESTING"] = True
    with app_modul.app.test_client() as c:
        yield c


def zip_bajty(jmeno="a.txt", obsah="obsah") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(jmeno, obsah)
    return buf.getvalue()


def posli_raw(client, data: bytes, filename="sample.zip", **kw):
    h = dict(HLAVICKY)
    if filename is not None:
        h["X-Filename"] = filename
    h.update(kw.pop("headers", {}))
    return client.post("/api/v1/samples", data=data,
                       content_type="application/octet-stream", headers=h, **kw)


# ── autentizace ──────────────────────────────────────────────────────────────

def test_bez_klice_je_401(client):
    r = client.get("/api/v1/samples")
    assert r.status_code == 401
    assert r.get_json()["error"] == "unauthorized"


def test_spatny_klic_je_401(client):
    r = client.get("/api/v1/samples", headers={"Authorization": "Bearer am_k1_cizi"})
    assert r.status_code == 401


def test_healthz_klic_nepotrebuje(client):
    r = client.get("/api/v1/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


# ── prijem: tri podoby pozadavku ────────────────────────────────────────────

def test_syrove_telo(client):
    r = posli_raw(client, zip_bajty())
    assert r.status_code == 201
    d = r.get_json()
    assert d["extraction"]["status"] == "extracted"
    assert len(d["sha256"]) == 64


def test_multipart_s_heslem(client, tmp_path):
    import pyzipper
    cesta = tmp_path / "enc.zip"
    with pyzipper.AESZipFile(cesta, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("payload.bin", "malware")

    r = client.post("/api/v1/samples", headers=HLAVICKY, data={
        "file": (io.BytesIO(cesta.read_bytes()), "enc.zip"),
        "filename": "enc.zip",
        "password": "infected",
    }, content_type="multipart/form-data")

    assert r.status_code == 201
    e = r.get_json()["extraction"]
    assert e["status"] == "extracted" and e["encrypted"] is True


def test_json_s_base64(client):
    telo = {"filename": "a.zip", "data": base64.b64encode(zip_bajty()).decode()}
    r = client.post("/api/v1/samples", headers=HLAVICKY,
                    data=json.dumps(telo), content_type="application/json")
    assert r.status_code == 201
    assert r.get_json()["extraction"]["status"] == "extracted"


def test_vadny_base64_je_400(client):
    telo = {"filename": "a.zip", "data": "tohle neni base64!!!"}
    r = client.post("/api/v1/samples", headers=HLAVICKY,
                    data=json.dumps(telo), content_type="application/json")
    assert r.status_code == 400
    assert r.get_json()["error"] == "bad_request"


def test_multipart_bez_pole_file_je_400(client):
    r = client.post("/api/v1/samples", headers=HLAVICKY,
                    data={"filename": "a.zip"}, content_type="multipart/form-data")
    assert r.status_code == 400


# ── past, ktera uz jednou vznikla ───────────────────────────────────────────

def test_urlencoded_telo_neprijde_prazdne(client):
    """Regrese: sahnuti na request.files u ne-multipartu vycerpa stream.

    `curl --data-binary` posila x-www-form-urlencoded. Kdyz se na
    `request.files` sahne driv, nez se pozna typ, Werkzeug telo sezere
    a do vaultu dojde prazdny soubor.
    """
    r = client.post("/api/v1/samples", data=zip_bajty(),
                    content_type="application/x-www-form-urlencoded",
                    headers={**HLAVICKY, "X-Filename": "a.zip"})
    assert r.status_code == 201, "telo se cestou ztratilo"
    assert r.get_json()["size"] > 0


def test_multipart_vetsi_nez_spool_prah(client):
    """Regrese: velky multipart konci v TMPDIR, ne v pameti.

    Werkzeug spooluje telo pozadavku nad ~500 kB do docasneho souboru.
    V kontejneru je /tmp tmpfs o par desitkach MB, takze bez presmerovani
    TMPDIR do vaultu skonci 50MB vzorek na "No space left on device" -
    HTTP 500, i kdyz na disku je mista dost.
    """
    velky = zip_bajty(obsah="x" * (3 * 1024 * 1024))

    r = client.post("/api/v1/samples", headers=HLAVICKY, data={
        "file": (io.BytesIO(velky), "velky.zip"), "filename": "velky.zip",
    }, content_type="multipart/form-data")

    assert r.status_code == 201, r.get_json()
    assert r.get_json()["size"] == len(velky)


# ── jmeno archivu ───────────────────────────────────────────────────────────

def test_chybejici_jmeno_je_400(client):
    """Bez jmena nejde urcit format - rict to hned, ne az stavem rozbaleni."""
    r = client.post("/api/v1/samples", data=zip_bajty(),
                    content_type="application/octet-stream", headers=HLAVICKY)
    assert r.status_code == 400
    assert r.get_json()["error"] == "filename_required"


def test_prazdne_telo_je_400(client):
    r = posli_raw(client, b"")
    assert r.status_code == 400
    assert r.get_json()["error"] == "empty_body"


# ── obsahove adresovani ─────────────────────────────────────────────────────

def test_tentyz_vzorek_podruhe_je_200(client):
    data = zip_bajty(obsah="stejny obsah")
    prvni = posli_raw(client, data)
    druhy = posli_raw(client, data)

    assert prvni.status_code == 201
    assert druhy.status_code == 200
    assert druhy.get_json()["duplicate"] is True
    assert druhy.get_json()["sha256"] == prvni.get_json()["sha256"]


def test_duplicita_dorozbali_kdyz_prijde_heslo(client, tmp_path):
    """Stav rozbaleni je vlastnost vzorku, ne pozadavku."""
    import pyzipper
    cesta = tmp_path / "enc.zip"
    with pyzipper.AESZipFile(cesta, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"tajne")
        z.writestr("payload.bin", "malware")
    data = cesta.read_bytes()

    bez = posli_raw(client, data, filename="enc.zip")
    assert bez.get_json()["extraction"]["status"] == "password_required"

    s_heslem = client.post("/api/v1/samples", headers=HLAVICKY, data={
        "file": (io.BytesIO(data), "enc.zip"),
        "filename": "enc.zip", "password": "tajne",
    }, content_type="multipart/form-data")

    assert s_heslem.status_code == 200
    assert s_heslem.get_json()["extraction"]["status"] == "extracted"


def test_kontrola_integrity(client):
    r = posli_raw(client, zip_bajty(), headers={
        "X-Expected-SHA256": "0" * 64})
    assert r.status_code == 422
    assert r.get_json()["error"] == "hash_mismatch"


def test_pri_neshode_hashe_se_neulozi_nic(client):
    posli_raw(client, zip_bajty(), headers={"X-Expected-SHA256": "0" * 64})
    r = client.get("/api/v1/samples", headers=HLAVICKY)
    assert r.get_json()["count"] == 0


# ── vypisy ──────────────────────────────────────────────────────────────────

def test_vypis_je_od_nejnovejsiho(client):
    for i in range(3):
        posli_raw(client, zip_bajty(obsah=f"vzorek {i}"), filename=f"v{i}.zip")

    r = client.get("/api/v1/samples?limit=2", headers=HLAVICKY)
    d = r.get_json()

    assert d["count"] == 2 and d["limit"] == 2
    casy = [s["received_at"] for s in d["samples"]]
    assert casy == sorted(casy, reverse=True)


def test_limit_se_orizne_do_rozsahu(client):
    posli_raw(client, zip_bajty())
    assert client.get("/api/v1/samples?limit=9999", headers=HLAVICKY).get_json()["limit"] == config.MAX_LIMIT
    assert client.get("/api/v1/samples?limit=0", headers=HLAVICKY).get_json()["limit"] == 1


def test_necislny_limit_je_400(client):
    r = client.get("/api/v1/samples?limit=hodne", headers=HLAVICKY)
    assert r.status_code == 400


def test_include_events_prilozi_access_log(client):
    posli_raw(client, zip_bajty())

    bez = client.get("/api/v1/samples", headers=HLAVICKY).get_json()
    s_udalostmi = client.get("/api/v1/samples?include=events", headers=HLAVICKY).get_json()

    assert "events" not in bez["samples"][0]
    assert len(s_udalostmi["samples"][0]["events"]) >= 2


# ── detail vzorku ───────────────────────────────────────────────────────────

def test_detail_nese_events_i_files(client):
    sha = posli_raw(client, zip_bajty("sub/x.txt")).get_json()["sha256"]

    d = client.get(f"/api/v1/samples/{sha}", headers=HLAVICKY).get_json()

    assert d["sha256"] == sha
    assert any(e["event"] == "upload" for e in d["events"])
    assert d["files"][0]["path"] == "sub/x.txt"
    assert len(d["files"][0]["sha256"]) == 64


def test_neznamy_vzorek_je_404(client):
    r = client.get(f"/api/v1/samples/{'a' * 64}", headers=HLAVICKY)
    assert r.status_code == 404


def test_nesmyslny_hash_je_400(client):
    r = client.get("/api/v1/samples/kratky", headers=HLAVICKY)
    assert r.status_code == 400


def test_analyza_je_zatim_pending(client):
    sha = posli_raw(client, zip_bajty()).get_json()["sha256"]
    r = client.get(f"/api/v1/samples/{sha}/analysis", headers=HLAVICKY)
    assert r.get_json()["state"] == "pending"


# ── misto na disku ──────────────────────────────────────────────────────────

def test_pri_nedostatku_mista_se_prijem_odmitne(client, monkeypatch):
    monkeypatch.setattr("soc_api.storage.free_bytes", lambda: 1024)

    r = posli_raw(client, zip_bajty())

    assert r.status_code == 507
    assert r.get_json()["error"] == "insufficient_storage"


def test_healthz_hlasi_dochazejici_misto(client, monkeypatch):
    monkeypatch.setattr("soc_api.storage.free_bytes", lambda: 1024)

    r = client.get("/api/v1/healthz")

    assert r.status_code == 503
    assert r.get_json()["status"] == "degraded"
