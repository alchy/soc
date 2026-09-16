"""Detail vzorku s vnorenou zpravou: boxy reportovaneho spamu + defangovane
servirovani tel. Bezi proti realnemu vaultu; bez vhodneho vzorku se preskoci.
"""
import pytest

from soc_portal import config, vault_reader
from soc_portal.web.app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        c.post("/login", data={"username": config.MOCK_USER,
                               "credential": config.MOCK_PASSWORD})
        yield c


def _sample_with_nested() -> str | None:
    for m in vault_reader.iter_samples():
        if vault_reader.list_nested_messages(m["sha256"]):
            return m["sha256"]
    return None


def test_detail_ukaze_reportovanou_zpravu(client):
    sha = _sample_with_nested()
    if sha is None:
        pytest.skip("vault nema vzorek s vnorenym .msg")
    html = client.get(f"/sample/{sha}").get_data(as_text=True)
    assert "Reported message" in html
    assert "Header signals" in html
    assert f"/sample/{sha}/nested/0/body" in html


def test_nested_body_je_defangovane_a_ma_csp(client):
    sha = _sample_with_nested()
    if sha is None:
        pytest.skip("vault nema vzorek s vnorenym .msg")
    resp = client.get(f"/sample/{sha}/nested/0/body")
    if resp.status_code == 404:
        pytest.skip("vnorena zprava nema HTML telo")
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    body = resp.get_data(as_text=True)
    assert "https://" not in body and "http://" not in body, \
        "telo musi byt defangovane (hxxp)"


def test_nested_body_neexistujici_index(client):
    sha = _sample_with_nested()
    if sha is None:
        pytest.skip("vault nema vzorek s vnorenym .msg")
    assert client.get(f"/sample/{sha}/nested/99/body").status_code == 404


def test_wrapper_body_je_defangovane(client):
    for m in vault_reader.iter_samples():
        files = [f["path"] for f in vault_reader.list_files(m["sha256"])]
        if "body.html" in files:
            resp = client.get(f"/sample/{m['sha256']}/body")
            assert resp.status_code == 200
            assert "https://" not in resp.get_data(as_text=True)
            return
    pytest.skip("vault nema vzorek s body.html")
