"""Smoke test webove vrstvy: mock prihlaseni -> dashboard s rozbalovacimi radky.

Bezi proti realnemu vaultu (stejne jako test_vault_reader) - overuje, ze se
dashboard vykresli a ze radky maji tvar <details>/<summary>: souhrn nese jen
Prijato/Odesilatel/Predmet, podrobnosti (sha256, soubor, ...) jsou v rozbalovaci
casti. Pripina tak kontrakt sablony, ktery zadny unit test nekryl.
"""
import pytest

from soc_portal import config, vault_reader
from soc_portal.web.app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _login(c):
    return c.post("/login", data={"username": config.MOCK_USER,
                                  "credential": config.MOCK_PASSWORD})


def test_dashboard_requires_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_redirects_to_dashboard(client):
    resp = _login(client)
    assert resp.status_code == 302


def test_dashboard_rows_are_expandable(client):
    samples = vault_reader.iter_samples()
    if not samples:
        pytest.skip("prazdny vault - neni co vykreslit")
    _login(client)

    html = client.get("/").get_data(as_text=True)

    # radky jsou nativni <details> se souhrnem
    assert '<details class="row">' in html
    assert "<summary>" in html
    # podrobnosti (plny sha256 + odkaz na detail) lezi v rozbalovaci casti
    sha = samples[0]["sha256"]
    assert sha in html
    assert f"/sample/{sha}" in html
