import pytest
from fastapi.testclient import TestClient

from patchwise.ingest.epss import load_epss
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.kev import load_kev
from patchwise.ingest.nvd import load_nvd
from patchwise.ingest.sbom import import_sbom
from patchwise.web.app import create_app


def load_everything(db, inventory="data/synthetic/assets.csv"):
    import_inventory(inventory, db)
    for asset in ("A001", "A002", "A003"):
        import_sbom(f"data/synthetic/sbom_{asset}.json", asset, db)
    load_kev("data/snapshots/kev_sample.json", db)
    load_nvd("data/snapshots/nvd_sample.json", db)
    load_epss("data/snapshots/epss_sample.csv", db)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "web.db"
    load_everything(path)
    return path


def test_findings_page_is_empty_before_matching_runs(db):
    page = TestClient(create_app(db)).get("/findings")
    assert page.status_code == 200
    assert "No findings yet" in page.text


def test_run_matching_button_fills_the_findings_page(db):
    client = TestClient(create_app(db))
    page = client.post("/matching/run", follow_redirects=True)
    assert page.status_code == 200
    assert "CVE-2099-0001" in page.text and "web-prod-01" in page.text
    assert "No findings yet" not in page.text


def test_findings_page_shows_counts_and_public_signals(db):
    client = TestClient(create_app(db))
    page = client.post("/matching/run", follow_redirects=True).text
    assert "confirmed: 3" in page and "probable: 2" in page
    assert "uncertain: 3" in page and "insufficient data: 2" in page
    assert "(ransomware)" in page            # CVE-2099-0001 is in KEV with ransomware use
    assert "0.91" in page                    # its EPSS score
    assert "(version unknown)" in page       # the SBOM component without a version


def test_findings_page_explains_why(db):
    client = TestClient(create_app(db))
    page = client.post("/matching/run", follow_redirects=True).text
    assert "inside the affected range" in page
    assert "has no version" in page


def test_navigation_links_to_findings(db):
    assert 'href="/findings"' in TestClient(create_app(db)).get("/").text


def test_html_in_asset_names_is_escaped_on_the_findings_page(tmp_path):
    inventory = tmp_path / "assets.csv"
    inventory.write_text(
        "asset_id,hostname,asset_type,criticality,exposure,environment\n"
        "A001,<script>alert(1)</script>,server,High,DMZ,prod\n", encoding="utf-8")
    db = tmp_path / "xss.db"
    import_inventory(inventory, db)
    import_sbom("data/synthetic/sbom_A001.json", "A001", db)
    load_nvd("data/snapshots/nvd_sample.json", db)
    page = TestClient(create_app(db)).post("/matching/run", follow_redirects=True).text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
