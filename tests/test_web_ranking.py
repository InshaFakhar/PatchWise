import pytest
from fastapi.testclient import TestClient

from patchwise.ingest.epss import load_epss
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.kev import load_kev
from patchwise.ingest.nvd import load_nvd
from patchwise.ingest.sbom import import_sbom
from patchwise.web.app import create_app


def load_everything(db):
    import_inventory("data/synthetic/assets.csv", db)
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


def ranking_page(db):
    client = TestClient(create_app(db))
    client.post("/matching/run", follow_redirects=True)
    return client.get("/ranking")


def test_ranking_page_asks_for_matching_first(db):
    page = TestClient(create_app(db)).get("/ranking")
    assert page.status_code == 200
    assert "Nothing to rank yet" in page.text


def test_ranking_page_lists_findings_in_priority_order(db):
    page = ranking_page(db)
    assert page.status_code == 200
    text = page.text
    # CVE-2099-0001 on web-prod-01 is rank 1; CVE-2099-0002 first appears at rank 3
    assert text.index("CVE-2099-0001") < text.index("CVE-2099-0002")
    assert "CVSS-only #" in text


def test_ranking_page_shows_the_weights_and_the_stability_check(db):
    text = ranking_page(db).text
    assert "KEV 25%" in text and "CVSS 20%" in text
    assert "How stable is this ranking?" in text
    assert "Similarity to current order" in text


def test_ranking_page_shows_rank_difference_arrows(db):
    text = ranking_page(db).text
    assert "&#9650;" in text      # at least one finding ranks higher than under CVSS alone


def test_navigation_links_to_ranking(db):
    assert 'href="/ranking"' in TestClient(create_app(db)).get("/").text


def test_html_in_asset_names_is_escaped_on_the_ranking_page(tmp_path):
    inventory = tmp_path / "assets.csv"
    inventory.write_text(
        "asset_id,hostname,asset_type,criticality,exposure,environment\n"
        "A001,<script>alert(1)</script>,server,High,DMZ,prod\n", encoding="utf-8")
    db = tmp_path / "xss.db"
    import_inventory(inventory, db)
    import_sbom("data/synthetic/sbom_A001.json", "A001", db)
    load_nvd("data/snapshots/nvd_sample.json", db)
    text = ranking_page(db).text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
