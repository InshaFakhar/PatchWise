import pytest
from fastapi.testclient import TestClient

from patchwise.web.app import create_app

HEADER = "asset_id,hostname,asset_type,criticality,exposure,environment\n"
GOOD_ROW = "A1,web-01,server,High,DMZ,prod\n"
SBOM = b'{"bomFormat": "CycloneDX", "components": [{"name": "examplelib", "version": "2.3.1"}]}'


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path / "web.db"))


def post_inventory(client, content):
    if isinstance(content, str):
        content = content.encode("utf-8")
    return client.post("/upload/inventory", files={"file": ("assets.csv", content, "text/csv")})


def post_sbom(client, asset_id, content):
    return client.post(
        "/upload/sbom",
        data={"asset_id": asset_id},
        files={"file": ("sbom.json", content, "application/json")},
    )


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_empty_database_shows_friendly_message(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "No assets yet" in response.text


def test_uploaded_inventory_appears_on_home_page(client):
    report = post_inventory(client, HEADER + GOOD_ROW)
    assert report.status_code == 200 and "No problems found" in report.text
    assert "web-01" in client.get("/").text


def test_invalid_row_is_reported_on_page(client):
    response = post_inventory(client, HEADER + "A2,db-01,database,Super,Internal,dev\n")
    assert "line 2" in response.text and "Super" in response.text
    assert "Some records were rejected" in response.text


def test_sbom_upload_and_asset_detail_page(client):
    post_inventory(client, HEADER + GOOD_ROW)
    report = post_sbom(client, "A1", SBOM)
    assert "No problems found" in report.text
    detail = client.get("/assets/A1")
    assert detail.status_code == 200
    assert "examplelib" in detail.text and "2.3.1" in detail.text


def test_unknown_asset_page_is_404(client):
    assert client.get("/assets/NOPE").status_code == 404


def test_sbom_for_unknown_asset_is_reported(client):
    response = post_sbom(client, "NOPE", SBOM)
    assert "not found" in response.text


def test_invalid_json_sbom_is_reported(client):
    post_inventory(client, HEADER + GOOD_ROW)
    response = post_sbom(client, "A1", b"{ not json")
    assert "not valid JSON" in response.text


def test_html_in_data_is_escaped(client):
    post_inventory(client, HEADER + "A3,<script>alert(1)</script>,server,High,DMZ,prod\n")
    page = client.get("/").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_non_utf8_file_is_rejected_politely(client):
    response = post_inventory(client, b"\xff\xfe\x00bad")
    assert response.status_code == 200 and "UTF-8" in response.text


def test_too_large_file_is_rejected(client):
    response = post_inventory(client, b"a" * 1_000_001)
    assert "too large" in response.text


def test_project_sample_files_work_through_the_web(client):
    with open("data/synthetic/assets.csv", "rb") as f:
        post_inventory(client, f.read())
    with open("data/synthetic/sbom_A001.json", "rb") as f:
        post_sbom(client, "A001", f.read())
    assert "web-prod-01" in client.get("/").text
    assert "examplelib" in client.get("/assets/A001").text