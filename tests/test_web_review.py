import pytest
from fastapi.testclient import TestClient

from patchwise import services
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


@pytest.fixture
def client(db):
    c = TestClient(create_app(db))
    c.post("/matching/run", follow_redirects=True)
    return c


def form(db, rank=1, action="bump", reason="ransomware in the wild", analyst="Insha"):
    f = [x for x in services.list_ranked(db) if x["rank"] == rank][0]
    return {"component_id": str(f["component_id"]), "cve_id": f["cve_id"],
            "action": action, "reason": reason, "analyst": analyst}


def test_queue_page_asks_for_matching_first(db):
    page = TestClient(create_app(db)).get("/queue")
    assert page.status_code == 200 and "Nothing to review yet" in page.text


def test_queue_page_lists_findings_with_decision_forms(client):
    text = client.get("/queue").text
    assert "Review queue" in text and 'action="/review/decide"' in text
    assert "bumped: 0" in text and "undecided: 10" in text


def test_saving_a_decision_updates_the_queue_and_the_audit_page(client, db):
    page = client.post("/review/decide", data=form(db, rank=10, action="bump", reason="customer data here"),
                       follow_redirects=True)
    assert page.status_code == 200
    assert "bumped: 1" in page.text and "customer data here" in page.text
    audit = client.get("/audit").text
    assert "customer data here" in audit and "Insha" in audit and "bump" in audit


def test_missing_reason_shows_an_error_and_saves_nothing(client, db):
    page = client.post("/review/decide", data=form(db, reason=""), follow_redirects=True)
    assert "a reason is required" in page.text
    assert "No decisions yet" in client.get("/audit").text


def test_unknown_finding_is_rejected_politely(client):
    page = client.post("/review/decide",
                       data={"component_id": "9999", "cve_id": "CVE-2099-0001", "action": "accept",
                             "reason": "x", "analyst": "Insha"},
                       follow_redirects=True)
    assert page.status_code == 200 and "not in the current results" in page.text


def test_analyst_name_is_remembered_for_the_next_decision(client, db):
    client.post("/review/decide", data=form(db, analyst="Insha Fakhar"), follow_redirects=True)
    assert 'value="Insha Fakhar"' in client.get("/queue").text


def test_html_in_a_reason_is_escaped(client, db):
    page = client.post("/review/decide", data=form(db, reason="<script>alert(1)</script>"), follow_redirects=True)
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;" in page.text


def test_error_message_in_the_address_is_escaped(client):
    text = client.get("/queue?error=<script>alert(1)</script>").text
    assert "<script>alert(1)</script>" not in text


def test_csv_export_is_a_download_with_the_queue(client, db):
    client.post("/review/decide", data=form(db, rank=10, action="bump", reason="urgent"), follow_redirects=True)
    response = client.get("/export/queue.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    lines = response.content.decode("utf-8-sig").strip().splitlines()
    assert lines[0].startswith("queue_position,patchwise_rank,score")
    assert len(lines) == 11 and ",bump," in lines[1]


def test_markdown_export_is_a_download(client):
    response = client.get("/export/queue.md")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "attachment" in response.headers["content-disposition"]
    assert response.text.startswith("# PatchWise remediation shortlist")


def test_navigation_links_to_queue_and_audit(db):
    text = TestClient(create_app(db)).get("/").text
    assert 'href="/queue"' in text and 'href="/audit"' in text
