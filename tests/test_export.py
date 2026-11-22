import csv
import io

from patchwise import services
from patchwise.export import reports
from patchwise.ingest.epss import load_epss
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.kev import load_kev
from patchwise.ingest.nvd import load_nvd
from patchwise.ingest.sbom import import_sbom


def load_samples(tmp_path):
    db = tmp_path / "t.db"
    import_inventory("data/synthetic/assets.csv", db)
    for asset in ("A001", "A002", "A003"):
        import_sbom(f"data/synthetic/sbom_{asset}.json", asset, db)
    load_kev("data/snapshots/kev_sample.json", db)
    load_nvd("data/snapshots/nvd_sample.json", db)
    load_epss("data/snapshots/epss_sample.csv", db)
    services.run_matching(db)
    return db


def parse_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def fake_item(position=1, reason="ok", analyst="Insha", action="accept", hostname="web-01"):
    return {
        "queue_position": position, "rank": position, "score": 80.123, "status": "confirmed",
        "decision": {"action": action, "analyst_name": analyst, "reason": reason,
                     "decided_at": "2026-11-21T10:00:00+00:00"},
        "hostname": hostname, "criticality": "High", "exposure": "DMZ",
        "component": "examplelib", "component_version": "2.3.1", "cve_id": "CVE-2099-0001",
        "cvss_score": 8.1, "in_kev": True, "epss_score": 0.91,
    }


def test_csv_has_the_expected_columns_and_one_row_per_finding(tmp_path):
    db = load_samples(tmp_path)
    rows = parse_csv(services.export_queue_csv(db))
    assert list(rows[0].keys()) == reports.CSV_COLUMNS
    assert len(rows) == 10
    assert [r["queue_position"] for r in rows] == [str(i) for i in range(1, 11)]
    assert rows[0]["asset"] == "web-prod-01" and rows[0]["cve_id"] == "CVE-2099-0001"
    assert rows[0]["in_kev"] == "yes" and rows[0]["score"] == "94.0"


def test_csv_shows_decisions_in_queue_order(tmp_path):
    db = load_samples(tmp_path)
    last = [f for f in services.list_ranked(db) if f["rank"] == 10][0]
    services.record_decision(last["component_id"], last["cve_id"], "bump", "customer data", "Insha", db)
    rows = parse_csv(services.export_queue_csv(db))
    assert rows[0]["decision"] == "bump" and rows[0]["analyst"] == "Insha"
    assert rows[0]["patchwise_rank"] == "10" and rows[0]["queue_position"] == "1"
    assert rows[1]["decision"] == ""


def test_unknown_values_stay_empty_not_zero(tmp_path):
    db = load_samples(tmp_path)
    rows = parse_csv(services.export_queue_csv(db))
    mystery = [r for r in rows if r["software"].startswith("mystery-lib")][0]
    assert mystery["software"] == "mystery-lib (version unknown)" and mystery["epss"] == ""


def test_csv_blocks_spreadsheet_formula_injection():
    text = reports.queue_to_csv([fake_item(reason='=HYPERLINK("http://evil","click")', analyst="@admin")])
    row = parse_csv(text)[0]
    assert row["reason"].startswith("'=") and row["analyst"].startswith("'@")
    for value in ("=1+1", "+1", "-1", "@x", "\t1"):
        assert reports.csv_safe(value) == "'" + value
    assert reports.csv_safe("normal text") == "normal text"
    assert reports.csv_safe(5) == 5


def test_csv_quotes_commas_quotes_and_line_breaks_correctly():
    nasty = 'needs "approval", then\nrestart'
    row = parse_csv(reports.queue_to_csv([fake_item(reason=nasty)]))[0]
    assert row["reason"] == nasty


def test_csv_keeps_non_english_text():
    row = parse_csv(reports.queue_to_csv([fake_item(reason="مالک سے بات ہو گئی", analyst="انشا")]))[0]
    assert row["reason"] == "مالک سے بات ہو گئی" and row["analyst"] == "انشا"


def test_markdown_has_header_weights_and_table(tmp_path):
    db = load_samples(tmp_path)
    md = services.export_queue_markdown(db, generated_at="2026-11-21T10:00:00+00:00")
    lines = md.splitlines()
    assert lines[0] == "# PatchWise remediation shortlist"
    assert "Generated: 2026-11-21T10:00:00+00:00" in md
    assert "CVSS 20%" in md and "KEV 25%" in md
    table = [l for l in lines if l.startswith("|")]
    assert len(table) == 2 + 10                      # header + separator + 10 findings
    assert "CVE-2099-0001" in table[2]


def test_markdown_cells_cannot_break_the_table():
    md = reports.queue_to_markdown([fake_item(reason="a | b\nsecond line")], [("CVSS", 20.0)], "now")
    row = [l for l in md.splitlines() if l.startswith("|")][2]
    assert "a \\| b second line" in row
    assert len(row.replace("\\|", "").split("|")) == 14      # 12 cells + the two outer edges


def test_export_is_reproducible(tmp_path):
    db = load_samples(tmp_path)
    assert services.export_queue_csv(db) == services.export_queue_csv(db)
    a = services.export_queue_markdown(db, generated_at="t")
    b = services.export_queue_markdown(db, generated_at="t")
    assert a == b


def test_export_of_an_empty_queue_is_just_the_header(tmp_path):
    csv_text = services.export_queue_csv(tmp_path / "empty.db")
    assert csv_text.strip() == ",".join(reports.CSV_COLUMNS)
