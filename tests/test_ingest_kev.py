import json
import sqlite3

from patchwise.db.connection import init_db
from patchwise.ingest.kev import load_kev, validate_kev


def entry(cve="CVE-2099-0001", **changes):
    e = {
        "cveID": cve, "vendorProject": "exampleco", "product": "examplelib",
        "dateAdded": "2026-01-10", "dueDate": "2026-01-31",
        "knownRansomwareCampaignUse": "Known",
    }
    e.update(changes)
    return e


def write_kev(tmp_path, entries):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps({"title": "test", "vulnerabilities": entries}), encoding="utf-8")
    return path


def query(db, sql):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def test_valid_entries_are_loaded(tmp_path):
    db = tmp_path / "t.db"
    report = load_kev(write_kev(tmp_path, [entry(), entry("CVE-2099-0002")]), db)
    assert not report.errors and report.loaded == 2
    assert len(query(db, "SELECT * FROM kev")) == 2
    assert len(query(db, "SELECT * FROM cves")) == 2   # parent rows were created


def test_fields_are_saved(tmp_path):
    db = tmp_path / "t.db"
    load_kev(write_kev(tmp_path, [entry()]), db)
    row = query(db, "SELECT cve_id, vendor_project, product, date_added, due_date, "
                    "known_ransomware_use FROM kev")[0]
    assert row == ("CVE-2099-0001", "exampleco", "examplelib",
                   "2026-01-10", "2026-01-31", "Known")


def test_bad_cve_id_is_rejected(tmp_path):
    report = validate_kev(write_kev(tmp_path, [entry("BAD-1")]))
    assert not report.valid and "not a valid CVE id" in report.errors[0][1]


def test_impossible_date_is_rejected(tmp_path):
    report = validate_kev(write_kev(tmp_path, [entry(dateAdded="2026-13-45")]))
    assert "dateAdded" in report.errors[0][1]


def test_missing_date_added_is_rejected(tmp_path):
    e = entry()
    del e["dateAdded"]
    report = validate_kev(write_kev(tmp_path, [e]))
    assert "dateAdded is missing" in report.errors[0][1]


def test_empty_due_date_is_saved_as_null(tmp_path):
    db = tmp_path / "t.db"
    load_kev(write_kev(tmp_path, [entry(dueDate="")]), db)
    assert query(db, "SELECT due_date FROM kev")[0][0] is None


def test_bad_ransomware_value_is_rejected(tmp_path):
    report = validate_kev(write_kev(tmp_path, [entry(knownRansomwareCampaignUse="Maybe")]))
    assert "knownRansomwareCampaignUse" in report.errors[0][1]


def test_duplicate_cve_in_file_is_rejected(tmp_path):
    report = validate_kev(write_kev(tmp_path, [entry(), entry()]))
    assert len(report.valid) == 1 and "duplicate" in report.errors[0][1]


def test_invalid_json_fails_and_is_logged(tmp_path):
    db = tmp_path / "t.db"
    path = tmp_path / "bad.json"
    path.write_text("{ nope", encoding="utf-8")
    report = load_kev(path, db)
    assert report.file_error and "not valid JSON" in report.errors[0][1]
    assert query(db, "SELECT * FROM kev") == []
    assert query(db, "SELECT status FROM data_fetch_log") == [("failed",)]


def test_missing_vulnerabilities_list_is_rejected(tmp_path):
    path = tmp_path / "nolist.json"
    path.write_text(json.dumps({"title": "x"}), encoding="utf-8")
    assert "'vulnerabilities' list is missing" in validate_kev(path).errors[0][1]


def test_loading_twice_updates_instead_of_duplicating(tmp_path):
    db = tmp_path / "t.db"
    load_kev(write_kev(tmp_path, [entry()]), db)
    load_kev(write_kev(tmp_path, [entry(dueDate="2026-02-15")]), db)
    assert query(db, "SELECT due_date FROM kev") == [("2026-02-15",)]


def test_existing_cve_data_is_not_overwritten(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO cves (cve_id, description, cvss_score) "
                 "VALUES ('CVE-2099-0001', 'from NVD', 9.8)")
    conn.commit()
    conn.close()
    load_kev(write_kev(tmp_path, [entry()]), db)
    assert query(db, "SELECT description, cvss_score FROM cves") == [("from NVD", 9.8)]


def test_fetch_log_records_counts_and_status(tmp_path):
    db = tmp_path / "t.db"
    entries = [entry(), entry("CVE-2099-0002"), entry("BAD-1")]
    load_kev(write_kev(tmp_path, entries), db, now="2026-10-16T12:00:00+00:00")
    row = query(db, "SELECT source, mode, records_read, records_loaded, "
                    "records_rejected, status, fetched_at FROM data_fetch_log")[0]
    assert row == ("KEV", "snapshot", 3, 2, 1, "partial", "2026-10-16T12:00:00+00:00")


def test_scope_filter_loads_only_wanted_cves(tmp_path):
    db = tmp_path / "t.db"
    report = load_kev(write_kev(tmp_path, [entry(), entry("CVE-2099-0002")]), db,
                      only_cves={"CVE-2099-0002"})
    assert report.loaded == 1 and report.skipped_out_of_scope == 1 and not report.errors
    assert query(db, "SELECT cve_id FROM kev") == [("CVE-2099-0002",)]


def test_project_sample_files_behave_as_expected():
    good = validate_kev("data/snapshots/kev_sample.json")
    assert len(good.valid) == 3 and not good.errors
    bad = validate_kev("data/snapshots/kev_invalid_demo.json")
    assert len(bad.valid) == 1 and len(bad.errors) == 2