import json
import sqlite3

from patchwise.db.connection import init_db
from patchwise.ingest.nvd import load_nvd, validate_nvd

CPE_ALL = "cpe:2.3:a:exampleco:examplelib:*:*:*:*:*:*:*:*"


def match(criteria=CPE_ALL, vulnerable=True, **bounds):
    m = {"vulnerable": vulnerable, "criteria": criteria}
    m.update(bounds)
    return m


def vuln(cve_id="CVE-2099-0001", score=8.1, matches="default", published="2026-01-05T10:15:09.143",
         metrics=None, descriptions=None):
    """Build one NVD-style entry. score=None -> no CVSS metrics at all."""
    if matches == "default":
        matches = [match(versionEndExcluding="2.4.0")]
    cve = {"id": cve_id}
    if published is not None:
        cve["published"] = published
    cve["descriptions"] = descriptions if descriptions is not None else [{"lang": "en", "value": "test CVE"}]
    if metrics is not None:
        cve["metrics"] = metrics
    elif score is not None:
        cve["metrics"] = {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": score}}]}
    if matches is not None:
        cve["configurations"] = [{"nodes": [{"cpeMatch": matches}]}]
    return {"cve": cve}


def write_nvd(tmp_path, entries):
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps({"vulnerabilities": entries}), encoding="utf-8")
    return path


def query(db, sql):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def test_valid_cve_is_loaded_with_details(tmp_path):
    db = tmp_path / "t.db"
    report = load_nvd(write_nvd(tmp_path, [vuln()]), db)
    assert not report.errors and report.loaded == 1
    row = query(db, "SELECT cve_id, description, published_date, cvss_score, cvss_version, "
                    "cvss_vector FROM cves")[0]
    assert row == ("CVE-2099-0001", "test CVE", "2026-01-05", 8.1, "3.1", "CVSS:3.1/AV:N")


def test_version_range_is_saved(tmp_path):
    db = tmp_path / "t.db"
    entry = vuln(matches=[match(versionStartIncluding="1.0.0", versionEndExcluding="2.4.0")])
    load_nvd(write_nvd(tmp_path, [entry]), db)
    row = query(db, "SELECT vendor, product, version_exact, version_start_including, "
                    "version_start_excluding, version_end_including, version_end_excluding "
                    "FROM cve_affected_products")[0]
    assert row == ("exampleco", "examplelib", None, "1.0.0", None, None, "2.4.0")


def test_specific_cpe_version_is_saved_as_exact(tmp_path):
    db = tmp_path / "t.db"
    entry = vuln(matches=[match("cpe:2.3:a:democo:demoparser:1.0.4:*:*:*:*:*:*:*")])
    load_nvd(write_nvd(tmp_path, [entry]), db)
    row = query(db, "SELECT product, version_exact FROM cve_affected_products")[0]
    assert row == ("demoparser", "1.0.4")


def test_all_versions_means_no_version_columns(tmp_path):
    db = tmp_path / "t.db"
    load_nvd(write_nvd(tmp_path, [vuln(matches=[match()])]), db)
    row = query(db, "SELECT version_exact, version_start_including, version_start_excluding, "
                    "version_end_including, version_end_excluding FROM cve_affected_products")[0]
    assert row == (None, None, None, None, None)


def test_missing_cvss_is_stored_as_null_not_zero(tmp_path):
    db = tmp_path / "t.db"
    report = load_nvd(write_nvd(tmp_path, [vuln(score=None)]), db)
    assert report.without_cvss == 1
    assert query(db, "SELECT cvss_score, cvss_version FROM cves") == [(None, None)]


def test_cve_without_configurations_is_loaded_and_counted(tmp_path):
    db = tmp_path / "t.db"
    report = load_nvd(write_nvd(tmp_path, [vuln(matches=None)]), db)
    assert report.loaded == 1 and report.without_products == 1
    assert query(db, "SELECT * FROM cve_affected_products") == []


def test_not_vulnerable_entries_are_ignored(tmp_path):
    db = tmp_path / "t.db"
    entry = vuln(matches=[match(), match("cpe:2.3:o:oscorp:someos:*:*:*:*:*:*:*:*", vulnerable=False)])
    load_nvd(write_nvd(tmp_path, [entry]), db)
    assert query(db, "SELECT product FROM cve_affected_products") == [("examplelib",)]


def test_duplicate_product_entries_are_stored_once(tmp_path):
    db = tmp_path / "t.db"
    entry = vuln(matches=[match(versionEndExcluding="2.4.0"), match(versionEndExcluding="2.4.0")])
    load_nvd(write_nvd(tmp_path, [entry]), db)
    assert len(query(db, "SELECT * FROM cve_affected_products")) == 1


def test_english_description_is_chosen(tmp_path):
    db = tmp_path / "t.db"
    descs = [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "hello"}]
    load_nvd(write_nvd(tmp_path, [vuln(descriptions=descs)]), db)
    assert query(db, "SELECT description FROM cves") == [("hello",)]


def test_cvss_v31_is_preferred_over_v2(tmp_path):
    db = tmp_path / "t.db"
    metrics = {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}}],
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.0}}],
    }
    load_nvd(write_nvd(tmp_path, [vuln(metrics=metrics)]), db)
    assert query(db, "SELECT cvss_score, cvss_version FROM cves") == [(9.0, "3.1")]


def test_cvss_v2_is_used_when_it_is_the_only_one(tmp_path):
    db = tmp_path / "t.db"
    metrics = {"cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 7.5}}]}
    load_nvd(write_nvd(tmp_path, [vuln(metrics=metrics)]), db)
    assert query(db, "SELECT cvss_score, cvss_version FROM cves") == [(7.5, "2.0")]


def test_bad_cve_id_is_rejected(tmp_path):
    report = validate_nvd(write_nvd(tmp_path, [vuln("CVE-99-1")]))
    assert not report.valid and "not a valid CVE id" in report.errors[0][1]


def test_score_out_of_range_is_rejected(tmp_path):
    report = validate_nvd(write_nvd(tmp_path, [vuln(score=11.5)]))
    assert "not a number between 0 and 10" in report.errors[0][1]


def test_text_score_is_rejected(tmp_path):
    report = validate_nvd(write_nvd(tmp_path, [vuln(score="high")]))
    assert "baseScore" in report.errors[0][1]


def test_impossible_date_is_rejected(tmp_path):
    report = validate_nvd(write_nvd(tmp_path, [vuln(published="2026-02-30T00:00:00.000")]))
    assert "not a valid date" in report.errors[0][1]


def test_invalid_cpe_rejects_the_whole_cve(tmp_path):
    db = tmp_path / "t.db"
    entry = vuln(matches=[match(), match("cpe:2.3:a:onlyvendor")])
    report = load_nvd(write_nvd(tmp_path, [entry]), db)
    assert report.loaded == 0 and "invalid cpe criteria" in report.errors[0][1]
    assert query(db, "SELECT * FROM cves") == []          # nothing partial is saved
    assert query(db, "SELECT * FROM cve_affected_products") == []


def test_non_object_entry_is_rejected(tmp_path):
    report = validate_nvd(write_nvd(tmp_path, ["oops"]))
    assert "no 'cve' object" in report.errors[0][1]


def test_duplicate_cve_in_file_is_rejected(tmp_path):
    report = validate_nvd(write_nvd(tmp_path, [vuln(), vuln()]))
    assert len(report.valid) == 1 and "duplicate" in report.errors[0][1]


def test_missing_vulnerabilities_list_is_rejected(tmp_path):
    path = tmp_path / "nolist.json"
    path.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    assert "'vulnerabilities' list is missing" in validate_nvd(path).errors[0][1]


def test_invalid_json_fails_and_is_logged(tmp_path):
    db = tmp_path / "t.db"
    path = tmp_path / "bad.json"
    path.write_text("{ nope", encoding="utf-8")
    report = load_nvd(path, db)
    assert report.file_error and "not valid JSON" in report.errors[0][1]
    assert query(db, "SELECT status FROM data_fetch_log") == [("failed",)]


def test_missing_file_is_reported_not_crashed(tmp_path):
    report = validate_nvd(tmp_path / "does_not_exist.json")
    assert report.file_error and "cannot read file" in report.errors[0][1]


def test_reloading_replaces_products_and_updates_score(tmp_path):
    db = tmp_path / "t.db"
    load_nvd(write_nvd(tmp_path, [vuln(score=5.0)]), db)
    load_nvd(write_nvd(tmp_path, [vuln(score=9.5, matches=[match(versionEndExcluding="3.0.0")])]), db)
    assert query(db, "SELECT cvss_score FROM cves") == [(9.5,)]
    assert query(db, "SELECT version_end_excluding FROM cve_affected_products") == [("3.0.0",)]


def test_empty_cve_row_from_kev_is_filled_by_nvd(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO cves (cve_id) VALUES ('CVE-2099-0001')")   # like the KEV loader does
    conn.commit()
    conn.close()
    load_nvd(write_nvd(tmp_path, [vuln()]), db)
    assert query(db, "SELECT description, cvss_score FROM cves") == [("test CVE", 8.1)]


def test_fetch_log_records_counts(tmp_path):
    db = tmp_path / "t.db"
    load_nvd(write_nvd(tmp_path, [vuln(), vuln("CVE-99-1")]), db, now="2026-10-16T12:00:00+00:00")
    row = query(db, "SELECT source, mode, records_read, records_loaded, records_rejected, status, "
                    "fetched_at FROM data_fetch_log")[0]
    assert row == ("NVD", "snapshot", 2, 1, 1, "partial", "2026-10-16T12:00:00+00:00")


def test_only_cves_narrows_scope(tmp_path):
    db = tmp_path / "t.db"
    entries = [vuln("CVE-2099-0001"), vuln("CVE-2099-0002")]
    report = load_nvd(write_nvd(tmp_path, entries), db, only_cves={"CVE-2099-0002"})
    assert report.loaded == 1 and report.skipped_out_of_scope == 1
    assert query(db, "SELECT cve_id FROM cves") == [("CVE-2099-0002",)]


def test_project_sample_files_behave_as_expected():
    good = validate_nvd("data/snapshots/nvd_sample.json")
    assert good.total == 6 and len(good.valid) == 6 and not good.errors
    by_id = {c["cve_id"]: c for c in good.valid}
    assert by_id["CVE-2099-0005"]["cvss_score"] is None and by_id["CVE-2099-0005"]["products"] == []
    assert by_id["CVE-2099-0006"]["cvss_version"] == "2.0"
    assert by_id["CVE-2099-0003"]["products"][0]["version_exact"] == "1.0.4"
    assert by_id["CVE-2099-0004"]["products"][0]["version_start_excluding"] == "2.3.1"
    bad = validate_nvd("data/snapshots/nvd_invalid_demo.json")
    assert len(bad.valid) == 1 and len(bad.errors) == 5