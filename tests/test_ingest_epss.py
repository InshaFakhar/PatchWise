import gzip
import sqlite3

from patchwise.db.connection import init_db
from patchwise.ingest.epss import load_epss, validate_epss

META = "#model_version:v2099.01.01,score_date:2026-10-15T12:55:00Z"


def write_epss(tmp_path, rows, meta=META, header="cve,epss,percentile"):
    lines = ([meta] if meta else []) + [header] + rows
    path = tmp_path / "epss.csv"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def make_db(tmp_path, cve_ids):
    db = tmp_path / "t.db"
    init_db(db)
    conn = sqlite3.connect(db)
    for c in cve_ids:
        conn.execute("INSERT INTO cves (cve_id) VALUES (?)", (c,))
    conn.commit()
    conn.close()
    return db


def query(db, sql):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def test_valid_rows_are_loaded(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001", "CVE-2099-0002"])
    report = load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9", "CVE-2099-0002,0.1,0.4"]), db)
    assert not report.errors and report.loaded == 2
    assert len(query(db, "SELECT * FROM epss")) == 2


def test_fields_and_data_version_are_saved(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001"])
    load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9"]), db)
    assert query(db, "SELECT cve_id, epss_score, percentile, score_date, model_version FROM epss") == [
        ("CVE-2099-0001", 0.5, 0.9, "2026-10-15", "v2099.01.01")]


def test_cve_not_in_database_is_skipped(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001"])
    report = load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9", "CVE-2099-7777,0.5,0.9"]), db)
    assert report.loaded == 1 and report.skipped_out_of_scope == 1
    assert query(db, "SELECT cve_id FROM epss") == [("CVE-2099-0001",)]


def test_score_above_one_is_rejected(tmp_path):
    report = validate_epss(write_epss(tmp_path, ["CVE-2099-0001,1.7,0.9"]))
    assert not report.valid and "outside 0..1" in report.errors[0][1]


def test_non_numeric_score_is_rejected(tmp_path):
    report = validate_epss(write_epss(tmp_path, ["CVE-2099-0001,abc,0.9"]))
    assert "not a number" in report.errors[0][1]


def test_bad_percentile_is_rejected(tmp_path):
    report = validate_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,-0.2"]))
    assert "percentile" in report.errors[0][1]


def test_bad_cve_id_is_rejected(tmp_path):
    report = validate_epss(write_epss(tmp_path, ["BAD,0.5,0.9"]))
    assert "not a valid CVE id" in report.errors[0][1]


def test_duplicate_cve_is_rejected(tmp_path):
    report = validate_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9", "CVE-2099-0001,0.6,0.9"]))
    assert len(report.valid) == 1 and "duplicate" in report.errors[0][1]


def test_missing_column_fails_whole_file(tmp_path):
    report = validate_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5"], header="cve,epss"))
    assert report.file_error and "percentile" in report.errors[0][1]


def test_missing_score_date_fails_and_is_logged(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001"])
    report = load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9"], meta=None), db)
    assert report.file_error
    assert query(db, "SELECT * FROM epss") == []
    assert query(db, "SELECT status FROM data_fetch_log") == [("failed",)]


def test_gzip_file_is_supported(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001"])
    path = tmp_path / "epss.csv.gz"
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(META + "\ncve,epss,percentile\nCVE-2099-0001,0.5,0.9\n")
    assert load_epss(path, db).loaded == 1


def test_loading_again_updates_score(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001"])
    load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9"]), db)
    load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.8,0.95"]), db)
    assert query(db, "SELECT epss_score FROM epss") == [(0.8,)]


def test_fetch_log_records_counts(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001"])
    load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9", "BAD,0.5,0.9"]), db,
              now="2026-10-16T12:00:00+00:00")
    row = query(db, "SELECT source, records_read, records_loaded, records_rejected, status "
                    "FROM data_fetch_log")[0]
    assert row == ("EPSS", 2, 1, 1, "partial")


def test_only_cves_narrows_scope(tmp_path):
    db = make_db(tmp_path, ["CVE-2099-0001", "CVE-2099-0002"])
    report = load_epss(write_epss(tmp_path, ["CVE-2099-0001,0.5,0.9", "CVE-2099-0002,0.5,0.9"]), db,
                       only_cves={"CVE-2099-0002"})
    assert report.loaded == 1 and query(db, "SELECT cve_id FROM epss") == [("CVE-2099-0002",)]


def test_project_sample_files_behave_as_expected():
    good = validate_epss("data/snapshots/epss_sample.csv")
    assert len(good.valid) == 4 and not good.errors and good.score_date == "2026-10-15"
    bad = validate_epss("data/snapshots/epss_invalid_demo.csv")
    assert len(bad.valid) == 1 and len(bad.errors) == 3