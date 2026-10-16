import sqlite3

from patchwise.ingest.inventory import import_inventory, validate_inventory

HEADER = "asset_id,hostname,asset_type,criticality,exposure,environment\n"


def write_csv(tmp_path, body, header=HEADER):
    path = tmp_path / "assets.csv"
    path.write_text(header + body, encoding="utf-8")
    return path


def count_assets(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    finally:
        conn.close()


def test_valid_file_is_imported(tmp_path):
    csv_file = write_csv(tmp_path, "A1,web-01,server,High,DMZ,prod\nA2,db-01,database,Low,Internal,dev\n")
    db = tmp_path / "t.db"
    report = import_inventory(csv_file, db)
    assert not report.errors
    assert report.added == 2
    assert count_assets(db) == 2


def test_invalid_value_is_reported_and_valid_rows_still_imported(tmp_path):
    csv_file = write_csv(tmp_path, "A1,web-01,server,High,DMZ,prod\nA2,db-01,database,Super,Internal,dev\n")
    db = tmp_path / "t.db"
    report = import_inventory(csv_file, db)
    assert len(report.errors) == 1
    line, message = report.errors[0]
    assert line == 3 and "criticality 'Super'" in message
    assert count_assets(db) == 1


def test_duplicate_asset_id_is_rejected(tmp_path):
    csv_file = write_csv(tmp_path, "A1,web-01,server,High,DMZ,prod\nA1,web-02,server,Low,Internal,dev\n")
    report = validate_inventory(csv_file)
    assert len(report.valid_rows) == 1
    assert "duplicate asset_id 'A1'" in report.errors[0][1]


def test_empty_field_is_reported(tmp_path):
    csv_file = write_csv(tmp_path, "A1,,server,High,DMZ,prod\n")
    report = validate_inventory(csv_file)
    assert "hostname is empty" in report.errors[0][1]


def test_missing_column_rejects_whole_file(tmp_path):
    csv_file = write_csv(tmp_path, "A1,web-01,server,High,DMZ\n",
                         header="asset_id,hostname,asset_type,criticality,exposure\n")
    report = validate_inventory(csv_file)
    assert not report.valid_rows
    assert "missing required column" in report.errors[0][1]


def test_empty_file_is_reported(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    assert validate_inventory(path).errors[0][1] == "file is empty"


def test_importing_twice_does_not_create_duplicates(tmp_path):
    csv_file = write_csv(tmp_path, "A1,web-01,server,High,DMZ,prod\n")
    db = tmp_path / "t.db"
    import_inventory(csv_file, db)
    second = import_inventory(csv_file, db)
    assert second.added == 0 and second.updated == 1
    assert count_assets(db) == 1


def test_project_sample_files_behave_as_expected(tmp_path):
    good = validate_inventory("data/synthetic/assets.csv")
    assert len(good.valid_rows) == 12 and not good.errors
    bad = validate_inventory("data/synthetic/assets_invalid_demo.csv")
    assert len(bad.valid_rows) == 1 and len(bad.errors) == 3