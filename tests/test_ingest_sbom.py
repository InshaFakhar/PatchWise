import json
import sqlite3

from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.sbom import import_sbom, validate_sbom

INVENTORY = "data/synthetic/assets.csv"


def write_sbom(tmp_path, components, bom_format="CycloneDX"):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"bomFormat": bom_format, "components": components}), encoding="utf-8")
    return path


def make_db(tmp_path):
    db = tmp_path / "t.db"
    import_inventory(INVENTORY, db)
    return db


def rows(db, sql="SELECT * FROM components"):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def test_valid_sbom_is_imported(tmp_path):
    db = make_db(tmp_path)
    sbom = write_sbom(tmp_path, [{"name": "a", "version": "1.0"}, {"name": "b", "version": "2.0"}])
    report = import_sbom(sbom, "A001", db)
    assert not report.errors and report.added == 2
    assert len(rows(db)) == 2


def test_missing_version_is_saved_as_null(tmp_path):
    db = make_db(tmp_path)
    import_sbom(write_sbom(tmp_path, [{"name": "mystery"}]), "A001", db)
    assert rows(db, "SELECT version FROM components")[0][0] is None


def test_component_without_name_is_rejected(tmp_path):
    report = validate_sbom(write_sbom(tmp_path, [{"version": "1.0"}]))
    assert not report.valid and "name is missing" in report.errors[0][1]


def test_duplicate_component_is_rejected(tmp_path):
    comps = [{"name": "a", "version": "1.0"}, {"name": "a", "version": "1.0"}]
    report = validate_sbom(write_sbom(tmp_path, comps))
    assert len(report.valid) == 1 and "duplicate" in report.errors[0][1]


def test_non_object_component_is_rejected(tmp_path):
    report = validate_sbom(write_sbom(tmp_path, ["oops"]))
    assert "not an object" in report.errors[0][1]


def test_wrong_format_is_rejected(tmp_path):
    report = validate_sbom(write_sbom(tmp_path, [], bom_format="SPDX"))
    assert "not a CycloneDX SBOM" in report.errors[0][1]


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    assert "not valid JSON" in validate_sbom(path).errors[0][1]


def test_missing_components_list_is_rejected(tmp_path):
    path = tmp_path / "nocomp.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    assert "'components' list is missing" in validate_sbom(path).errors[0][1]


def test_unknown_asset_is_rejected_and_nothing_saved(tmp_path):
    db = make_db(tmp_path)
    report = import_sbom(write_sbom(tmp_path, [{"name": "a", "version": "1"}]), "NOPE", db)
    assert "not found" in report.errors[0][1]
    assert rows(db) == []


def test_importing_twice_does_not_create_duplicates(tmp_path):
    db = make_db(tmp_path)
    sbom = write_sbom(tmp_path, [{"name": "a", "version": "1.0"}, {"name": "m"}])
    import_sbom(sbom, "A001", db)
    second = import_sbom(sbom, "A001", db)
    assert second.added == 0 and second.skipped_existing == 2
    assert len(rows(db)) == 2


def test_project_sample_files_behave_as_expected():
    good = validate_sbom("data/synthetic/sbom_A001.json")
    assert len(good.valid) == 4 and not good.errors
    bad = validate_sbom("data/synthetic/sbom_invalid_demo.json")
    assert len(bad.valid) == 1 and len(bad.errors) == 3