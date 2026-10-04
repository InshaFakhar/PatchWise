"""Milestone 4.3 tests: the 'cves', 'kev' and 'epss' tables."""

import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from patchwise.db.connection import get_connection, init_db, list_tables


# ---------- helpers ----------

def make_db(folder):
    """Create a fresh test database inside a temporary folder."""
    db_path = Path(folder) / "test.db"
    init_db(db_path)
    return db_path


def insert_cve(conn, **overrides):
    values = {
        "cve_id": "CVE-2021-44228",
        "description": "Example description",
        "published_date": "2021-12-10",
        "cvss_score": 10.0,
        "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    values.update(overrides)
    conn.execute(
        "INSERT INTO cves (cve_id, description, published_date, cvss_score, "
        "cvss_version, cvss_vector) VALUES "
        "(:cve_id, :description, :published_date, :cvss_score, "
        ":cvss_version, :cvss_vector)",
        values,
    )


def insert_kev(conn, **overrides):
    values = {
        "cve_id": "CVE-2021-44228",
        "vendor_project": "Apache",
        "product": "Log4j2",
        "date_added": "2021-12-10",
        "due_date": "2021-12-24",
        "known_ransomware_use": "Known",
    }
    values.update(overrides)
    conn.execute(
        "INSERT INTO kev (cve_id, vendor_project, product, date_added, due_date, "
        "known_ransomware_use) VALUES (:cve_id, :vendor_project, :product, "
        ":date_added, :due_date, :known_ransomware_use)",
        values,
    )


def insert_epss(conn, **overrides):
    values = {
        "cve_id": "CVE-2021-44228",
        "epss_score": 0.94358,
        "percentile": 0.99975,
        "score_date": "2026-10-01",
        "model_version": "v2025.03.14",
    }
    values.update(overrides)
    conn.execute(
        "INSERT INTO epss (cve_id, epss_score, percentile, score_date, model_version) "
        "VALUES (:cve_id, :epss_score, :percentile, :score_date, :model_version)",
        values,
    )


def is_rejected(insert_function, conn, **values):
    """True if the database refuses this insert with an IntegrityError."""
    try:
        insert_function(conn, **values)
    except sqlite3.IntegrityError:
        return True
    return False


# ---------- table existence ----------

def test_public_data_tables_are_created():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            tables = list_tables(conn)
            for name in ("assets", "cves", "kev", "epss"):
                assert name in tables


# ---------- cves ----------

def test_can_insert_and_read_back_a_cve():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            row = conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?", ("CVE-2021-44228",)
            ).fetchone()
            assert row["cvss_score"] == 10.0
            assert row["published_date"] == "2021-12-10"


def test_missing_cvss_is_stored_as_null_not_zero():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn, cvss_score=None, cvss_version=None, cvss_vector=None)
            row = conn.execute("SELECT cvss_score FROM cves").fetchone()
            assert row["cvss_score"] is None


def test_bad_cve_id_format_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            assert is_rejected(insert_cve, conn, cve_id="CVE2021-44228")
            assert is_rejected(insert_cve, conn, cve_id="cve-2021-44228")
            assert is_rejected(insert_cve, conn, cve_id="not-a-cve")


def test_cvss_score_must_be_between_0_and_10():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            assert is_rejected(insert_cve, conn, cvss_score=10.5)
            assert is_rejected(insert_cve, conn, cvss_score=-1)


def test_bad_date_format_is_rejected_in_cves():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            assert is_rejected(insert_cve, conn, published_date="10/12/2021")


def test_duplicate_cve_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            assert is_rejected(insert_cve, conn)


# ---------- kev ----------

def test_can_insert_and_read_back_a_kev_row():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            insert_kev(conn)
            row = conn.execute("SELECT * FROM kev").fetchone()
            assert row["vendor_project"] == "Apache"
            assert row["known_ransomware_use"] == "Known"


def test_kev_row_requires_an_existing_cve():
    """Proves foreign keys are really enforced (PRAGMA in get_connection)."""
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            assert is_rejected(insert_kev, conn, cve_id="CVE-2099-0001")


def test_kev_rejects_bad_date_and_bad_ransomware_value():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            assert is_rejected(insert_kev, conn, date_added="10/12/2021")
            assert is_rejected(insert_kev, conn, known_ransomware_use="Maybe")


# ---------- epss ----------

def test_can_insert_and_read_back_an_epss_row():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            insert_epss(conn)
            row = conn.execute("SELECT * FROM epss").fetchone()
            assert row["epss_score"] == 0.94358
            assert row["score_date"] == "2026-10-01"


def test_epss_row_requires_an_existing_cve():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            assert is_rejected(insert_epss, conn, cve_id="CVE-2099-0001")


def test_epss_values_must_be_between_0_and_1():
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            assert is_rejected(insert_epss, conn, epss_score=1.5)
            assert is_rejected(insert_epss, conn, epss_score=-0.1)
            assert is_rejected(insert_epss, conn, percentile=2)


# ---------- the three tables working together ----------

def test_cve_without_kev_or_epss_is_valid():
    """'Not in KEV' and 'no EPSS score' are normal situations, not errors."""
    with tempfile.TemporaryDirectory() as folder:
        with closing(get_connection(make_db(folder))) as conn:
            insert_cve(conn)
            row = conn.execute(
                "SELECT c.cve_id, k.cve_id AS kev_id, e.epss_score "
                "FROM cves c "
                "LEFT JOIN kev k ON k.cve_id = c.cve_id "
                "LEFT JOIN epss e ON e.cve_id = c.cve_id"
            ).fetchone()
            assert row["cve_id"] == "CVE-2021-44228"
            assert row["kev_id"] is None
            assert row["epss_score"] is None