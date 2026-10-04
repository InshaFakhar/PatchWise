"""Milestone 4.2 tests: the connection helper and the 'assets' table."""

import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from patchwise.db.connection import (
    DEFAULT_DB_PATH,
    get_connection,
    init_db,
    list_tables,
)


# ---------- helpers ----------

def make_db(folder):
    """Create a fresh test database inside a temporary folder."""
    db_path = Path(folder) / "test.db"
    init_db(db_path)
    return db_path


def insert_asset(conn, **overrides):
    """Insert one asset. Pass keyword arguments to change any default value."""
    values = {
        "asset_id": "A-001",
        "hostname": "web-server-01",
        "asset_type": "web server",
        "criticality": "Critical",
        "exposure": "Internet-facing",
        "environment": "prod",
    }
    values.update(overrides)
    conn.execute(
        "INSERT INTO assets "
        "(asset_id, hostname, asset_type, criticality, exposure, environment) "
        "VALUES (:asset_id, :hostname, :asset_type, :criticality, :exposure, :environment)",
        values,
    )


def database_rejects(folder, **bad_values):
    """True if the database refuses an asset built with these values."""
    db_path = make_db(folder)
    with closing(get_connection(db_path)) as conn:
        try:
            insert_asset(conn, **bad_values)
        except sqlite3.IntegrityError:
            return True
    return False


# ---------- tests ----------

def test_init_db_creates_assets_table():
    with tempfile.TemporaryDirectory() as folder:
        db_path = make_db(folder)
        with closing(get_connection(db_path)) as conn:
            assert "assets" in list_tables(conn)


def test_init_db_can_run_twice_without_error():
    with tempfile.TemporaryDirectory() as folder:
        db_path = make_db(folder)
        with closing(get_connection(db_path)) as conn:
            tables_before = list_tables(conn)
        init_db(db_path)  # second run must not fail or change anything
        with closing(get_connection(db_path)) as conn:
            assert list_tables(conn) == tables_before


def test_can_insert_and_read_back_an_asset():
    with tempfile.TemporaryDirectory() as folder:
        db_path = make_db(folder)
        with closing(get_connection(db_path)) as conn:
            insert_asset(conn)
            conn.commit()
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_id = ?", ("A-001",)
            ).fetchone()
            assert row["hostname"] == "web-server-01"
            assert row["criticality"] == "Critical"
            assert row["exposure"] == "Internet-facing"


def test_duplicate_asset_id_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        db_path = make_db(folder)
        with closing(get_connection(db_path)) as conn:
            insert_asset(conn)
            try:
                insert_asset(conn, hostname="another-box")  # same asset_id
            except sqlite3.IntegrityError:
                return
            raise AssertionError("Duplicate asset_id was accepted")


def test_invalid_criticality_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        assert database_rejects(folder, criticality="Super-Important")


def test_invalid_exposure_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        assert database_rejects(folder, exposure="Everywhere")


def test_invalid_environment_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        assert database_rejects(folder, environment="production")


def test_missing_required_value_is_rejected():
    with tempfile.TemporaryDirectory() as folder:
        db_path = make_db(folder)
        with closing(get_connection(db_path)) as conn:
            try:
                conn.execute("INSERT INTO assets (asset_id) VALUES ('A-009')")
            except sqlite3.IntegrityError:
                return
            raise AssertionError("Asset without required columns was accepted")


def test_default_database_lives_in_data_folder():
    assert DEFAULT_DB_PATH.name == "patchwise.db"
    assert DEFAULT_DB_PATH.parent.name == "data"