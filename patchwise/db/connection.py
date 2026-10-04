"""SQLite connection helpers for PatchWise.

Only this package talks to the database file directly. Other modules call
these helpers, so the database rules live in one place.
"""

import sqlite3
from pathlib import Path

# .../PatchWise/patchwise/db/connection.py -> parents[2] is the project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "patchwise.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_connection(db_path=None):
    """Open the database file and return a connection."""
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row            # read columns by name: row["hostname"]
    conn.execute("PRAGMA foreign_keys = ON")  # make SQLite enforce table links
    return conn


def init_db(db_path=None):
    """Create the tables from schema.sql (safe to run repeatedly)."""
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn = get_connection(db_path)
    try:
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()
    return Path(db_path) if db_path is not None else DEFAULT_DB_PATH


def list_tables(conn):
    """Return the names of all user tables in the database."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [row["name"] for row in rows]


if __name__ == "__main__":
    db_file = init_db()
    conn = get_connection(db_file)
    try:
        print(f"Database ready at: {db_file}")
        print(f"Tables: {list_tables(conn)}")
    finally:
        conn.close()