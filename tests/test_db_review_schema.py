import sqlite3

from patchwise.db.connection import get_connection, init_db, list_tables


def test_init_db_creates_the_decisions_table_and_its_triggers(tmp_path):
    db = tmp_path / "t.db"
    init_db(db)
    conn = get_connection(db)
    try:
        assert "decisions" in list_tables(conn)
        triggers = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
        assert {"decisions_no_update", "decisions_no_delete"} <= triggers
    finally:
        conn.close()


def test_init_db_can_run_many_times(tmp_path):
    db = tmp_path / "t.db"
    for _ in range(3):
        init_db(db)
    conn = get_connection(db)
    try:
        assert list_tables(conn).count("decisions") == 1
    finally:
        conn.close()


def test_a_database_made_before_the_review_feature_gets_the_new_table(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE assets (asset_id TEXT PRIMARY KEY)")     # an old, partial database
    conn.commit()
    conn.close()
    init_db(db)
    conn = get_connection(db)
    try:
        assert "decisions" in list_tables(conn)
    finally:
        conn.close()
