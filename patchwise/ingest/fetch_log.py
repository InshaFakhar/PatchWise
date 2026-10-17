"""Helpers for the data_fetch_log table (shared by KEV, EPSS and NVD loaders)."""

from datetime import datetime, timezone


def now_utc():
    """Current time in UTC, e.g. '2026-10-16T12:00:00+00:00'."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_fetch(conn, source, origin, mode, read, loaded, rejected, status,
              fetched_at=None, note=None):
    """Add one row to data_fetch_log. The caller owns the transaction."""
    conn.execute(
        """
        INSERT INTO data_fetch_log
            (source, origin, mode, fetched_at, records_read, records_loaded,
             records_rejected, status, note)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (source, origin, mode, fetched_at or now_utc(), read, loaded,
         rejected, status, note),
    )