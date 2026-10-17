"""Shared service layer (PD-14). (Built progressively from Phase 4.)

Both the CLI and the FastAPI web interface call the functions defined here,
so the application logic is written once. Web routes stay thin.
"""

import tempfile
from pathlib import Path

from patchwise.db.connection import get_connection, init_db
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.sbom import import_sbom

MAX_UPLOAD_BYTES = 1_000_000  # 1 MB is plenty for our CSV / SBOM files


# ---------- reading data ----------

def list_assets(db_path=None):
    """All assets, each with the number of components it has."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT a.asset_id, a.hostname, a.asset_type, a.criticality,
                   a.exposure, a.environment,
                   COUNT(c.component_id) AS component_count
            FROM assets a
            LEFT JOIN components c ON c.asset_id = a.asset_id
            GROUP BY a.asset_id
            ORDER BY a.asset_id
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_asset(asset_id, db_path=None):
    """One asset plus its components, or None if the asset does not exist."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
        ).fetchone()
        if row is None:
            return None
        asset = dict(row)
        comps = conn.execute(
            "SELECT name, version, vendor, purl FROM components "
            "WHERE asset_id = ? ORDER BY name, version",
            (asset_id,),
        ).fetchall()
        asset["components"] = [dict(c) for c in comps]
        return asset
    finally:
        conn.close()


# ---------- uploads ----------

def _where(position):
    """Turn an error position into text: 3 -> 'line 3', 'component #2' stays."""
    return f"line {position}" if isinstance(position, int) else str(position)


def _view(title, stats, errors):
    """A plain dict the report page can show (keeps HTML out of this layer)."""
    return {
        "title": title,
        "has_errors": bool(errors),
        "stats": stats,
        "errors": [(_where(pos), msg) for pos, msg in errors],
    }


def _run_on_temp_file(content, suffix, runner):
    """Save uploaded bytes to a temp file with OUR name, run the importer on it.

    We never use the uploaded file's own name (it could contain '../' tricks).
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"upload{suffix}"
        path.write_bytes(content)
        return runner(path)


def import_inventory_upload(content, db_path=None):
    title = "Inventory import report"
    if len(content) > MAX_UPLOAD_BYTES:
        return _view(title, [], [("file", "file is too large (max 1 MB)")])
    try:
        report = _run_on_temp_file(content, ".csv", lambda p: import_inventory(p, db_path))
    except UnicodeDecodeError:
        return _view(title, [], [("file", "file is not valid UTF-8 text")])
    stats = [
        ("Rows read", report.total_rows),
        ("Valid", len(report.valid_rows)),
        ("Added", report.added),
        ("Updated", report.updated),
        ("Rejected", len(report.errors)),
    ]
    return _view(title, stats, report.errors)


def import_sbom_upload(content, asset_id, db_path=None):
    asset_id = (asset_id or "").strip()
    title = f"SBOM import report (asset {asset_id})"
    if not asset_id:
        return _view(title, [], [("file", "please choose an asset")])
    if len(content) > MAX_UPLOAD_BYTES:
        return _view(title, [], [("file", "file is too large (max 1 MB)")])
    try:
        report = _run_on_temp_file(
            content, ".json", lambda p: import_sbom(p, asset_id, db_path)
        )
    except UnicodeDecodeError:
        return _view(title, [], [("file", "file is not valid UTF-8 text")])
    stats = [
        ("Components read", report.total_components),
        ("Valid", len(report.valid)),
        ("Added", report.added),
        ("Already present", report.skipped_existing),
        ("Rejected", len(report.errors)),
    ]
    return _view(title, stats, report.errors)