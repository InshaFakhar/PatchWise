"""Shared service layer (PD-14). (Built progressively from Phase 4.)

Both the CLI and the FastAPI web interface call the functions defined here,
so the application logic is written once. Web routes stay thin.
"""

import tempfile
from pathlib import Path

from patchwise.db.connection import get_connection, init_db
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.sbom import import_sbom
from patchwise.matching import matcher
from patchwise.export import reports
from patchwise.ranking import analysis, scoring
from patchwise.review import decisions, queue as review_queue

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


# ---------- matching and findings ----------

def run_matching(db_path=None):
    """Recompute all matches. Returns the number of matches per status."""
    return matcher.run_matching(db_path).counts


def list_findings(db_path=None):
    """Every match with its asset, component and public signals (KEV, EPSS, CVSS).

    Sorted by how sure the match is (confirmed first), then asset, then CVE.
    NOTE: this is NOT the priority ranking. The ranking engine comes later.
    """
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT m.match_id, m.component_id, m.status, m.name_evidence, m.version_evidence, m.reason,
                   a.asset_id, a.hostname, a.criticality, a.exposure,
                   c.name AS component, c.version AS component_version,
                   v.cve_id, v.cvss_score, v.cvss_version,
                   (k.cve_id IS NOT NULL) AS in_kev,
                   k.known_ransomware_use, k.due_date AS kev_due_date,
                   e.epss_score
            FROM matches m
            JOIN components c ON c.component_id = m.component_id
            JOIN assets a ON a.asset_id = c.asset_id
            JOIN cves v ON v.cve_id = m.cve_id
            LEFT JOIN kev k ON k.cve_id = m.cve_id
            LEFT JOIN epss e ON e.cve_id = m.cve_id
            ORDER BY CASE m.status WHEN 'confirmed' THEN 1 WHEN 'probable' THEN 2
                                   WHEN 'uncertain' THEN 3 ELSE 4 END,
                     a.asset_id, v.cve_id, c.name, m.match_id
            """
        ).fetchall()
        findings = [dict(r) for r in rows]
        for f in findings:
            f["in_kev"] = bool(f["in_kev"])
        return findings
    finally:
        conn.close()


def count_by_status(findings):
    """{'confirmed': 3, 'probable': 2, ...} (all four keys always present)."""
    counts = {s: 0 for s in matcher.STATUS_ORDER}
    for f in findings:
        counts[f["status"]] += 1
    return counts


# ---------- ranking ----------

def list_ranked(db_path=None, config=None):
    """Findings with a priority score, its breakdown and the CVSS-only rank (best first).

    'rank' comes from the PatchWise score, 'cvss_rank' from CVSS alone (the baseline).
    """
    cfg = config if config is not None else scoring.get_config()
    findings = list_findings(db_path)
    ranked = scoring.rank_findings(findings, cfg)
    baseline = {f["match_id"]: f["cvss_rank"] for f in scoring.rank_cvss_only(findings)}
    for item in ranked:
        item["cvss_rank"] = baseline[item["match_id"]]
    return ranked


def weight_shares(config=None):
    """[('CVSS', 20.0), ('EPSS', 25.0), ...]: the weights as percentages, in display order."""
    shares = scoring.weight_shares(config)
    return [(scoring.FACTOR_LABELS[f], shares[f]) for f in scoring.FACTORS]


def sensitivity_report(db_path=None, config=None):
    """How much does the ranking change if one weight changes by +/-50 percent?"""
    cfg = config if config is not None else scoring.get_config()
    return analysis.sensitivity(list_findings(db_path), cfg)


# ---------- review (Accept / Bump / Defer), audit, export ----------

def record_decision(component_id, cve_id, action, reason, analyst, db_path=None):
    """Save one analyst decision. Raises ValueError with a clear message if it is not valid."""
    cid, cve_id, action, reason, analyst = decisions.validate_decision(
        component_id, cve_id, action, reason, analyst)
    finding = next((f for f in list_ranked(db_path)
                    if f["component_id"] == cid and f["cve_id"] == cve_id), None)
    if finding is None:
        raise ValueError("this finding is not in the current results (run matching first)")
    conn = get_connection(db_path)
    try:
        with conn:
            decision_id = decisions.add_decision(
                conn, cid, cve_id, action, reason, analyst,
                rank=finding["rank"], score=finding["score"])
    finally:
        conn.close()
    return decision_id


def list_queue(db_path=None, config=None):
    """The ranking with the analyst's decisions applied (bumped first, deferred last)."""
    ranked = list_ranked(db_path, config)
    conn = get_connection(db_path)
    try:
        latest = decisions.latest_decisions(conn)
    finally:
        conn.close()
    return review_queue.build_queue(ranked, latest)


def queue_counts(queue):
    return review_queue.queue_counts(queue)


def list_audit(db_path=None):
    """Every decision ever made, newest first."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        return decisions.list_decisions(conn)
    finally:
        conn.close()


def export_queue_csv(db_path=None):
    return reports.queue_to_csv(list_queue(db_path))


def export_queue_markdown(db_path=None, generated_at=None):
    from datetime import datetime, timezone
    stamp = generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return reports.queue_to_markdown(list_queue(db_path), weight_shares(), stamp)


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
