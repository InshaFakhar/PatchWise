"""Analyst decisions: Accept / Bump / Defer, with an append-only audit history (FR-07).

A decision never changes the PatchWise score or rank. It is a SEPARATE human layer
on top of the deterministic ranking (see queue.py).

    accept  the analyst agrees with the priority as it is
    bump    the analyst wants this handled earlier (moved to the top of the queue)
    defer   the analyst wants this handled later (moved to the bottom of the queue)

Every decision needs a reason and the analyst's name. Rows are only ever ADDED:
database triggers refuse UPDATE and DELETE, so the history cannot be rewritten.
The current decision for a finding is its newest row.
"""

import re
from datetime import datetime, timezone

ACTIONS = ("accept", "bump", "defer")
ACTION_LABELS = {"accept": "Accept", "bump": "Bump", "defer": "Defer"}
MAX_REASON = 500
MAX_ANALYST = 80
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def validate_decision(component_id, cve_id, action, reason, analyst):
    """Return (component_id:int, cve_id, action, reason, analyst) cleaned, or raise ValueError."""
    if isinstance(component_id, bool):
        raise ValueError("component id is not valid")
    try:
        component_id = int(str(component_id).strip())
    except ValueError:
        raise ValueError("component id is not valid") from None
    if component_id <= 0:
        raise ValueError("component id is not valid")

    cve_id = (cve_id or "").strip()
    if not _CVE_RE.fullmatch(cve_id):
        raise ValueError("CVE id is not valid")

    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise ValueError("action must be Accept, Bump or Defer")

    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    if len(reason) > MAX_REASON:
        raise ValueError(f"the reason is too long (max {MAX_REASON} characters)")

    analyst = (analyst or "").strip()
    if not analyst:
        raise ValueError("the analyst name is required")
    if len(analyst) > MAX_ANALYST:
        raise ValueError(f"the analyst name is too long (max {MAX_ANALYST} characters)")

    return component_id, cve_id, action, reason, analyst


def add_decision(conn, component_id, cve_id, action, reason, analyst,
                 rank=None, score=None, now=None):
    """Append one decision. The caller owns the transaction. Returns the new decision_id."""
    component_id, cve_id, action, reason, analyst = validate_decision(
        component_id, cve_id, action, reason, analyst)
    decided_at = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        "INSERT INTO decisions (component_id, cve_id, action, reason, analyst_name, decided_at, "
        "rank_at_decision, score_at_decision) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (component_id, cve_id, action, reason, analyst, decided_at, rank, score),
    )
    return cur.lastrowid


def latest_decisions(conn):
    """{(component_id, cve_id): decision dict} holding the NEWEST decision of each finding."""
    rows = conn.execute(
        "SELECT decision_id, component_id, cve_id, action, reason, analyst_name, decided_at, "
        "rank_at_decision, score_at_decision FROM decisions ORDER BY decision_id").fetchall()
    return {(r["component_id"], r["cve_id"]): dict(r) for r in rows}


def list_decisions(conn):
    """The full audit history, newest first, with asset and software names."""
    rows = conn.execute(
        """
        SELECT d.decision_id, d.decided_at, d.analyst_name, d.action, d.reason,
               d.rank_at_decision, d.score_at_decision, d.component_id, d.cve_id,
               c.name AS component, c.version AS component_version,
               a.asset_id, a.hostname
        FROM decisions d
        JOIN components c ON c.component_id = d.component_id
        JOIN assets a ON a.asset_id = c.asset_id
        ORDER BY d.decision_id DESC
        """).fetchall()
    return [dict(r) for r in rows]
