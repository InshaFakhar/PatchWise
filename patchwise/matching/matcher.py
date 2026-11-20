"""Matching engine (FR-04).

Question: "Is this installed component affected by this CVE, and HOW SURE are we?"

Inputs : components (from the SBOM) and cve_affected_products (from NVD).
Output : one row per (component, CVE) in the `matches` table, with a status:

    confirmed         name AND vendor match, and the version is inside a real
                      version range (or an exact version) given by NVD.
    probable          the name matches, but something is weaker: the component
                      has no vendor to compare, or NVD says "all versions".
    uncertain         weak name evidence (vendor conflict, partial name), or the
                      version exists but cannot be compared.
    insufficient_data the component has NO version, so a version range cannot be
                      checked.  We say so instead of guessing.

If the version is clearly OUTSIDE the affected range there is no match at all.

This module only decides matches. It never computes a risk score (that is the
ranking engine's job) and it never talks to an LLM.
"""

import re
import sys
from dataclasses import dataclass, field

from patchwise.db.connection import get_connection, init_db
from patchwise.matching.versions import (
    IN_RANGE, OUT_OF_RANGE, row_range_status,
)

# ---- statuses (best first) ----
CONFIRMED = "confirmed"
PROBABLE = "probable"
UNCERTAIN = "uncertain"
INSUFFICIENT = "insufficient_data"
STATUS_ORDER = (CONFIRMED, PROBABLE, UNCERTAIN, INSUFFICIENT)

# ---- how well the NAMES agree ----
CPE_EXACT = "cpe_exact"                # the component's own CPE equals the NVD product
NAME_VENDOR = "name_vendor_exact"      # same name and same vendor
NAME_ONLY = "name_only"                # same name, component has no vendor
VENDOR_CONFLICT = "vendor_conflict"    # same name, DIFFERENT vendor
FUZZY = "fuzzy"                        # names only partly agree (shared words)

NAME_TEXT = {
    CPE_EXACT: "the component's CPE equals the affected product",
    NAME_VENDOR: "name and vendor match the affected product",
    NAME_ONLY: "name matches, but the component has no vendor to compare",
    VENDOR_CONFLICT: "name matches, but the vendor is different",
    FUZZY: "the name only partly matches the affected product",
}

_RANGE_COLUMNS = (
    "version_exact", "version_start_including", "version_start_excluding",
    "version_end_including", "version_end_excluding",
)


# ---------- name helpers ----------

def _norm(text):
    """'Example-Lib ' -> 'example_lib' (lowercase, punctuation -> underscore)."""
    return re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_")


def _tokens(norm):
    return {t for t in norm.split("_") if t}


def _cpe_vendor_product(cpe):
    """('exampleco', 'examplelib') from a CPE 2.3 string, or None."""
    if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
        return None
    parts = re.split(r"(?<!\\):", cpe)
    if len(parts) < 5:
        return None
    vendor, product = _norm(parts[3]), _norm(parts[4])
    return (vendor, product) if vendor and product else None


def name_evidence(component, product_row):
    """How well do the component and the NVD product agree by NAME? None = not related."""
    row_vendor = _norm(product_row.get("vendor"))
    row_product = _norm(product_row.get("product"))

    own_cpe = _cpe_vendor_product(component.get("cpe"))
    if own_cpe is not None and own_cpe == (row_vendor, row_product):
        return CPE_EXACT

    name = _norm(component.get("name"))
    vendor = _norm(component.get("vendor"))
    if name and name == row_product:
        if not vendor:
            return NAME_ONLY
        return NAME_VENDOR if vendor == row_vendor else VENDOR_CONFLICT

    a, b = _tokens(name), _tokens(row_product)
    if a and b and (a <= b or b <= a):
        smaller = a if len(a) <= len(b) else b
        if sum(len(t) for t in smaller) >= 4:     # ignore tiny overlaps like 'ab'
            return FUZZY
    return None


# ---------- version helpers ----------

def _has_bounds(row):
    return any((row.get(c) or "").strip() for c in _RANGE_COLUMNS)


def describe_range(row):
    """Human text for a range: '< 2.4.0', '>= 5.0.0, <= 5.2.0', '= 1.0.4', 'all versions'."""
    pieces = []
    for column, symbol in (
        ("version_exact", "="),
        ("version_start_including", ">="),
        ("version_start_excluding", ">"),
        ("version_end_including", "<="),
        ("version_end_excluding", "<"),
    ):
        value = (row.get(column) or "").strip()
        if value:
            pieces.append(f"{symbol} {value}")
    return ", ".join(pieces) if pieces else "all versions"


# ---------- the decision ----------

def decide(name_ev, version_status, version_text, row):
    """Return (status, version_evidence, reason) or None when there is no match."""
    if version_status == OUT_OF_RANGE:
        return None

    strong = name_ev in (CPE_EXACT, NAME_VENDOR)
    unclear_name = name_ev in (VENDOR_CONFLICT, FUZZY)
    version_present = bool((version_text or "").strip())
    bounded = _has_bounds(row)

    if version_status == IN_RANGE:
        if bounded:
            version_evidence = "in_range"
            version_reason = f"version {version_text} is inside the affected range ({describe_range(row)})"
            status = CONFIRMED if strong else (UNCERTAIN if unclear_name else PROBABLE)
        else:
            version_evidence = "all_versions"
            version_reason = "NVD lists all versions of this product as affected"
            status = UNCERTAIN if unclear_name else PROBABLE
    else:  # the version could not be checked against the range
        if not version_present:
            version_evidence = "version_missing"
            version_reason = f"the component has no version, so the range ({describe_range(row)}) cannot be checked"
            status = UNCERTAIN if unclear_name else INSUFFICIENT
        else:
            version_evidence = "not_comparable"
            version_reason = f"version '{version_text}' could not be compared with the range ({describe_range(row)})"
            status = UNCERTAIN

    return status, version_evidence, f"{NAME_TEXT[name_ev]}; {version_reason}."


def find_matches(components, affected_rows):
    """Pure function: lists of dicts in, list of match dicts out (no database).

    Several NVD rows can point at the same (component, CVE). The strongest
    status wins; ties keep the row that comes first (lowest id), so the result
    never depends on input order.
    """
    best = {}
    for comp in sorted(components, key=lambda c: c["component_id"]):
        for row in sorted(affected_rows, key=lambda r: r["id"]):
            if row.get("cpe_part") != "a":          # only applications / libraries
                continue
            ev = name_evidence(comp, row)
            if ev is None:
                continue
            version_status = row_range_status(comp.get("version"), row)
            decision = decide(ev, version_status, comp.get("version"), row)
            if decision is None:
                continue
            status, version_evidence, reason = decision
            key = (comp["component_id"], row["cve_id"])
            rank = STATUS_ORDER.index(status)
            if key not in best or rank < best[key]["_rank"]:
                best[key] = {
                    "_rank": rank,
                    "component_id": comp["component_id"],
                    "cve_id": row["cve_id"],
                    "status": status,
                    "name_evidence": ev,
                    "version_evidence": version_evidence,
                    "reason": reason,
                    "affected_cpe": row.get("cpe_criteria"),
                }
    result = [{k: v for k, v in m.items() if k != "_rank"} for m in best.values()]
    result.sort(key=lambda m: (m["component_id"], m["cve_id"]))
    return result


# ---------- database ----------

@dataclass
class MatchingReport:
    components: int = 0
    affected_rows: int = 0
    matches: list = field(default_factory=list)

    @property
    def counts(self):
        counts = {s: 0 for s in STATUS_ORDER}
        for m in self.matches:
            counts[m["status"]] += 1
        return counts

    def summary(self):
        c = self.counts
        return "\n".join([
            f"Components checked: {self.components}",
            f"NVD affected-product rows used: {self.affected_rows}",
            f"Matches: {len(self.matches)}",
            *(f"  {status}: {c[status]}" for status in STATUS_ORDER),
        ])


def run_matching(db_path=None):
    """Recompute every match from the database and save them in `matches`."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        components = [dict(r) for r in conn.execute(
            "SELECT component_id, asset_id, name, version, vendor, cpe "
            "FROM components ORDER BY component_id")]
        rows = [dict(r) for r in conn.execute(
            "SELECT id, cve_id, cpe_part, vendor, product, version_exact, "
            "version_start_including, version_start_excluding, version_end_including, "
            "version_end_excluding, cpe_criteria FROM cve_affected_products ORDER BY id")]
        matches = find_matches(components, rows)
        with conn:   # delete + insert in ONE transaction: never a half-updated table
            conn.execute("DELETE FROM matches")
            conn.executemany(
                """
                INSERT INTO matches (component_id, cve_id, status, name_evidence,
                                     version_evidence, reason, affected_cpe)
                VALUES (:component_id, :cve_id, :status, :name_evidence,
                        :version_evidence, :reason, :affected_cpe)
                """,
                matches,
            )
    finally:
        conn.close()
    return MatchingReport(components=len(components), affected_rows=len(rows), matches=matches)


if __name__ == "__main__":
    # Temporary runner until the real CLI exists (Phase 14).
    print(run_matching().summary())