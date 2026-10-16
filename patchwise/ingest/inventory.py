"""Inventory CSV importer (FR-01).

Reads a CSV of assets, checks every row, imports the valid rows into the
`assets` table and reports the invalid ones (with line numbers).
"""

import csv
import sys
from dataclasses import dataclass, field

from patchwise.db.connection import get_connection, init_db

REQUIRED_COLUMNS = [
    "asset_id", "hostname", "asset_type", "criticality", "exposure", "environment",
]

# Must match the CHECK rules in db/schema.sql.
ALLOWED_VALUES = {
    "criticality": ("Low", "Medium", "High", "Critical"),
    "exposure": ("Internal", "DMZ", "Internet-facing"),
    "environment": ("prod", "staging", "dev"),
}


@dataclass
class ImportReport:
    total_rows: int = 0
    valid_rows: list = field(default_factory=list)   # clean dicts, ready to insert
    errors: list = field(default_factory=list)       # (line_number, message)
    added: int = 0
    updated: int = 0

    def summary(self):
        lines = [
            f"Rows read: {self.total_rows}",
            f"Valid: {len(self.valid_rows)} (added {self.added}, updated {self.updated})",
            f"Rejected: {len(self.errors)}",
        ]
        lines += [f"  line {n}: {msg}" for n, msg in self.errors]
        return "\n".join(lines)


def _check_row(row):
    """Return a list of problems found in one cleaned row (empty list = OK)."""
    problems = []
    for col in REQUIRED_COLUMNS:
        if not row[col]:
            problems.append(f"{col} is empty")
    for col, allowed in ALLOWED_VALUES.items():
        value = row[col]
        if value and value not in allowed:
            problems.append(f"{col} '{value}' is not valid (allowed: {', '.join(allowed)})")
    return problems


def validate_inventory(csv_path):
    """Check the file only. Does not touch the database."""
    report = ImportReport()
    with open(csv_path, newline="", encoding="utf-8-sig") as f:  # utf-8-sig: Excel files
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            report.errors.append((1, "file is empty"))
            return report

        reader.fieldnames = [name.strip() for name in reader.fieldnames]
        missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
        if missing:
            report.errors.append((1, f"missing required column(s): {', '.join(missing)}"))
            return report

        first_seen = {}  # asset_id -> line number of its first valid row
        for row in reader:
            line = reader.line_num
            report.total_rows += 1
            clean = {c: (row.get(c) or "").strip() for c in REQUIRED_COLUMNS}

            problems = _check_row(clean)
            asset_id = clean["asset_id"]
            if asset_id in first_seen:
                problems.append(
                    f"duplicate asset_id '{asset_id}' (first seen on line {first_seen[asset_id]})"
                )

            if problems:
                report.errors.append((line, "; ".join(problems)))
            else:
                first_seen[asset_id] = line
                report.valid_rows.append(clean)
    return report


def import_inventory(csv_path, db_path=None):
    """Validate the file, then save the valid rows. Returns an ImportReport."""
    report = validate_inventory(csv_path)
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        existing = {r["asset_id"] for r in conn.execute("SELECT asset_id FROM assets")}
        with conn:  # one transaction: commits on success, rolls back on error
            for row in report.valid_rows:
                conn.execute(
                    """
                    INSERT INTO assets
                        (asset_id, hostname, asset_type, criticality, exposure, environment)
                    VALUES
                        (:asset_id, :hostname, :asset_type, :criticality, :exposure, :environment)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        hostname = excluded.hostname,
                        asset_type = excluded.asset_type,
                        criticality = excluded.criticality,
                        exposure = excluded.exposure,
                        environment = excluded.environment
                    """,
                    row,
                )
        report.updated = sum(1 for r in report.valid_rows if r["asset_id"] in existing)
        report.added = len(report.valid_rows) - report.updated
    finally:
        conn.close()
    return report


if __name__ == "__main__":
    # Temporary runner until the real CLI exists (Phase 14).
    path = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic/assets.csv"
    print(import_inventory(path).summary())