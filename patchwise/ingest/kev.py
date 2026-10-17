"""CISA KEV loader (FR-02).

Reads a KEV snapshot file (JSON), checks every entry, saves the valid ones in
the `kev` table, and records the load in `data_fetch_log`.
"""

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime

from patchwise.db.connection import get_connection, init_db
from patchwise.ingest.fetch_log import log_fetch

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
RANSOMWARE_VALUES = ("Known", "Unknown")


@dataclass
class KevReport:
    origin: str = ""
    total: int = 0
    valid: list = field(default_factory=list)
    errors: list = field(default_factory=list)   # (position, message)
    loaded: int = 0
    new_cve_rows: int = 0
    skipped_out_of_scope: int = 0

    @property
    def file_error(self):
        """True if the whole file was unusable (not just some entries)."""
        return any(where == "file" for where, _ in self.errors)

    def summary(self):
        lines = [
            f"Source: {self.origin}",
            f"Entries read: {self.total}",
            f"Loaded: {self.loaded} (new CVE rows created: {self.new_cve_rows})",
            f"Outside scope (skipped): {self.skipped_out_of_scope}",
            f"Rejected: {len(self.errors)}",
        ]
        lines += [f"  {where}: {msg}" for where, msg in self.errors]
        return "\n".join(lines)


def _text(value):
    """Stripped string, or None if missing/empty/not text."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _is_real_date(text):
    """True for a real calendar date written as YYYY-MM-DD."""
    if not DATE_RE.fullmatch(text):
        return False
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _check_entry(entry):
    """Return (clean_dict_or_None, problems) for one KEV entry."""
    problems = []
    if not isinstance(entry, dict):
        return None, ["entry is not an object"]

    cve_id = _text(entry.get("cveID"))
    if cve_id is None or not CVE_RE.fullmatch(cve_id):
        problems.append(f"cveID {cve_id!r} is not a valid CVE id")

    date_added = _text(entry.get("dateAdded"))
    if date_added is None:
        problems.append("dateAdded is missing")
    elif not _is_real_date(date_added):
        problems.append(f"dateAdded '{date_added}' is not a valid YYYY-MM-DD date")

    due_date = _text(entry.get("dueDate"))          # optional
    if due_date is not None and not _is_real_date(due_date):
        problems.append(f"dueDate '{due_date}' is not a valid YYYY-MM-DD date")

    ransomware = _text(entry.get("knownRansomwareCampaignUse"))   # optional
    if ransomware is not None and ransomware not in RANSOMWARE_VALUES:
        problems.append(
            f"knownRansomwareCampaignUse '{ransomware}' is not valid "
            f"(allowed: {', '.join(RANSOMWARE_VALUES)})"
        )

    if problems:
        return None, problems
    return {
        "cve_id": cve_id,
        "vendor_project": _text(entry.get("vendorProject")),
        "product": _text(entry.get("product")),
        "date_added": date_added,
        "due_date": due_date,
        "known_ransomware_use": ransomware,
    }, []


def validate_kev(path):
    """Check the file only. Does not touch the database."""
    report = KevReport(origin=str(path))
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        report.errors.append(("file", f"not valid JSON ({exc.msg})"))
        return report

    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        report.errors.append(("file", "'vulnerabilities' list is missing"))
        return report

    seen = set()
    for index, entry in enumerate(entries, start=1):
        report.total += 1
        clean, problems = _check_entry(entry)
        if clean is not None and clean["cve_id"] in seen:
            problems.append(f"duplicate cveID '{clean['cve_id']}' in file")
            clean = None
        if problems:
            report.errors.append((f"entry #{index}", "; ".join(problems)))
        else:
            seen.add(clean["cve_id"])
            report.valid.append(clean)
    return report


def load_kev(path, db_path=None, only_cves=None, now=None):
    """Validate a KEV snapshot, save valid entries, log the load.

    only_cves: optional set of CVE ids. If given, only those are loaded
    (our scope); other valid entries are counted as 'outside scope'.
    now: timestamp text for the log (tests pass a fixed value).
    """
    report = validate_kev(path)
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = report.valid
        if only_cves is not None and not report.file_error:
            wanted = set(only_cves)
            kept = [r for r in rows if r["cve_id"] in wanted]
            report.skipped_out_of_scope = len(rows) - len(kept)
            rows = kept

        with conn:  # one transaction: data and log are saved together
            if not report.file_error:
                for r in rows:
                    # kev.cve_id points to cves.cve_id, so the CVE row must exist.
                    # OR IGNORE: never overwrite data NVD may have filled in.
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO cves (cve_id) VALUES (?)", (r["cve_id"],)
                    )
                    report.new_cve_rows += cur.rowcount
                    conn.execute(
                        """
                        INSERT INTO kev (cve_id, vendor_project, product, date_added,
                                         due_date, known_ransomware_use)
                        VALUES (:cve_id, :vendor_project, :product, :date_added,
                                :due_date, :known_ransomware_use)
                        ON CONFLICT(cve_id) DO UPDATE SET
                            vendor_project = excluded.vendor_project,
                            product = excluded.product,
                            date_added = excluded.date_added,
                            due_date = excluded.due_date,
                            known_ransomware_use = excluded.known_ransomware_use
                        """,
                        r,
                    )
                report.loaded = len(rows)

            if report.file_error:
                status = "failed"
            elif report.errors:
                status = "partial"
            else:
                status = "ok"
            note = None
            if only_cves is not None:
                note = f"filtered to scope; {report.skipped_out_of_scope} outside scope skipped"
            log_fetch(conn, "KEV", report.origin, "snapshot", report.total,
                      report.loaded, len(report.errors), status,
                      fetched_at=now, note=note)
    finally:
        conn.close()
    return report


if __name__ == "__main__":
    # Temporary runner until the real CLI exists (Phase 14).
    file_path = sys.argv[1] if len(sys.argv) > 1 else "data/snapshots/kev_sample.json"
    print(load_kev(file_path).summary())