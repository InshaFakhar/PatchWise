"""FIRST EPSS loader (FR-02).

Reads an EPSS snapshot (CSV or CSV.GZ), checks every row, saves scores only
for CVEs already in the `cves` table, and records the load in data_fetch_log.

File layout (assumed, verify against a real file):
    #model_version:v2025.03.14,score_date:2026-10-15T12:55:00Z
    cve,epss,percentile
    CVE-2099-0001,0.72000,0.97000
"""

import csv
import gzip
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime

from patchwise.db.connection import get_connection, init_db
from patchwise.ingest.fetch_log import log_fetch

CVE_RE = re.compile(r"CVE-\d{4}-\d+")
REQUIRED_COLUMNS = ("cve", "epss", "percentile")


@dataclass
class EpssReport:
    origin: str = ""
    score_date: str = ""
    model_version: str = None
    total: int = 0
    valid: list = field(default_factory=list)
    errors: list = field(default_factory=list)   # (position, message)
    loaded: int = 0
    skipped_out_of_scope: int = 0

    @property
    def file_error(self):
        return any(where == "file" for where, _ in self.errors)

    def summary(self):
        lines = [
            f"Source: {self.origin}",
            f"Score date: {self.score_date or 'unknown'} | model: {self.model_version or 'unknown'}",
            f"Rows read: {self.total}",
            f"Loaded: {self.loaded}",
            f"Outside scope (skipped): {self.skipped_out_of_scope}",
            f"Rejected: {len(self.errors)}",
        ]
        lines += [f"  {where}: {msg}" for where, msg in self.errors]
        return "\n".join(lines)


def _open_text(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    return open(path, encoding="utf-8-sig", newline="")


def _is_real_date(text):
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _probability(text, name):
    """Parse a 0..1 number. Returns (value_or_None, problem_or_None)."""
    try:
        value = float((text or "").strip())
    except ValueError:
        return None, f"{name} '{text}' is not a number"
    if not (0 <= value <= 1):       # also False for nan
        return None, f"{name} {text} is outside 0..1"
    return value, None


def validate_epss(path):
    """Check the file only. Does not touch the database."""
    report = EpssReport(origin=str(path))
    try:
        with _open_text(path) as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError, EOFError):
        report.errors.append(("file", "cannot read file (missing, corrupt or not text)"))
        return report

    comments = [ln for ln in lines if ln.startswith("#")]
    data_lines = [ln for ln in lines if ln.strip() and not ln.startswith("#")]

    for ln in comments:
        date_match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", ln)
        model_match = re.search(r"model_version:([^,\s]+)", ln)
        if date_match:
            report.score_date = date_match.group(1)
        if model_match:
            report.model_version = model_match.group(1)
    if not report.score_date or not _is_real_date(report.score_date):
        report.errors.append(("file", "score_date is missing or not a valid date in the header comment"))
        return report

    reader = csv.DictReader(data_lines)
    if reader.fieldnames is None:
        report.errors.append(("file", "no header row"))
        return report
    reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
    missing = [c for c in REQUIRED_COLUMNS if c not in reader.fieldnames]
    if missing:
        report.errors.append(("file", f"missing column(s): {', '.join(missing)}"))
        return report

    seen = set()
    for index, row in enumerate(reader, start=1):
        report.total += 1
        problems = []
        cve_id = (row.get("cve") or "").strip()
        if not CVE_RE.fullmatch(cve_id):
            problems.append(f"cve '{cve_id}' is not a valid CVE id")
        epss, p1 = _probability(row.get("epss"), "epss")
        pct, p2 = _probability(row.get("percentile"), "percentile")
        problems += [p for p in (p1, p2) if p]
        if cve_id in seen:
            problems.append(f"duplicate cve '{cve_id}' in file")

        if problems:
            report.errors.append((f"row #{index}", "; ".join(problems)))
        else:
            seen.add(cve_id)
            report.valid.append({"cve_id": cve_id, "epss_score": epss, "percentile": pct})
    return report


def load_epss(path, db_path=None, only_cves=None, now=None):
    """Validate an EPSS snapshot, save scores for in-scope CVEs, log the load.

    Scope = CVEs already in the cves table. only_cves can narrow it further.
    """
    report = validate_epss(path)
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = report.valid
        if not report.file_error:
            in_db = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM cves")}
            wanted = in_db if only_cves is None else in_db & set(only_cves)
            kept = [r for r in rows if r["cve_id"] in wanted]
            report.skipped_out_of_scope = len(rows) - len(kept)
            rows = kept

        with conn:
            if not report.file_error:
                for r in rows:
                    conn.execute(
                        """
                        INSERT INTO epss (cve_id, epss_score, percentile, score_date, model_version)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(cve_id) DO UPDATE SET
                            epss_score = excluded.epss_score,
                            percentile = excluded.percentile,
                            score_date = excluded.score_date,
                            model_version = excluded.model_version
                        """,
                        (r["cve_id"], r["epss_score"], r["percentile"],
                         report.score_date, report.model_version),
                    )
                report.loaded = len(rows)

            status = "failed" if report.file_error else ("partial" if report.errors else "ok")
            log_fetch(conn, "EPSS", report.origin, "snapshot", report.total,
                      report.loaded, len(report.errors), status, fetched_at=now,
                      note=f"scope = CVEs in cves table; {report.skipped_out_of_scope} outside scope skipped")
    finally:
        conn.close()
    return report


if __name__ == "__main__":
    file_path = sys.argv[1] if len(sys.argv) > 1 else "data/snapshots/epss_sample.csv"
    print(load_epss(file_path).summary())