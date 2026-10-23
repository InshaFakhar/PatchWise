"""NVD CVE loader (FR-02).

Reads an NVD "CVE API 2.0" style JSON snapshot, checks every CVE, saves the
CVE details (cves table) and the affected software / version ranges
(cve_affected_products table), and records the load in data_fetch_log.

Assumed layout (verify against a real NVD response):
    {"vulnerabilities": [{"cve": {
        "id": "CVE-2099-0001",
        "published": "2026-01-05T10:15:09.143",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {"cvssMetricV31": [{"type": "Primary",
                    "cvssData": {"version": "3.1", "vectorString": "...", "baseScore": 8.1}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": true,
            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.4.0"}]}]}]}}]}
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
CPE_SPLIT = re.compile(r"(?<!\\):")          # split on ':' but not on '\:'

# Which CVSS version to use when a CVE has several. A fixed order keeps the
# ranking reproducible. (Proposed decision: 3.1, then 3.0, then 4.0, then 2.0.)
CVSS_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")

RANGE_FIELDS = {
    "versionStartIncluding": "version_start_including",
    "versionStartExcluding": "version_start_excluding",
    "versionEndIncluding": "version_end_including",
    "versionEndExcluding": "version_end_excluding",
}


@dataclass
class NvdReport:
    origin: str = ""
    total: int = 0
    valid: list = field(default_factory=list)
    errors: list = field(default_factory=list)   # (position, message)
    loaded: int = 0
    products_loaded: int = 0
    without_cvss: int = 0
    without_products: int = 0
    skipped_out_of_scope: int = 0

    @property
    def file_error(self):
        return any(where == "file" for where, _ in self.errors)

    def summary(self):
        lines = [
            f"Source: {self.origin}",
            f"CVEs read: {self.total}",
            f"Loaded: {self.loaded} (affected-product rows: {self.products_loaded})",
            f"  without CVSS score (kept as unknown): {self.without_cvss}",
            f"  without affected-product data: {self.without_products}",
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


def _parse_date(value):
    """NVD dates look like '2021-12-10T10:15:09.143'. Keep YYYY-MM-DD.

    Returns (date_or_None, problem_or_None). A missing date is allowed.
    """
    if value is None or value == "":
        return None, None
    if not isinstance(value, str):
        return None, "published is not text"
    day = value.strip()[:10]
    if not DATE_RE.fullmatch(day):
        return None, f"published '{value}' is not a valid date"
    try:
        datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        return None, f"published '{value}' is not a valid date"
    return day, None


def _pick_cvss(metrics):
    """Choose one CVSS score. Returns (score, version, vector, problem).

    No score available -> (None, None, None, None): stored as NULL = unknown.
    """
    if not isinstance(metrics, dict):
        return None, None, None, None
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        chosen = next((e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"), None)
        if chosen is None:
            chosen = entries[0]
        data = chosen.get("cvssData") if isinstance(chosen, dict) else None
        if not isinstance(data, dict):
            return None, None, None, f"{key} has no cvssData"
        score = data.get("baseScore")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not (0 <= score <= 10):
            return None, None, None, f"{key} baseScore {score!r} is not a number between 0 and 10"
        return float(score), _text(data.get("version")), _text(data.get("vectorString")), None
    return None, None, None, None


def _parse_cpe(criteria):
    """Split 'cpe:2.3:a:vendor:product:version:...' Returns a dict or None."""
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = CPE_SPLIT.split(criteria)
    if len(parts) < 6:
        return None
    part, vendor, product, version = parts[2], parts[3], parts[4], parts[5]
    if part not in ("a", "o", "h") or not vendor or not product:
        return None
    return {"cpe_part": part, "vendor": vendor, "product": product, "version": version}


def _collect_products(configurations):
    """Return (list_of_product_rows, list_of_problems).

    Only entries marked vulnerable are kept. AND/OR logic between nodes is
    flattened (a known limitation: matching treats the result as indicative).
    """
    products, problems, seen = [], [], set()
    if configurations is None:
        return products, problems
    if not isinstance(configurations, list):
        return products, ["configurations is not a list"]
    for conf in configurations:
        nodes = conf.get("nodes") if isinstance(conf, dict) else None
        if not isinstance(nodes, list):
            problems.append("a configuration has no 'nodes' list")
            continue
        for node in nodes:
            matches = node.get("cpeMatch") if isinstance(node, dict) else None
            if matches is None:
                continue
            if not isinstance(matches, list):
                problems.append("cpeMatch is not a list")
                continue
            for match in matches:
                if not isinstance(match, dict):
                    problems.append("a cpeMatch entry is not an object")
                    continue
                if match.get("vulnerable") is not True:
                    continue            # e.g. "runs on" conditions are not vulnerable products
                criteria = match.get("criteria")
                cpe = _parse_cpe(criteria)
                if cpe is None:
                    problems.append(f"invalid cpe criteria {criteria!r}")
                    continue
                row = {
                    "cpe_part": cpe["cpe_part"],
                    "vendor": cpe["vendor"],
                    "product": cpe["product"],
                    "version_exact": None if cpe["version"] in ("*", "-", "") else cpe["version"],
                    "cpe_criteria": criteria,
                }
                for api_name, column in RANGE_FIELDS.items():
                    row[column] = _text(match.get(api_name))
                key = tuple(sorted(row.items()))
                if key not in seen:
                    seen.add(key)
                    products.append(row)
    return products, problems


def _check_vulnerability(item):
    """Return (clean_dict_or_None, problems) for one entry of 'vulnerabilities'."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None, ["entry has no 'cve' object"]
    problems = []

    cve_id = _text(cve.get("id"))
    if cve_id is None or not CVE_RE.fullmatch(cve_id):
        problems.append(f"id {cve_id!r} is not a valid CVE id")

    published, problem = _parse_date(cve.get("published"))
    if problem:
        problems.append(problem)

    description = None
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                description = _text(d.get("value"))
                break

    score, version, vector, problem = _pick_cvss(cve.get("metrics"))
    if problem:
        problems.append(problem)

    products, product_problems = _collect_products(cve.get("configurations"))
    problems += product_problems

    if problems:
        return None, problems
    return {
        "cve_id": cve_id,
        "description": description,
        "published_date": published,
        "cvss_score": score,
        "cvss_version": version,
        "cvss_vector": vector,
        "products": products,
    }, []


def validate_nvd(path):
    """Check the file only. Does not touch the database."""
    report = NvdReport(origin=str(path))
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        report.errors.append(("file", f"not valid JSON ({exc.msg})"))
        return report
    except (OSError, UnicodeDecodeError):
        report.errors.append(("file", "cannot read file (missing or not text)"))
        return report

    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        report.errors.append(("file", "'vulnerabilities' list is missing"))
        return report

    seen = set()
    for index, item in enumerate(entries, start=1):
        report.total += 1
        clean, problems = _check_vulnerability(item)
        if clean is not None and clean["cve_id"] in seen:
            problems.append(f"duplicate CVE '{clean['cve_id']}' in file")
            clean = None
        if problems:
            report.errors.append((f"entry #{index}", "; ".join(problems)))
        else:
            seen.add(clean["cve_id"])
            report.valid.append(clean)
    return report


def load_nvd(path, db_path=None, only_cves=None, now=None):
    """Validate an NVD snapshot, save valid CVEs and their affected products.

    NVD is the authoritative source for CVE details, so an existing row (for
    example an empty one created by the KEV loader) is filled / updated.
    Affected products of a CVE are replaced on every load (no duplicates).
    """
    report = validate_nvd(path)
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        rows = report.valid
        if only_cves is not None and not report.file_error:
            wanted = set(only_cves)
            kept = [r for r in rows if r["cve_id"] in wanted]
            report.skipped_out_of_scope = len(rows) - len(kept)
            rows = kept

        with conn:  # one transaction: CVEs, products and log are saved together
            if not report.file_error:
                for r in rows:
                    conn.execute(
                        """
                        INSERT INTO cves (cve_id, description, published_date,
                                          cvss_score, cvss_version, cvss_vector)
                        VALUES (:cve_id, :description, :published_date,
                                :cvss_score, :cvss_version, :cvss_vector)
                        ON CONFLICT(cve_id) DO UPDATE SET
                            description = excluded.description,
                            published_date = excluded.published_date,
                            cvss_score = excluded.cvss_score,
                            cvss_version = excluded.cvss_version,
                            cvss_vector = excluded.cvss_vector
                        """,
                        r,
                    )
                    conn.execute("DELETE FROM cve_affected_products WHERE cve_id = ?", (r["cve_id"],))
                    for p in r["products"]:
                        conn.execute(
                            """
                            INSERT INTO cve_affected_products
                                (cve_id, cpe_part, vendor, product, version_exact,
                                 version_start_including, version_start_excluding,
                                 version_end_including, version_end_excluding, cpe_criteria)
                            VALUES (:cve_id, :cpe_part, :vendor, :product, :version_exact,
                                    :version_start_including, :version_start_excluding,
                                    :version_end_including, :version_end_excluding, :cpe_criteria)
                            """,
                            {"cve_id": r["cve_id"], **p},
                        )
                        report.products_loaded += 1
                    if r["cvss_score"] is None:
                        report.without_cvss += 1
                    if not r["products"]:
                        report.without_products += 1
                report.loaded = len(rows)

            status = "failed" if report.file_error else ("partial" if report.errors else "ok")
            log_fetch(conn, "NVD", report.origin, "snapshot", report.total,
                      report.loaded, len(report.errors), status, fetched_at=now,
                      note=f"{report.products_loaded} affected-product rows saved")
    finally:
        conn.close()
    return report


if __name__ == "__main__":
    # Temporary runner until the real CLI exists (Phase 14).
    file_path = sys.argv[1] if len(sys.argv) > 1 else "data/snapshots/nvd_sample.json"
    print(load_nvd(file_path).summary())