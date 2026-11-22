"""Export the review queue as CSV or Markdown (FR-08).

Pure functions: rows in, text out. No database, no web, no LLM.

CSV safety: a spreadsheet treats a cell that starts with = + - @ as a FORMULA.
Text that came from people (reasons, names) could therefore run something when
the file is opened in Excel. csv_safe() puts a ' in front of such cells.
"""

import csv
import io

CSV_COLUMNS = [
    "queue_position", "patchwise_rank", "score", "match_status", "decision", "analyst",
    "reason", "decided_at", "asset", "asset_criticality", "exposure", "software",
    "cve_id", "cvss", "in_kev", "epss",
]
_DANGEROUS_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    if isinstance(value, str) and value.startswith(_DANGEROUS_START):
        return "'" + value
    return value


def _software(item):
    return f"{item['component']} {item['component_version'] or '(version unknown)'}"


def export_rows(queue):
    """One flat dict per finding, in queue order."""
    rows = []
    for item in queue:
        decision = item.get("decision")
        rows.append({
            "queue_position": item["queue_position"],
            "patchwise_rank": item["rank"],
            "score": round(item["score"], 1),
            "match_status": item["status"],
            "decision": decision["action"] if decision else "",
            "analyst": decision["analyst_name"] if decision else "",
            "reason": decision["reason"] if decision else "",
            "decided_at": decision["decided_at"] if decision else "",
            "asset": item["hostname"],
            "asset_criticality": item["criticality"],
            "exposure": item["exposure"],
            "software": _software(item),
            "cve_id": item["cve_id"],
            "cvss": "" if item["cvss_score"] is None else item["cvss_score"],
            "in_kev": "yes" if item["in_kev"] else "no",
            "epss": "" if item["epss_score"] is None else item["epss_score"],
        })
    return rows


def queue_to_csv(queue):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    for row in export_rows(queue):
        writer.writerow({k: csv_safe(v) for k, v in row.items()})
    return out.getvalue()


def _md(value):
    """Make a value safe inside a Markdown table cell."""
    text = "" if value is None else str(value)
    return " ".join(text.split()).replace("|", "\\|")


def queue_to_markdown(queue, weights, generated_at):
    """weights: [('CVSS', 20.0), ...]. generated_at: text, passed in so the output is reproducible."""
    lines = [
        "# PatchWise remediation shortlist",
        "",
        f"Generated: {generated_at}",
        "",
        "Ranking weights (initial values): " + ", ".join(f"{label} {share:.0f}%" for label, share in weights),
        "",
        "Order: bumped findings first, deferred findings last. The PatchWise rank and score "
        "are computed by a fixed formula; decisions are made by the analyst.",
        "",
        "| # | PatchWise rank | Score | Match | Decision | Asset | Software | CVE | CVSS | KEV | EPSS | Reason |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in export_rows(queue):
        decision = f"{r['decision']} ({r['analyst']})" if r["decision"] else ""
        cells = [r["queue_position"], r["patchwise_rank"], r["score"], r["match_status"], decision,
                 r["asset"], r["software"], r["cve_id"], r["cvss"], r["in_kev"], r["epss"], r["reason"]]
        lines.append("| " + " | ".join(_md(c) for c in cells) + " |")
    return "\n".join(lines) + "\n"
