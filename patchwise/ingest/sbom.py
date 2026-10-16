"""CycloneDX SBOM importer (FR-03).

One SBOM file belongs to one asset (the asset_id is given at import time).
Valid components are saved; invalid ones are reported.
"""

import json
import sys
from dataclasses import dataclass, field

from patchwise.db.connection import get_connection, init_db


@dataclass
class SbomReport:
    asset_id: str = ""
    total_components: int = 0
    valid: list = field(default_factory=list)
    errors: list = field(default_factory=list)   # (position, message)
    added: int = 0
    skipped_existing: int = 0

    def summary(self):
        lines = [
            f"Asset: {self.asset_id}",
            f"Components read: {self.total_components}",
            f"Valid: {len(self.valid)} (added {self.added}, already present {self.skipped_existing})",
            f"Rejected: {len(self.errors)}",
        ]
        lines += [f"  {where}: {msg}" for where, msg in self.errors]
        return "\n".join(lines)


def _text(value):
    """Return a stripped string, or None if the value is missing/empty/not text."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def validate_sbom(sbom_path):
    """Check the file only. Does not touch the database."""
    report = SbomReport()
    try:
        with open(sbom_path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        report.errors.append(("file", f"not valid JSON ({exc.msg})"))
        return report

    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        report.errors.append(("file", "not a CycloneDX SBOM (bomFormat must be 'CycloneDX')"))
        return report

    components = data.get("components")
    if not isinstance(components, list):
        report.errors.append(("file", "'components' list is missing"))
        return report

    seen = set()
    for index, comp in enumerate(components, start=1):
        report.total_components += 1
        where = f"component #{index}"
        if not isinstance(comp, dict):
            report.errors.append((where, "component is not an object"))
            continue

        name = _text(comp.get("name"))
        if name is None:
            report.errors.append((where, "name is missing or empty"))
            continue

        clean = {
            "name": name,
            "version": _text(comp.get("version")),   # None = unknown, kept as NULL
            "vendor": _text(comp.get("group")) or _text(comp.get("publisher")),
            "purl": _text(comp.get("purl")),
            "cpe": _text(comp.get("cpe")),
        }
        key = (clean["name"], clean["version"])
        if key in seen:
            report.errors.append((where, f"duplicate component '{name}' version {clean['version']}"))
            continue
        seen.add(key)
        report.valid.append(clean)
    return report


def import_sbom(sbom_path, asset_id, db_path=None):
    """Validate the SBOM, then save its components for the given asset."""
    report = validate_sbom(sbom_path)
    report.asset_id = asset_id
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        asset = conn.execute("SELECT 1 FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        if asset is None:
            report.errors.append(("file", f"asset_id '{asset_id}' not found; import the inventory first"))
            report.valid = []
            return report

        with conn:
            for comp in report.valid:
                exists = conn.execute(
                    "SELECT 1 FROM components "
                    "WHERE asset_id = ? AND name = ? AND version IS ?",
                    (asset_id, comp["name"], comp["version"]),
                ).fetchone()
                if exists:
                    report.skipped_existing += 1
                    continue
                conn.execute(
                    "INSERT INTO components (asset_id, name, version, vendor, purl, cpe) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (asset_id, comp["name"], comp["version"],
                     comp["vendor"], comp["purl"], comp["cpe"]),
                )
                report.added += 1
    finally:
        conn.close()
    return report


if __name__ == "__main__":
    # Temporary runner until the real CLI exists (Phase 14).
    if len(sys.argv) < 3:
        print("Usage: python -m patchwise.ingest.sbom <sbom.json> <asset_id>")
        sys.exit(1)
    print(import_sbom(sys.argv[1], sys.argv[2]).summary())