"""Deterministic priority scoring (FR-05).

Each finding (one matched component + one CVE on one asset) gets a score from
0 to 100 built from FIVE factors:

    cvss         severity of the vulnerability      (CVSS / 10)
    epss         chance of exploitation             (already 0..1)
    kev          exploited in the wild?             (1 or 0)
    criticality  how important the asset is         (mapping in the config)
    exposure     how reachable the asset is         (mapping in the config)

    score = 100 * sum(weight_share[f] * value[f])      value[f] is between 0 and 1

The score comes with a visible BREAKDOWN (how many points each factor gave).
A missing value (for example no CVSS score yet) gives 0 points and is flagged
"unknown": we never invent a number.

IMPORTANT: this module is pure Python. No database, no internet, no LLM, no
randomness. Same input and same config always give the same ranking.
(An automated test also checks that patchwise/ranking never imports the
explanation / LLM layer.)
"""

import copy
import math
import tomllib
from pathlib import Path

FACTORS = ("cvss", "epss", "kev", "criticality", "exposure")
FACTOR_LABELS = {
    "cvss": "CVSS", "epss": "EPSS", "kev": "KEV",
    "criticality": "Criticality", "exposure": "Exposure",
}

CRITICALITY_LABELS = ("Low", "Medium", "High", "Critical")
EXPOSURE_LABELS = ("Internal", "DMZ", "Internet-facing")

DEFAULT_CONFIG = {
    "weights": {"cvss": 20, "epss": 25, "kev": 25, "criticality": 15, "exposure": 15},
    "criticality": {"Low": 0.25, "Medium": 0.5, "High": 0.75, "Critical": 1.0},
    "exposure": {"Internal": 0.33, "DMZ": 0.67, "Internet-facing": 1.0},
}

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "config" / "scoring_config.toml"


# ---------- configuration ----------

def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_config(config):
    """Return a cleaned copy of the config, or raise ValueError with a clear message."""
    if not isinstance(config, dict):
        raise ValueError("scoring config must be a dictionary")
    for section in ("weights", "criticality", "exposure"):
        if not isinstance(config.get(section), dict):
            raise ValueError(f"scoring config is missing the [{section}] section")

    weights = config["weights"]
    missing = [f for f in FACTORS if f not in weights]
    extra = [k for k in weights if k not in FACTORS]
    if missing:
        raise ValueError(f"weights are missing: {', '.join(missing)}")
    if extra:
        raise ValueError(f"unknown weight(s): {', '.join(extra)}")
    for name, value in weights.items():
        if not _is_number(value) or value < 0:
            raise ValueError(f"weight '{name}' must be a number that is 0 or more (got {value!r})")
    if sum(weights.values()) <= 0:
        raise ValueError("at least one weight must be greater than 0")

    for section, labels in (("criticality", CRITICALITY_LABELS), ("exposure", EXPOSURE_LABELS)):
        mapping = config[section]
        for label in labels:
            if label not in mapping:
                raise ValueError(f"[{section}] is missing the value for '{label}'")
        for label, value in mapping.items():
            if not _is_number(value) or not (0 <= value <= 1):
                raise ValueError(f"[{section}] '{label}' must be a number between 0 and 1 (got {value!r})")

    return copy.deepcopy({s: config[s] for s in ("weights", "criticality", "exposure")})


def load_config(path):
    """Read a TOML settings file and validate it."""
    with open(path, "rb") as f:
        return validate_config(tomllib.load(f))


def get_config():
    """The settings the app uses: config/scoring_config.toml if present, else the defaults."""
    if CONFIG_PATH.is_file():
        return load_config(CONFIG_PATH)
    return validate_config(DEFAULT_CONFIG)


def weight_shares(config=None):
    """{'cvss': 20.0, ...}: each weight as a percentage of the total."""
    cfg = validate_config(config if config is not None else get_config())
    total = sum(cfg["weights"].values())
    return {f: cfg["weights"][f] / total * 100 for f in FACTORS}


# ---------- scoring one finding ----------

def _clamp01(value):
    return max(0.0, min(1.0, float(value)))


def _factor_values(finding, cfg):
    """(raw, value 0..1 or None) per factor. None means 'unknown'."""
    cvss = finding.get("cvss_score")
    epss = finding.get("epss_score")
    return {
        "cvss": (cvss, None if cvss is None else _clamp01(cvss / 10)),
        "epss": (epss, None if epss is None else _clamp01(epss)),
        "kev": (bool(finding.get("in_kev")), 1.0 if finding.get("in_kev") else 0.0),
        "criticality": (finding.get("criticality"), cfg["criticality"].get(finding.get("criticality"))),
        "exposure": (finding.get("exposure"), cfg["exposure"].get(finding.get("exposure"))),
    }


def score_finding(finding, config=None):
    """Return {'score': 0..100, 'factors': {name: {raw, value, weight, points, unknown}}}."""
    cfg = validate_config(config if config is not None else get_config())
    total_weight = sum(cfg["weights"].values())
    factors, score = {}, 0.0
    for name, (raw, value) in _factor_values(finding, cfg).items():
        share = cfg["weights"][name] / total_weight * 100
        unknown = value is None
        points = 0.0 if unknown else share * value
        score += points
        factors[name] = {"raw": raw, "value": 0.0 if unknown else value,
                         "weight": share, "points": points, "unknown": unknown}
    return {"score": score, "factors": factors}


# ---------- ranking many findings ----------

def rank_findings(findings, config=None):
    """Return NEW dicts (inputs are not changed), best first, with 'score', 'factors', 'rank'.

    Order: higher score first. If two scores are equal, the tie is broken by (in this order)
    higher asset criticality, KEV listed, higher EPSS, then CVE / asset / software name,
    so the result never depends on the input order.
    """
    cfg = validate_config(config if config is not None else get_config())
    scored = []
    for f in findings:
        result = score_finding(f, cfg)
        item = dict(f)
        item["score"] = result["score"]
        item["factors"] = result["factors"]
        scored.append(item)

    def key(item):
        fac = item["factors"]
        return (
            -round(item["score"], 6),
            -fac["criticality"]["value"],
            -fac["kev"]["value"],
            -fac["epss"]["value"],
            item.get("cve_id") or "",
            item.get("asset_id") or "",
            item.get("component") or "",
            item.get("component_version") or "",
        )

    scored.sort(key=key)
    for position, item in enumerate(scored, start=1):
        item["rank"] = position
    return scored


def rank_cvss_only(findings):
    """The baseline: order by CVSS alone (unknown CVSS last). Adds 'cvss_rank'.

    Ties are broken by names only, so the baseline knows nothing about KEV, EPSS or the asset.
    """
    def key(f):
        cvss = f.get("cvss_score")
        return (cvss is None, -(cvss or 0), f.get("cve_id") or "", f.get("asset_id") or "",
                f.get("component") or "", f.get("component_version") or "")

    ordered = []
    for position, f in enumerate(sorted(findings, key=key), start=1):
        item = dict(f)
        item["cvss_rank"] = position
        ordered.append(item)
    return ordered
