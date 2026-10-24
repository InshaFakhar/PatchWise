"""Version comparison for matching (FR-04).

Question this module answers: "Is installed version X inside the affected
range of a CVE?"  Example: is 2.10.0 below 2.4.0?  (No: 10 is bigger than 4,
so versions must be compared as NUMBERS, not as text.)

Design rules:
  * Pure Python, no database, no internet. Same input -> same answer.
  * If a version string cannot be understood, we do NOT guess. We return
    None / "unknown", and the matching engine will then say "uncertain".

Supported shapes (everything else -> unparseable):
    1.2.3        2.10        v1.2.3        1.0.0+build5 (build part ignored)
    1.0-beta2    1.0rc1      1.0a1         1.0.dev1     1.0.0-alpha.1
    8.9p1        1.0.post1   1.1.1k        (a patch letter, like OpenSSL)
Order inside one release:  dev < alpha < beta < rc < (final) < patch/post.
At most ONE qualifier is allowed (so '1.0.0-rc.1.2' is unparseable).
"""

import re
from dataclasses import dataclass

IN_RANGE = "in"
OUT_OF_RANGE = "out"
UNKNOWN = "unknown"

_ALLOWED = re.compile(r"[0-9a-z.\-_+]+")
_RELEASE = re.compile(r"(\d+(?:\.\d+)*)(.*)", re.DOTALL)
_QUALIFIER = re.compile(r"[.\-_]?([a-z]+)[.\-_]?(\d*)")

# Rank of a qualifier: below 0 = before the final release, above 0 = after it.
_PRE_RANKS = {"dev": -4, "alpha": -3, "beta": -2, "rc": -1, "pre": -1, "preview": -1}
_SHORT_PRE = {"a": -3, "b": -2, "c": -1}           # only valid WITH a number: 1.0a1
_POST_WORDS = {"post", "patch", "sp"}


@dataclass(frozen=True)
class Version:
    release: tuple          # (2, 10, 0)
    rank: int = 0           # 0 = final release
    number: int = 0         # beta2 -> 2
    letter: str = ""        # 1.1.1k -> 'k'

    def sort_key(self):
        release = list(self.release)
        while len(release) > 1 and release[-1] == 0:   # 2.0 == 2.0.0
            release.pop()
        return (tuple(release), self.rank, self.number, self.letter)


def parse_version(text):
    """Return a Version, or None if the text is not a version we understand."""
    if not isinstance(text, str):
        return None
    s = text.strip().lower().split("+", 1)[0]          # ignore build metadata
    if len(s) > 1 and s[0] == "v" and s[1].isdigit():
        s = s[1:]
    if not _ALLOWED.fullmatch(s):
        return None
    m = _RELEASE.fullmatch(s)
    if not m:
        return None
    release = tuple(int(part) for part in m.group(1).split("."))
    rest = m.group(2)
    if rest == "":
        return Version(release)

    q = _QUALIFIER.fullmatch(rest)
    if not q:
        return None
    label, digits = q.group(1), q.group(2)
    attached = rest[0].isalpha()                       # '1.1.1k' (no separator)

    if len(label) == 1:
        if digits:
            if label in _SHORT_PRE:                    # 1.0a1, 1.0b2, 1.0c1
                return Version(release, _SHORT_PRE[label], int(digits))
            if label == "p":                           # 8.9p1
                return Version(release, 1, int(digits))
            return None
        if attached:                                   # 1.1.1k
            return Version(release, 1, 0, label)
        return None
    if label in _PRE_RANKS:
        return Version(release, _PRE_RANKS[label], int(digits) if digits else 0)
    if label in _POST_WORDS:
        return Version(release, 1, int(digits) if digits else 0)
    return None


def compare_versions(a, b):
    """Return -1, 0 or 1 (a<b, a==b, a>b), or None if either is unparseable."""
    va, vb = parse_version(a), parse_version(b)
    if va is None or vb is None:
        return None
    ka, kb = va.sort_key(), vb.sort_key()
    return (ka > kb) - (ka < kb)


def version_in_range(version, exact=None, start_including=None, start_excluding=None,
                     end_including=None, end_excluding=None):
    """Is `version` inside the affected range? Returns 'in', 'out' or 'unknown'.

      * No bounds at all  -> 'in'  (the CVE affects ALL versions, even if our
        own version is unknown).
      * A bound that is clearly violated -> 'out' (even if another bound is unclear).
      * Otherwise, if any comparison was impossible -> 'unknown'.
    """
    checks = [
        ("eq", exact), ("ge", start_including), ("gt", start_excluding),
        ("le", end_including), ("lt", end_excluding),
    ]
    active = [(op, bound) for op, bound in checks
              if bound is not None and str(bound).strip() != ""]
    if not active:
        return IN_RANGE

    unknown = False
    for op, bound in active:
        c = compare_versions(version, bound)
        if c is None:
            unknown = True
            continue
        ok = {"eq": c == 0, "ge": c >= 0, "gt": c > 0, "le": c <= 0, "lt": c < 0}[op]
        if not ok:
            return OUT_OF_RANGE
    return UNKNOWN if unknown else IN_RANGE


def row_range_status(version, row):
    """Same as version_in_range, reading the bounds from a cve_affected_products row."""
    return version_in_range(
        version,
        exact=row["version_exact"],
        start_including=row["version_start_including"],
        start_excluding=row["version_start_excluding"],
        end_including=row["version_end_including"],
        end_excluding=row["version_end_excluding"],
    )