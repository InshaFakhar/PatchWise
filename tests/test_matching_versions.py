import sqlite3
from functools import cmp_to_key

from patchwise.ingest.nvd import validate_nvd
from patchwise.matching.versions import (
    IN_RANGE, OUT_OF_RANGE, UNKNOWN,
    compare_versions, parse_version, row_range_status, version_in_range,
)

# (a, b, expected compare_versions(a, b))
NUMBER_NOT_TEXT = [
    ("2.10.0", "2.4.0", 1),      # 10 > 4 (text order would get this WRONG)
    ("2.9", "2.10", -1),
    ("1.2.10", "1.2.9", 1),
    ("10.0", "9.9", 1),
    ("1.0.0", "1.0.1", -1),
    ("2.3.1", "2.3.1", 0),
    ("3", "2.99.99", 1),
]
EQUAL_FORMS = [
    ("2.0", "2.0.0", 0),
    ("1", "1.0.0.0", 0),
    ("v1.2.3", "1.2.3", 0),
    ("V1.2.3", "1.2.3", 0),
    ("1.0.0+build5", "1.0.0", 0),
    ("1.0-BETA", "1.0-beta", 0),
    (" 1.0 ", "1.0", 0),
]
PRE_RELEASES = [
    ("1.0-beta", "1.0", -1),
    ("1.0rc1", "1.0", -1),
    ("1.0.0-alpha.1", "1.0.0", -1),
    ("1.0.dev1", "1.0-alpha", -1),
    ("1.0-alpha", "1.0-beta", -1),
    ("1.0-beta", "1.0-rc", -1),
    ("1.0-beta2", "1.0-beta10", -1),
    ("1.0-alpha", "1.0-alpha0", 0),
    ("1.0a1", "1.0-alpha1", 0),
    ("1.0b2", "1.0-beta.2", 0),
    ("1.0c1", "1.0rc1", 0),
    ("2.0.0-rc1", "1.9.9", 1),
]
POST_RELEASES = [
    ("8.9p1", "8.9", 1),
    ("8.9p1", "8.9p2", -1),
    ("1.1.1k", "1.1.1", 1),
    ("1.1.1k", "1.1.1a", 1),
    ("1.1.1k", "1.1.2", -1),
    ("1.1.1a", "1.1.1b", -1),
    ("1.0.post1", "1.0", 1),
    ("1.0-patch2", "1.0-patch1", 1),
]
UNPARSEABLE = [
    "", "   ", None, 5, "latest", "unknown", "abc", "1.0.0-1", "1.0.0-rc.1.2", "1..2",
    "1.x", "1.2.x", "*", "-", "1.0 beta", "1.0-k", "1.0kk", "1.0k2", "v", "+build", "1.0_",
]
ORDERED = ["1.0.dev1", "1.0-alpha", "1.0b2", "1.0rc1", "1.0", "1.0.post1", "1.0.1",
           "1.1.1", "1.1.1a", "1.1.1k", "1.1.2", "2.4.0", "2.10.0"]


def check_table(table):
    for a, b, expected in table:
        assert compare_versions(a, b) == expected, f"compare({a!r}, {b!r})"


def test_versions_are_compared_as_numbers_not_text():
    check_table(NUMBER_NOT_TEXT)


def test_equivalent_spellings_are_equal():
    check_table(EQUAL_FORMS)


def test_pre_releases_come_before_the_final_release():
    check_table(PRE_RELEASES)


def test_patch_and_post_releases_come_after_the_release():
    check_table(POST_RELEASES)


def test_unclear_versions_are_not_guessed():
    for text in UNPARSEABLE:
        assert parse_version(text) is None, f"{text!r} should be unparseable"


def test_comparison_with_unclear_version_is_none():
    assert compare_versions("1.0.0-1", "1.0") is None
    assert compare_versions("1.0", "latest") is None
    assert compare_versions(None, "1.0") is None


def test_comparison_is_symmetric():
    tables = NUMBER_NOT_TEXT + EQUAL_FORMS + PRE_RELEASES + POST_RELEASES
    for a, b, expected in tables:
        assert compare_versions(b, a) == -expected, f"reverse of ({a!r}, {b!r})"


def test_sorting_gives_the_expected_order():
    shuffled = list(reversed(ORDERED))
    result = sorted(shuffled, key=cmp_to_key(compare_versions))
    assert result == ORDERED


def test_order_is_transitive_for_the_whole_list():
    for i in range(len(ORDERED)):
        for j in range(i + 1, len(ORDERED)):
            assert compare_versions(ORDERED[i], ORDERED[j]) == -1, (ORDERED[i], ORDERED[j])


# ---------- ranges ----------

def test_end_excluding_range():
    r = lambda v: version_in_range(v, end_excluding="2.4.0")
    assert r("2.3.1") == IN_RANGE
    assert r("2.4.0") == OUT_OF_RANGE         # the end itself is NOT affected
    assert r("2.10.0") == OUT_OF_RANGE        # 2.10.0 is newer than 2.4.0
    assert r("2.4.0-rc1") == IN_RANGE         # a release candidate is older than 2.4.0


def test_including_range_keeps_both_ends():
    r = lambda v: version_in_range(v, start_including="5.0.0", end_including="5.2.0")
    assert r("5.0.0") == IN_RANGE and r("5.2.0") == IN_RANGE
    assert r("4.9.9") == OUT_OF_RANGE and r("5.2.1") == OUT_OF_RANGE


def test_excluding_range_drops_both_ends():
    r = lambda v: version_in_range(v, start_excluding="2.3.1", end_excluding="3.0.0")
    assert r("2.3.1") == OUT_OF_RANGE         # boundary: start itself NOT affected
    assert r("2.3.2") == IN_RANGE
    assert r("2.9.9") == IN_RANGE
    assert r("3.0.0") == OUT_OF_RANGE


def test_single_sided_ranges():
    assert version_in_range("3.0", start_including="2.0.0") == IN_RANGE
    assert version_in_range("1.0", start_including="2.0.0") == OUT_OF_RANGE
    assert version_in_range("1.0", end_including="1.0.0") == IN_RANGE


def test_exact_version():
    assert version_in_range("1.0.4", exact="1.0.4") == IN_RANGE
    assert version_in_range("1.0.4.0", exact="1.0.4") == IN_RANGE
    assert version_in_range("1.0.5", exact="1.0.4") == OUT_OF_RANGE


def test_no_bounds_means_all_versions_even_if_ours_is_unknown():
    assert version_in_range("9.9.9") == IN_RANGE
    assert version_in_range(None) == IN_RANGE
    assert version_in_range("latest") == IN_RANGE


def test_unknown_or_missing_version_with_bounds_is_unknown():
    assert version_in_range(None, end_excluding="2.4.0") == UNKNOWN
    assert version_in_range("latest", end_excluding="2.4.0") == UNKNOWN
    assert version_in_range("1.0.0-1", end_excluding="2.4.0") == UNKNOWN


def test_unclear_bound_gives_unknown_but_clear_violation_still_wins():
    assert version_in_range("1.0.0", end_excluding="weird") == UNKNOWN
    assert version_in_range("1.0.0", start_including="2.0.0", end_excluding="weird") == OUT_OF_RANGE


def test_empty_bound_text_is_ignored():
    assert version_in_range("1.0", start_including="  ", end_excluding="2.0") == IN_RANGE


def test_row_helper_works_with_dict_and_sqlite_row():
    cols = ["version_exact", "version_start_including", "version_start_excluding",
            "version_end_including", "version_end_excluding"]
    as_dict = dict.fromkeys(cols)
    as_dict["version_end_excluding"] = "2.4.0"
    assert row_range_status("2.3.1", as_dict) == IN_RANGE
    assert row_range_status("2.4.0", as_dict) == OUT_OF_RANGE

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE t (" + ", ".join(cols) + ")")
    conn.execute("INSERT INTO t VALUES (NULL, NULL, NULL, NULL, '2.4.0')")
    row = conn.execute("SELECT * FROM t").fetchone()
    assert row_range_status("2.10.0", row) == OUT_OF_RANGE
    conn.close()


def test_sample_nvd_ranges_give_the_expected_answers():
    report = validate_nvd("data/snapshots/nvd_sample.json")
    first = {c["cve_id"]: c["products"][0] for c in report.valid if c["products"]}
    # CVE-2099-0001: examplelib below 2.4.0
    assert row_range_status("2.3.1", first["CVE-2099-0001"]) == IN_RANGE
    assert row_range_status("2.4.0", first["CVE-2099-0001"]) == OUT_OF_RANGE
    assert row_range_status("2.10.0", first["CVE-2099-0001"]) == OUT_OF_RANGE
    # CVE-2099-0002: samplehttpd 5.0.0 to 5.2.0 (both included)
    assert row_range_status("5.2.0", first["CVE-2099-0002"]) == IN_RANGE
    assert row_range_status("5.2.1", first["CVE-2099-0002"]) == OUT_OF_RANGE
    # CVE-2099-0003: demoparser exactly 1.0.4
    assert row_range_status("1.0.4", first["CVE-2099-0003"]) == IN_RANGE
    assert row_range_status("1.0.5", first["CVE-2099-0003"]) == OUT_OF_RANGE
    # CVE-2099-0004: examplelib above 2.3.1 and below 3.0.0 (boundary case)
    assert row_range_status("2.3.1", first["CVE-2099-0004"]) == OUT_OF_RANGE
    assert row_range_status("2.3.2", first["CVE-2099-0004"]) == IN_RANGE
    # CVE-2099-0006: mystery-lib, all versions
    assert row_range_status(None, first["CVE-2099-0006"]) == IN_RANGE