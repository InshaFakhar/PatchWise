import random
import sqlite3

from patchwise import services
from patchwise.ingest.epss import load_epss
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.kev import load_kev
from patchwise.ingest.nvd import load_nvd
from patchwise.ingest.sbom import import_sbom
from patchwise.matching.matcher import (
    CPE_EXACT, FUZZY, NAME_ONLY, NAME_VENDOR, VENDOR_CONFLICT,
    describe_range, find_matches, name_evidence, run_matching,
)


# ---------- small builders for hand-made data ----------

def comp(cid=1, name="examplelib", version="2.3.1", vendor="exampleco", cpe=None):
    return {"component_id": cid, "name": name, "version": version, "vendor": vendor, "cpe": cpe}


def row(rid=1, cve="CVE-2099-0001", vendor="exampleco", product="examplelib", part="a", **bounds):
    r = {
        "id": rid, "cve_id": cve, "cpe_part": part, "vendor": vendor, "product": product,
        "version_exact": None, "version_start_including": None, "version_start_excluding": None,
        "version_end_including": None, "version_end_excluding": None,
        "cpe_criteria": f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*",
    }
    r.update(bounds)
    return r


def one(components, rows):
    """Run find_matches and return the single match (or None)."""
    result = find_matches(components, rows)
    assert len(result) <= 1
    return result[0] if result else None


# ---------- status rules ----------

def test_confirmed_when_name_vendor_and_version_range_match():
    m = one([comp()], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "confirmed"
    assert m["name_evidence"] == NAME_VENDOR and m["version_evidence"] == "in_range"
    assert "2.3.1" in m["reason"] and "< 2.4.0" in m["reason"]


def test_version_outside_range_gives_no_match():
    assert one([comp(version="2.4.0")], [row(version_end_excluding="2.4.0")]) is None


def test_text_order_trap_2_10_0_is_not_below_2_4_0():
    assert one([comp(version="2.10.0")], [row(version_end_excluding="2.4.0")]) is None


def test_missing_vendor_gives_probable():
    m = one([comp(vendor=None)], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "probable" and m["name_evidence"] == NAME_ONLY


def test_all_versions_is_probable_even_if_component_has_no_version():
    m = one([comp(version=None, vendor=None)], [row()])
    assert m["status"] == "probable" and m["version_evidence"] == "all_versions"


def test_all_versions_with_matching_vendor_is_still_only_probable():
    m = one([comp()], [row()])
    assert m["status"] == "probable"


def test_missing_version_with_a_version_range_is_insufficient_data():
    m = one([comp(version=None)], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "insufficient_data" and m["version_evidence"] == "version_missing"
    assert "no version" in m["reason"]


def test_blank_version_counts_as_missing():
    m = one([comp(version="  ")], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "insufficient_data"


def test_version_that_cannot_be_compared_is_uncertain():
    m = one([comp(version="1.0.4-1")], [row(version_exact="1.0.4")])
    assert m["status"] == "uncertain" and m["version_evidence"] == "not_comparable"


def test_vendor_conflict_is_uncertain():
    m = one([comp(vendor="otherco")], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "uncertain" and m["name_evidence"] == VENDOR_CONFLICT


def test_vendor_conflict_with_version_outside_range_is_dropped():
    assert one([comp(vendor="otherco", version="3.0.0")], [row(version_end_excluding="2.4.0")]) is None


def test_partial_name_is_uncertain():
    m = one([comp(name="examplelib-extras", vendor=None)], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "uncertain" and m["name_evidence"] == FUZZY


def test_partial_name_with_missing_version_is_uncertain_not_insufficient():
    m = one([comp(name="examplelib-extras", version=None, vendor=None)], [row(version_end_excluding="2.4.0")])
    assert m["status"] == "uncertain"


def test_partial_name_outside_range_is_dropped():
    assert one([comp(name="examplelib-extras", version="9.0", vendor=None)],
               [row(version_end_excluding="2.4.0")]) is None


def test_tiny_name_overlap_is_not_a_match():
    assert name_evidence(comp(name="ab", vendor=None), row(product="ab_cd")) is None


def test_unrelated_names_do_not_match():
    assert one([comp(name="otherlib")], [row(version_end_excluding="2.4.0")]) is None


def test_names_are_normalised():
    ev = name_evidence(comp(name="Example-Lib", vendor="ExampleCo"), row(product="example_lib"))
    assert ev == NAME_VENDOR


def test_component_cpe_gives_exact_evidence_even_if_the_name_differs():
    c = comp(name="my-private-copy", vendor=None, cpe="cpe:2.3:a:exampleco:examplelib:2.3.1:*:*:*:*:*:*:*")
    assert name_evidence(c, row()) == CPE_EXACT
    assert one([c], [row(version_end_excluding="2.4.0")])["status"] == "confirmed"


def test_operating_system_rows_are_ignored():
    assert one([comp()], [row(part="o", version_end_excluding="2.4.0")]) is None


def test_exact_version_confirmed_and_other_version_not():
    r = row(product="demoparser", vendor="democo", version_exact="1.0.4")
    assert one([comp(name="demoparser", vendor="democo", version="1.0.4")], [r])["status"] == "confirmed"
    assert one([comp(name="demoparser", vendor="democo", version="1.0.5")], [r]) is None


# ---------- several NVD rows for one CVE ----------

def test_strongest_status_wins_when_several_rows_point_to_one_cve():
    rows = [
        row(rid=1, version_end_excluding="1.0"),          # 2.3.1 is outside this one
        row(rid=2, version_start_including="2.0.0"),      # inside this one
    ]
    m = one([comp()], rows)
    assert m["status"] == "confirmed"


def test_confirmed_beats_probable_for_the_same_cve():
    rows = [row(rid=1), row(rid=2, version_end_excluding="2.4.0")]   # all-versions row, then range row
    assert one([comp()], rows)["status"] == "confirmed"


# ---------- order independence ----------

def test_result_does_not_depend_on_input_order():
    components = [comp(1), comp(2, name="demoparser", vendor=None, version="1.0.4"),
                  comp(3, version=None)]
    rows = [row(1, "CVE-2099-0001", version_end_excluding="2.4.0"),
            row(2, "CVE-2099-0003", vendor="democo", product="demoparser", version_exact="1.0.4"),
            row(3, "CVE-2099-0004", version_start_excluding="2.3.1", version_end_excluding="3.0.0")]
    expected = find_matches(components, rows)
    rng = random.Random(7)
    for _ in range(20):
        c, r = components[:], rows[:]
        rng.shuffle(c)
        rng.shuffle(r)
        assert find_matches(c, r) == expected


def test_describe_range_texts():
    assert describe_range(row()) == "all versions"
    assert describe_range(row(version_end_excluding="2.4.0")) == "< 2.4.0"
    assert describe_range(row(version_start_including="5.0.0", version_end_including="5.2.0")) == ">= 5.0.0, <= 5.2.0"
    assert describe_range(row(version_exact="1.0.4")) == "= 1.0.4"


# ---------- the database layer, on the project's sample data ----------

def load_samples(tmp_path):
    db = tmp_path / "t.db"
    import_inventory("data/synthetic/assets.csv", db)
    for asset in ("A001", "A002", "A003"):
        import_sbom(f"data/synthetic/sbom_{asset}.json", asset, db)
    load_kev("data/snapshots/kev_sample.json", db)
    load_nvd("data/snapshots/nvd_sample.json", db)
    load_epss("data/snapshots/epss_sample.csv", db)
    return db


def saved_matches(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT a.asset_id, c.name, m.cve_id, m.status FROM matches m "
            "JOIN components c ON c.component_id = m.component_id "
            "JOIN assets a ON a.asset_id = c.asset_id "
            "ORDER BY a.asset_id, c.name, m.cve_id").fetchall()
    finally:
        conn.close()


EXPECTED_SAMPLE_MATCHES = [
    ("A001", "demoparser", "CVE-2099-0003", "probable"),
    ("A001", "examplelib", "CVE-2099-0001", "confirmed"),
    ("A001", "mystery-lib", "CVE-2099-0006", "probable"),
    ("A001", "samplehttpd", "CVE-2099-0002", "confirmed"),
    ("A002", "demoparser-extras", "CVE-2099-0003", "uncertain"),
    ("A002", "examplelib", "CVE-2099-0001", "insufficient_data"),
    ("A002", "examplelib", "CVE-2099-0004", "insufficient_data"),
    ("A003", "demoparser", "CVE-2099-0003", "uncertain"),
    ("A003", "examplelib", "CVE-2099-0004", "confirmed"),
    ("A003", "samplehttpd", "CVE-2099-0002", "uncertain"),
]


def test_sample_data_gives_the_expected_matches(tmp_path):
    db = load_samples(tmp_path)
    report = run_matching(db)
    assert report.counts == {"confirmed": 3, "probable": 2, "uncertain": 3, "insufficient_data": 2}
    assert saved_matches(db) == EXPECTED_SAMPLE_MATCHES


def test_boundary_cases_in_the_sample_data(tmp_path):
    db = load_samples(tmp_path)
    run_matching(db)
    saved = saved_matches(db)
    # examplelib 2.3.1 is the START of CVE-0004's range but the start is excluded: no match
    assert ("A001", "examplelib", "CVE-2099-0004", "confirmed") not in saved
    assert not any(m[0] == "A001" and m[1] == "examplelib" and m[2] == "CVE-2099-0004" for m in saved)
    # samplehttpd 6.0.0 is above 5.2.0: no match
    assert not any(m[0] == "A002" and m[1] == "samplehttpd" for m in saved)
    # examplelib 2.10.0 is NOT below 2.4.0 (CVE-0001) but IS inside (2.3.1, 3.0.0) (CVE-0004)
    a003 = [m for m in saved if m[0] == "A003" and m[1] == "examplelib"]
    assert a003 == [("A003", "examplelib", "CVE-2099-0004", "confirmed")]


def test_cve_without_affected_product_data_never_matches(tmp_path):
    db = load_samples(tmp_path)
    run_matching(db)
    assert all(m[2] != "CVE-2099-0005" for m in saved_matches(db))


def test_running_twice_gives_the_same_rows(tmp_path):
    db = load_samples(tmp_path)
    run_matching(db)
    first = saved_matches(db)
    run_matching(db)
    assert saved_matches(db) == first


def test_rerun_replaces_old_matches_when_data_changes(tmp_path):
    db = load_samples(tmp_path)
    run_matching(db)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM matches")           # simulate stale content
    conn.execute("INSERT INTO matches (component_id, cve_id, status, name_evidence, version_evidence, reason) "
                 "VALUES (1, 'CVE-2099-0001', 'uncertain', 'fuzzy', 'in_range', 'stale')")
    conn.commit()
    conn.close()
    run_matching(db)
    assert saved_matches(db) == EXPECTED_SAMPLE_MATCHES


def test_empty_database_gives_no_matches(tmp_path):
    report = run_matching(tmp_path / "empty.db")
    assert report.matches == [] and report.counts["confirmed"] == 0


def test_match_rows_keep_the_reason_and_the_nvd_cpe(tmp_path):
    db = load_samples(tmp_path)
    run_matching(db)
    conn = sqlite3.connect(db)
    reason, cpe = conn.execute(
        "SELECT reason, affected_cpe FROM matches WHERE cve_id = 'CVE-2099-0001' AND status = 'confirmed'"
    ).fetchone()
    conn.close()
    assert "inside the affected range" in reason and cpe.startswith("cpe:2.3:a:exampleco:examplelib")


# ---------- findings (what the web page shows) ----------

def test_findings_join_public_signals(tmp_path):
    db = load_samples(tmp_path)
    services.run_matching(db)
    findings = services.list_findings(db)
    assert len(findings) == 10
    top = findings[0]
    assert (top["status"], top["hostname"], top["cve_id"]) == ("confirmed", "web-prod-01", "CVE-2099-0001")
    assert top["in_kev"] is True and top["known_ransomware_use"] == "Known"
    assert top["epss_score"] == 0.91 and top["cvss_score"] == 8.1
    mystery = [f for f in findings if f["component"] == "mystery-lib"][0]
    assert mystery["component_version"] is None and mystery["in_kev"] is False and mystery["epss_score"] is None


def test_findings_are_sorted_by_certainty(tmp_path):
    db = load_samples(tmp_path)
    services.run_matching(db)
    order = ["confirmed", "probable", "uncertain", "insufficient_data"]
    statuses = [f["status"] for f in services.list_findings(db)]
    assert statuses == sorted(statuses, key=order.index)


def test_count_by_status_has_all_four_keys():
    assert services.count_by_status([]) == {
        "confirmed": 0, "probable": 0, "uncertain": 0, "insufficient_data": 0}
