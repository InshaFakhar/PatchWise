import copy
import random
import sqlite3

import pytest

from patchwise import services
from patchwise.ingest.epss import load_epss
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.kev import load_kev
from patchwise.ingest.nvd import load_nvd
from patchwise.ingest.sbom import import_sbom
from patchwise.ranking import scoring
from patchwise.ranking.analysis import kendall_tau, sensitivity, top_k_agreement

CFG = scoring.DEFAULT_CONFIG


def finding(match_id=1, cvss=8.1, epss=0.91, kev=True, criticality="Critical",
            exposure="Internet-facing", cve="CVE-2099-0001", asset="A001",
            component="examplelib", version="2.3.1"):
    return {
        "match_id": match_id, "cvss_score": cvss, "epss_score": epss, "in_kev": kev,
        "criticality": criticality, "exposure": exposure, "cve_id": cve,
        "asset_id": asset, "component": component, "component_version": version,
    }


def with_weights(**weights):
    cfg = copy.deepcopy(CFG)
    cfg["weights"] = {f: 0 for f in scoring.FACTORS}
    cfg["weights"].update(weights)
    return cfg


# ---------- scoring one finding ----------

def test_worked_example_from_the_documentation():
    result = scoring.score_finding(finding(), CFG)
    points = {name: f["points"] for name, f in result["factors"].items()}
    assert points["cvss"] == pytest.approx(16.2)
    assert points["epss"] == pytest.approx(22.75)
    assert points["kev"] == pytest.approx(25.0)
    assert points["criticality"] == pytest.approx(15.0)
    assert points["exposure"] == pytest.approx(15.0)
    assert result["score"] == pytest.approx(93.95)


def test_breakdown_adds_up_to_the_score():
    result = scoring.score_finding(finding(cvss=5.3, epss=0.02, kev=False, criticality="High", exposure="DMZ"), CFG)
    assert sum(f["points"] for f in result["factors"].values()) == pytest.approx(result["score"])


def test_each_factor_is_scaled_to_zero_one():
    f = scoring.score_finding(finding(cvss=8.1, epss=0.91, kev=True, criticality="Critical", exposure="DMZ"), CFG)["factors"]
    assert f["cvss"]["value"] == pytest.approx(0.81)
    assert f["epss"]["value"] == pytest.approx(0.91)
    assert f["kev"]["value"] == 1.0
    assert f["criticality"]["value"] == 1.0
    assert f["exposure"]["value"] == pytest.approx(0.67)


def test_best_possible_finding_scores_100():
    best = finding(cvss=10, epss=1.0, kev=True, criticality="Critical", exposure="Internet-facing")
    assert scoring.score_finding(best, CFG)["score"] == pytest.approx(100.0)


def test_score_always_stays_between_0_and_100():
    for cvss in (None, 0, 5, 10):
        for epss in (None, 0, 0.5, 1):
            for kev in (False, True):
                for crit in scoring.CRITICALITY_LABELS:
                    for exp in scoring.EXPOSURE_LABELS:
                        s = scoring.score_finding(finding(cvss=cvss, epss=epss, kev=kev,
                                                          criticality=crit, exposure=exp), CFG)["score"]
                        assert 0 <= s <= 100


def test_missing_values_give_zero_points_and_are_flagged_unknown():
    full = scoring.score_finding(finding(), CFG)
    missing = scoring.score_finding(finding(cvss=None, epss=None), CFG)
    assert missing["factors"]["cvss"]["unknown"] and missing["factors"]["cvss"]["points"] == 0
    assert missing["factors"]["epss"]["unknown"] and missing["factors"]["epss"]["points"] == 0
    assert missing["score"] < full["score"]


def test_kev_not_listed_is_zero_but_not_unknown():
    kev = scoring.score_finding(finding(kev=False), CFG)["factors"]["kev"]
    assert kev["points"] == 0 and kev["unknown"] is False


def test_unknown_asset_label_is_flagged_not_a_crash():
    result = scoring.score_finding(finding(criticality="Weird"), CFG)
    assert result["factors"]["criticality"]["unknown"] is True


def test_only_the_proportions_of_the_weights_matter():
    doubled = copy.deepcopy(CFG)
    doubled["weights"] = {k: v * 2 for k, v in CFG["weights"].items()}
    f = finding(cvss=7.0, epss=0.3, kev=False, criticality="High", exposure="DMZ")
    assert scoring.score_finding(f, doubled)["score"] == pytest.approx(scoring.score_finding(f, CFG)["score"])


def test_a_zero_weight_switches_the_factor_off():
    cfg = copy.deepcopy(CFG)
    cfg["weights"]["kev"] = 0
    listed = scoring.score_finding(finding(kev=True), cfg)["score"]
    not_listed = scoring.score_finding(finding(kev=False), cfg)["score"]
    assert listed == pytest.approx(not_listed)


# ---------- configuration ----------

def test_default_config_is_valid_and_returned_as_a_copy():
    cfg = scoring.validate_config(CFG)
    cfg["weights"]["cvss"] = 999
    assert CFG["weights"]["cvss"] == 20


def test_config_file_matches_the_built_in_defaults():
    assert scoring.load_config(scoring.CONFIG_PATH) == scoring.validate_config(scoring.DEFAULT_CONFIG)
    assert scoring.get_config() == scoring.validate_config(scoring.DEFAULT_CONFIG)


def test_weight_shares_add_up_to_100():
    shares = scoring.weight_shares(CFG)
    assert sum(shares.values()) == pytest.approx(100.0)
    assert shares["kev"] == pytest.approx(25.0)


def test_bad_configs_are_rejected_with_a_clear_message():
    def broken(mutator):
        cfg = copy.deepcopy(CFG)
        mutator(cfg)
        return cfg

    cases = [
        (lambda c: c["weights"].pop("kev"), "missing"),
        (lambda c: c["weights"].update(speed=1), "unknown weight"),
        (lambda c: c["weights"].update(cvss=-1), "0 or more"),
        (lambda c: c["weights"].update(cvss="high"), "must be a number"),
        (lambda c: c["weights"].update(cvss=True), "must be a number"),
        (lambda c: c["weights"].update({f: 0 for f in scoring.FACTORS}), "greater than 0"),
        (lambda c: c["criticality"].pop("High"), "High"),
        (lambda c: c["exposure"].update(DMZ=1.5), "between 0 and 1"),
        (lambda c: c.pop("exposure"), "exposure"),
    ]
    for mutator, expected_text in cases:
        with pytest.raises(ValueError) as error:
            scoring.validate_config(broken(mutator))
        assert expected_text in str(error.value)
    with pytest.raises(ValueError):
        scoring.validate_config("not a dict")


def test_load_config_reads_a_custom_toml_file(tmp_path):
    path = tmp_path / "custom.toml"
    path.write_text(
        "[weights]\ncvss=1\nepss=1\nkev=1\ncriticality=1\nexposure=1\n"
        "[criticality]\nLow=0\nMedium=0.3\nHigh=0.6\nCritical=1\n"
        "[exposure]\nInternal=0\nDMZ=0.5\nInternet-facing=1\n", encoding="utf-8")
    cfg = scoring.load_config(path)
    assert scoring.weight_shares(cfg)["cvss"] == pytest.approx(20.0)
    assert cfg["criticality"]["Medium"] == 0.3


def test_load_config_rejects_a_bad_file(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("[weights]\ncvss = -5\n", encoding="utf-8")
    with pytest.raises(ValueError):
        scoring.load_config(path)


# ---------- ranking many findings ----------

def sample_findings():
    return [
        finding(1, cvss=8.1, epss=0.91, kev=True, criticality="Critical", exposure="Internet-facing", cve="CVE-2099-0001"),
        finding(2, cvss=9.8, epss=0.45, kev=True, criticality="Critical", exposure="Internal", cve="CVE-2099-0002"),
        finding(3, cvss=5.3, epss=0.02, kev=False, criticality="Low", exposure="Internal", cve="CVE-2099-0003"),
        finding(4, cvss=None, epss=None, kev=False, criticality="Medium", exposure="DMZ", cve="CVE-2099-0004"),
    ]


def test_higher_score_ranks_first_and_ranks_are_consecutive():
    ranked = scoring.rank_findings(sample_findings(), CFG)
    assert [r["rank"] for r in ranked] == [1, 2, 3, 4]
    scores = [r["score"] for r in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked[0]["match_id"] == 1


def test_ranking_does_not_modify_its_input():
    findings = sample_findings()
    before = copy.deepcopy(findings)
    scoring.rank_findings(findings, CFG)
    assert findings == before


def test_result_does_not_depend_on_input_order():
    findings = sample_findings()
    expected = [r["match_id"] for r in scoring.rank_findings(findings, CFG)]
    rng = random.Random(1)
    for _ in range(20):
        shuffled = findings[:]
        rng.shuffle(shuffled)
        assert [r["match_id"] for r in scoring.rank_findings(shuffled, CFG)] == expected


def test_equal_scores_are_broken_by_higher_asset_criticality():
    cfg = with_weights(cvss=10, criticality=10)           # 50 / 50
    a = finding(1, cvss=5.0, criticality="Critical")      # 0.5 + 1.0
    b = finding(2, cvss=10.0, criticality="Medium")       # 1.0 + 0.5
    ranked = scoring.rank_findings([b, a], cfg)
    assert ranked[0]["score"] == pytest.approx(ranked[1]["score"])
    assert [r["match_id"] for r in ranked] == [1, 2]


def test_completely_equal_findings_are_ordered_by_cve_id():
    a = finding(1, cve="CVE-2099-0009")
    b = finding(2, cve="CVE-2099-0002")
    ranked = scoring.rank_findings([a, b], CFG)
    assert [r["cve_id"] for r in ranked] == ["CVE-2099-0002", "CVE-2099-0009"]


def test_cvss_only_baseline_orders_by_cvss_and_puts_unknown_last():
    ordered = scoring.rank_cvss_only(sample_findings())
    assert [f["cvss_score"] for f in ordered] == [9.8, 8.1, 5.3, None]
    assert [f["cvss_rank"] for f in ordered] == [1, 2, 3, 4]


def test_cvss_only_baseline_ignores_kev_epss_and_the_asset():
    a = finding(1, cvss=7.0, epss=0.99, kev=True, criticality="Critical", cve="CVE-2099-0002")
    b = finding(2, cvss=7.0, epss=0.0, kev=False, criticality="Low", cve="CVE-2099-0001")
    ordered = scoring.rank_cvss_only([a, b])
    assert [f["cve_id"] for f in ordered] == ["CVE-2099-0001", "CVE-2099-0002"]   # name order only


def test_patchwise_and_cvss_only_can_disagree():
    findings = [
        finding(1, cvss=9.8, epss=0.0, kev=False, criticality="Low", exposure="Internal"),
        finding(2, cvss=5.0, epss=0.9, kev=True, criticality="Critical", exposure="Internet-facing"),
    ]
    assert scoring.rank_findings(findings, CFG)[0]["match_id"] == 2
    assert scoring.rank_cvss_only(findings)[0]["match_id"] == 1


# ---------- comparing rankings ----------

def test_kendall_tau_values():
    assert kendall_tau([1, 2, 3], [1, 2, 3]) == 1.0
    assert kendall_tau([1, 2, 3], [3, 2, 1]) == -1.0
    assert kendall_tau([1, 2, 3], [1, 3, 2]) == pytest.approx(1 / 3)
    assert kendall_tau([1], [1]) is None


def test_top_k_agreement_values():
    assert top_k_agreement([1, 2, 3, 4], [2, 1, 4, 3], 2) == 1.0
    assert top_k_agreement([1, 2, 3, 4], [3, 4, 1, 2], 2) == 0.0
    assert top_k_agreement([1, 2], [2, 1], 5) == 1.0          # k larger than the list
    assert top_k_agreement([], [], 3) is None


def test_sensitivity_gives_one_row_per_factor_and_direction():
    rows = sensitivity(sample_findings(), CFG)
    assert len(rows) == 10
    assert {r["factor"] for r in rows} == set(scoring.FACTORS)
    assert {r["change"] for r in rows} == {"+50%", "-50%"}
    for r in rows:
        assert -1 <= r["tau"] <= 1
        assert 0 <= r["top_k_agreement"] <= 1


def test_sensitivity_does_not_change_the_config():
    cfg = copy.deepcopy(CFG)
    sensitivity(sample_findings(), cfg)
    assert cfg == CFG


def test_sensitivity_detects_a_fragile_ranking():
    findings = [
        finding(1, cvss=10, epss=0.0, kev=False, criticality="Medium", exposure="DMZ"),
        finding(2, cvss=5, epss=0.0, kev=True, criticality="Medium", exposure="DMZ"),
    ]
    cfg = with_weights(cvss=10, kev=10)
    rows = {(r["factor"], r["change"]): r for r in sensitivity(findings, cfg, change=0.6)}
    flipped = rows[("kev", "-60%")]
    assert flipped["tau"] == -1.0 and flipped["top1_unchanged"] is False


def test_sensitivity_skips_changes_that_would_remove_every_weight():
    rows = sensitivity(sample_findings(), with_weights(kev=10), change=1.0)
    assert not any(r["factor"] == "kev" and r["change"] == "-100%" for r in rows)


# ---------- the database layer, on the project's sample data ----------

def load_samples(tmp_path):
    db = tmp_path / "t.db"
    import_inventory("data/synthetic/assets.csv", db)
    for asset in ("A001", "A002", "A003"):
        import_sbom(f"data/synthetic/sbom_{asset}.json", asset, db)
    load_kev("data/snapshots/kev_sample.json", db)
    load_nvd("data/snapshots/nvd_sample.json", db)
    load_epss("data/snapshots/epss_sample.csv", db)
    services.run_matching(db)
    return db


def names(ranked):
    return [(r["hostname"], r["component"], r["component_version"], r["cve_id"]) for r in ranked]


EXPECTED_SAMPLE_ORDER = [
    ("web-prod-01", "examplelib", "2.3.1", "CVE-2099-0001"),
    ("api-prod-01", "examplelib", None, "CVE-2099-0001"),
    ("web-prod-01", "samplehttpd", "5.2.0", "CVE-2099-0002"),
    ("db-prod-01", "samplehttpd", "5.1.0", "CVE-2099-0002"),
    ("web-prod-01", "demoparser", "1.0.4", "CVE-2099-0003"),
    ("api-prod-01", "demoparser-extras", "1.0.4", "CVE-2099-0003"),
    ("db-prod-01", "demoparser", "1.0.4-1", "CVE-2099-0003"),
    ("web-prod-01", "mystery-lib", None, "CVE-2099-0006"),
    ("api-prod-01", "examplelib", None, "CVE-2099-0004"),
    ("db-prod-01", "examplelib", "2.10.0", "CVE-2099-0004"),
]


def test_sample_data_gives_the_expected_ranking(tmp_path):
    ranked = services.list_ranked(load_samples(tmp_path))
    assert names(ranked) == EXPECTED_SAMPLE_ORDER
    assert [r["rank"] for r in ranked] == list(range(1, 11))
    assert ranked[0]["score"] == pytest.approx(93.95)
    for r in ranked:
        assert sum(f["points"] for f in r["factors"].values()) == pytest.approx(r["score"])


def test_sample_data_shows_where_patchwise_differs_from_cvss_only(tmp_path):
    ranked = services.list_ranked(load_samples(tmp_path))
    top = ranked[0]
    assert top["component"] == "examplelib" and top["cvss_rank"] == 3        # CVSS-only would put it 3rd
    cvss_first = [r for r in ranked if r["cvss_rank"] == 1][0]
    assert cvss_first["component"] == "samplehttpd" and cvss_first["rank"] == 3
    patchwise_order = [r["match_id"] for r in ranked]
    cvss_order = [r["match_id"] for r in sorted(ranked, key=lambda r: r["cvss_rank"])]
    assert kendall_tau(patchwise_order, cvss_order) < 1


def test_changing_a_factor_changes_score_and_rank(tmp_path):
    db = load_samples(tmp_path)
    before = {names([r])[0]: r for r in services.list_ranked(db)}
    key = ("db-prod-01", "samplehttpd", "5.1.0", "CVE-2099-0002")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE assets SET criticality = 'Low' WHERE asset_id = 'A003'")
    conn.commit()
    conn.close()
    after = {names([r])[0]: r for r in services.list_ranked(db)}
    assert after[key]["score"] < before[key]["score"]
    assert after[key]["rank"] > before[key]["rank"]


def test_changing_a_weight_changes_the_scores(tmp_path):
    db = load_samples(tmp_path)
    default_top = services.list_ranked(db)[0]["score"]
    no_kev = copy.deepcopy(CFG)
    no_kev["weights"]["kev"] = 0
    assert services.list_ranked(db, no_kev)[0]["score"] != pytest.approx(default_top)


def test_ranking_is_reproducible(tmp_path):
    db = load_samples(tmp_path)
    first = services.list_ranked(db)
    for _ in range(5):
        assert services.list_ranked(db) == first


def test_empty_database_gives_an_empty_ranking(tmp_path):
    assert services.list_ranked(tmp_path / "empty.db") == []


def test_service_weight_labels_are_in_display_order():
    shares = services.weight_shares()
    assert [label for label, _ in shares] == ["CVSS", "EPSS", "KEV", "Criticality", "Exposure"]
    assert sum(share for _, share in shares) == pytest.approx(100.0)


def test_sensitivity_report_on_the_sample_data(tmp_path):
    rows = services.sensitivity_report(load_samples(tmp_path))
    assert len(rows) == 10
    assert all(0.9 <= r["tau"] <= 1.0 for r in rows)      # small sample, widely separated scores
