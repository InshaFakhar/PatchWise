import csv
import io
import sqlite3

import pytest

from patchwise import services
from patchwise.db.connection import get_connection
from patchwise.ingest.epss import load_epss
from patchwise.ingest.inventory import import_inventory
from patchwise.ingest.kev import load_kev
from patchwise.ingest.nvd import load_nvd
from patchwise.ingest.sbom import import_sbom
from patchwise.review import decisions
from patchwise.review.queue import build_queue, queue_counts


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


def finding_at_rank(db, rank):
    return [f for f in services.list_ranked(db) if f["rank"] == rank][0]


def decide(db, finding, action="accept", reason="checked with the owner", analyst="Insha"):
    return services.record_decision(finding["component_id"], finding["cve_id"], action, reason, analyst, db)


def queue_ids(db):
    return [(f["component_id"], f["cve_id"]) for f in services.list_queue(db)]


def ranked_ids(db):
    return [(f["component_id"], f["cve_id"]) for f in services.list_ranked(db)]


# ---------- validation ----------

def test_valid_decision_is_saved_with_context(tmp_path):
    db = load_samples(tmp_path)
    top = finding_at_rank(db, 1)
    decide(db, top, "Bump", "  ransomware seen in the wild  ", "  Insha  ")
    row = services.list_audit(db)[0]
    assert (row["action"], row["reason"], row["analyst_name"]) == ("bump", "ransomware seen in the wild", "Insha")
    assert row["rank_at_decision"] == 1 and row["score_at_decision"] == pytest.approx(93.95)
    assert row["hostname"] == "web-prod-01" and row["cve_id"] == "CVE-2099-0001"


def test_invalid_input_is_rejected_with_a_clear_message():
    good = (1, "CVE-2099-0001", "accept", "because", "Insha")
    bad_cases = [
        ((1, "CVE-2099-0001", "approve", "because", "Insha"), "Accept, Bump or Defer"),
        ((1, "CVE-2099-0001", "accept", "", "Insha"), "reason is required"),
        ((1, "CVE-2099-0001", "accept", "   ", "Insha"), "reason is required"),
        ((1, "CVE-2099-0001", "accept", "x" * 501, "Insha"), "too long"),
        ((1, "CVE-2099-0001", "accept", "because", ""), "name is required"),
        ((1, "CVE-2099-0001", "accept", "because", "n" * 81), "too long"),
        ((1, "not-a-cve", "accept", "because", "Insha"), "CVE id"),
        (("abc", "CVE-2099-0001", "accept", "because", "Insha"), "component id"),
        ((0, "CVE-2099-0001", "accept", "because", "Insha"), "component id"),
        ((True, "CVE-2099-0001", "accept", "because", "Insha"), "component id"),
    ]
    assert decisions.validate_decision(*good)[0] == 1
    for args, expected in bad_cases:
        with pytest.raises(ValueError) as error:
            decisions.validate_decision(*args)
        assert expected in str(error.value), args


def test_a_finding_that_does_not_exist_is_rejected(tmp_path):
    db = load_samples(tmp_path)
    with pytest.raises(ValueError) as error:
        services.record_decision(9999, "CVE-2099-0001", "accept", "because", "Insha", db)
    assert "not in the current results" in str(error.value)
    assert services.list_audit(db) == []


# ---------- the audit history ----------

def test_history_cannot_be_edited_or_deleted(tmp_path):
    db = load_samples(tmp_path)
    decide(db, finding_at_rank(db, 1))
    conn = get_connection(db)
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE decisions SET reason = 'changed'")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM decisions")
    conn.close()
    assert services.list_audit(db)[0]["reason"] == "checked with the owner"


def test_database_itself_refuses_empty_reason_and_name(tmp_path):
    db = load_samples(tmp_path)
    top = finding_at_rank(db, 1)
    conn = get_connection(db)
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("INSERT INTO decisions (component_id, cve_id, action, reason, analyst_name, decided_at) "
                     "VALUES (?, ?, 'accept', '  ', 'Insha', 'now')", (top["component_id"], top["cve_id"]))
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("INSERT INTO decisions (component_id, cve_id, action, reason, analyst_name, decided_at) "
                     "VALUES (?, ?, 'delete', 'why', 'Insha', 'now')", (top["component_id"], top["cve_id"]))
    conn.close()


def test_audit_lists_newest_first_and_keeps_every_decision(tmp_path):
    db = load_samples(tmp_path)
    first = finding_at_rank(db, 1)
    decide(db, first, "bump", "first thought", "Insha")
    decide(db, first, "accept", "changed my mind", "Anza")
    history = services.list_audit(db)
    assert [h["reason"] for h in history] == ["changed my mind", "first thought"]
    assert [h["analyst_name"] for h in history] == ["Anza", "Insha"]


def test_decisions_survive_a_matching_rerun(tmp_path):
    db = load_samples(tmp_path)
    target = finding_at_rank(db, 5)
    decide(db, target, "defer", "waiting for the vendor patch")
    services.run_matching(db)          # the matches table is rebuilt (new match ids)
    queue = services.list_queue(db)
    same = [q for q in queue if (q["component_id"], q["cve_id"]) == (target["component_id"], target["cve_id"])][0]
    assert same["decision"]["action"] == "defer"


# ---------- the queue ----------

def test_bump_moves_a_finding_to_the_top(tmp_path):
    db = load_samples(tmp_path)
    last = finding_at_rank(db, 10)
    decide(db, last, "bump", "customer data is on this machine")
    queue = services.list_queue(db)
    assert (queue[0]["component_id"], queue[0]["cve_id"]) == (last["component_id"], last["cve_id"])
    assert queue[0]["queue_position"] == 1 and queue[0]["rank"] == 10


def test_defer_moves_a_finding_to_the_bottom(tmp_path):
    db = load_samples(tmp_path)
    top = finding_at_rank(db, 1)
    decide(db, top, "defer", "maintenance window next month")
    queue = services.list_queue(db)
    assert (queue[-1]["component_id"], queue[-1]["cve_id"]) == (top["component_id"], top["cve_id"])
    assert queue[-1]["rank"] == 1


def test_accept_keeps_the_position(tmp_path):
    db = load_samples(tmp_path)
    decide(db, finding_at_rank(db, 3), "accept", "agree with the ranking")
    assert queue_ids(db) == ranked_ids(db)


def test_no_decisions_means_queue_equals_ranking(tmp_path):
    db = load_samples(tmp_path)
    assert queue_ids(db) == ranked_ids(db)
    assert [q["queue_position"] for q in services.list_queue(db)] == list(range(1, 11))


def test_bumped_findings_keep_their_score_order(tmp_path):
    db = load_samples(tmp_path)
    for rank in (8, 4):
        decide(db, finding_at_rank(db, rank), "bump", "important")
    top_two = services.list_queue(db)[:2]
    assert [q["rank"] for q in top_two] == [4, 8]


def test_decisions_never_change_score_or_rank(tmp_path):
    db = load_samples(tmp_path)
    before = {(f["component_id"], f["cve_id"]): (f["rank"], f["score"]) for f in services.list_ranked(db)}
    decide(db, finding_at_rank(db, 10), "bump", "x")
    decide(db, finding_at_rank(db, 1), "defer", "y")
    after = {(f["component_id"], f["cve_id"]): (f["rank"], f["score"]) for f in services.list_ranked(db)}
    assert after == before
    for q in services.list_queue(db):
        assert (q["rank"], q["score"]) == before[(q["component_id"], q["cve_id"])]


def test_a_later_decision_replaces_the_earlier_one_in_the_queue(tmp_path):
    db = load_samples(tmp_path)
    target = finding_at_rank(db, 10)
    decide(db, target, "bump", "urgent")
    decide(db, target, "accept", "false alarm")
    assert queue_ids(db) == ranked_ids(db)
    assert len(services.list_audit(db)) == 2


def test_queue_counts(tmp_path):
    db = load_samples(tmp_path)
    decide(db, finding_at_rank(db, 1), "bump", "a")
    decide(db, finding_at_rank(db, 2), "accept", "b")
    decide(db, finding_at_rank(db, 3), "defer", "c")
    assert queue_counts(services.list_queue(db)) == {"bump": 1, "accept": 1, "defer": 1, "undecided": 7}


def test_queue_is_empty_before_matching(tmp_path):
    assert services.list_queue(tmp_path / "empty.db") == []
    assert services.list_audit(tmp_path / "empty.db") == []


def test_build_queue_is_pure_and_stable():
    ranked = [{"component_id": i, "cve_id": "CVE-2099-0001", "rank": i} for i in (1, 2, 3)]
    latest = {(3, "CVE-2099-0001"): {"action": "bump"}, (1, "CVE-2099-0001"): {"action": "defer"}}
    queue = build_queue(ranked, latest)
    assert [q["component_id"] for q in queue] == [3, 2, 1]
    assert [r["rank"] for r in ranked] == [1, 2, 3] and "decision" not in ranked[0]
