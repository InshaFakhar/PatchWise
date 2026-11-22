"""The review queue: the PatchWise ranking with the analyst's decisions applied (FR-07).

Order of the queue:
    1. bumped findings      (best PatchWise rank first)
    2. everything else      (accepted or undecided, best PatchWise rank first)
    3. deferred findings    (best PatchWise rank first)

The PatchWise rank and score are never changed. The queue only adds a second,
human-controlled position (queue_position) next to them.
"""

_GROUP = {"bump": 0, "accept": 1, None: 1, "defer": 2}


def build_queue(ranked, latest):
    """ranked: output of rank_findings (with component_id). latest: latest_decisions()."""
    items = []
    for finding in ranked:
        item = dict(finding)
        item["decision"] = latest.get((finding["component_id"], finding["cve_id"]))
        items.append(item)

    def key(item):
        action = item["decision"]["action"] if item["decision"] else None
        return (_GROUP[action], item["rank"])

    items.sort(key=key)
    for position, item in enumerate(items, start=1):
        item["queue_position"] = position
    return items


def queue_counts(queue):
    counts = {"bump": 0, "accept": 0, "defer": 0, "undecided": 0}
    for item in queue:
        counts[item["decision"]["action"] if item["decision"] else "undecided"] += 1
    return counts
