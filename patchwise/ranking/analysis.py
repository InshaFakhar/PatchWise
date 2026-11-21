"""Comparing rankings and testing how stable the weights are (FR-05, evaluation).

kendall_tau          how similar are two orders?  1 = same order, -1 = exactly reversed
top_k_agreement      how many of the top K items are the same in both orders
sensitivity          change ONE weight at a time by +/-50 percent, re-rank, and compare
                     with the original ranking. If tiny weight changes flip the whole
                     list, the model is fragile; if the order stays similar, it is stable.
"""

import copy

from patchwise.ranking import scoring


def kendall_tau(order_a, order_b):
    """Kendall rank correlation of two orders (lists of ids). None if fewer than 2 shared ids."""
    pos_b = {item: i for i, item in enumerate(order_b)}
    shared = [x for x in order_a if x in pos_b]
    concordant = discordant = 0
    for i in range(len(shared)):
        for j in range(i + 1, len(shared)):
            if pos_b[shared[j]] > pos_b[shared[i]]:
                concordant += 1
            else:
                discordant += 1
    pairs = concordant + discordant
    return None if pairs == 0 else (concordant - discordant) / pairs


def top_k_agreement(order_a, order_b, k):
    """Fraction (0..1) of the top-k ids of order_a that are also in the top-k of order_b."""
    k = min(k, len(order_a), len(order_b))
    if k <= 0:
        return None
    return len(set(order_a[:k]) & set(order_b[:k])) / k


def sensitivity(findings, config=None, change=0.5, top_k=3):
    """One row per (factor, +/-change). Each row compares the new ranking with the original."""
    cfg = scoring.validate_config(config if config is not None else scoring.get_config())
    base = [f["match_id"] for f in scoring.rank_findings(findings, cfg)]
    k = min(top_k, len(base))
    rows = []
    for factor in scoring.FACTORS:
        for sign in (1, -1):
            changed = copy.deepcopy(cfg)
            changed["weights"][factor] = cfg["weights"][factor] * (1 + sign * change)
            if sum(changed["weights"].values()) <= 0:
                continue
            order = [f["match_id"] for f in scoring.rank_findings(findings, changed)]
            rows.append({
                "factor": factor,
                "label": scoring.FACTOR_LABELS[factor],
                "change": f"{sign * change:+.0%}",
                "tau": kendall_tau(base, order),
                "top_k": k,
                "top_k_agreement": top_k_agreement(base, order, k),
                "top1_unchanged": (order[0] == base[0]) if order else None,
            })
    return rows


if __name__ == "__main__":
    # Temporary runner until the real CLI exists (Phase 14).
    from patchwise import services

    report = services.sensitivity_report()
    print("Weight sensitivity (one weight changed at a time, compared with the current ranking)")
    for r in report:
        tau = "n/a" if r["tau"] is None else f"{r['tau']:.2f}"
        agree = "n/a" if r["top_k_agreement"] is None else f"{round(r['top_k_agreement'] * r['top_k'])}/{r['top_k']}"
        print(f"  {r['label']:<12} {r['change']:>5}   similarity {tau:>5}   top-{r['top_k']} same {agree:>4}   #1 same: {r['top1_unchanged']}")
