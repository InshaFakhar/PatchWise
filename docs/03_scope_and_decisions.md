# PatchWise — Scope Boundaries and Decision Register

**Document version:** 0.1 (Phase 1 draft)

---

## 1. Classification legend

Every project statement belongs to exactly one of these classes. We never present a PD or TB as if it were an official requirement.

| Label | Meaning | Who can change it |
|---|---|---|
| **O — Official** | Stated or directly implied by the approved proposal [P] or the brief [B]. | Only with supervisor approval |
| **TB — Team Boundary** | A rule our team set to keep the project safe and in scope. It is consistent with [P] and [B] but is not a sentence in them. | The team (tell the supervisor) |
| **PD — Proposed Decision** | An implementation choice for something the documents leave open. It is our suggestion. | The team, after supervisor confirmation |

---

## 2. What PatchWise IS

1. **O** — A system that **prioritizes known vulnerabilities** to help decide what to patch first.
2. **O** — A **sandbox-friendly** tool that runs on a **synthetic asset inventory** and **public** data (CVE, CISA KEV, EPSS).
3. **O** — A **deterministic, factor-based, reproducible** ranking engine.
4. **O** — A ranking that is **independent of the LLM**.
5. **O** — A system with an **LLM explainer** that cites the computed factors.
6. **O** — A **human-in-the-loop** workflow where analysts can **Accept, Bump, or Defer** items.
7. **O** — A producer of **exportable patch shortlists** (CSV / Markdown / PDF).
8. **O** — A project with a **structured evaluation set** (expected orderings, explanation consistency).
9. **O** — An **open-source (MIT)** project with README and sample data.
10. **O** — A system with a **demo deployment** on a cloud/VPS with a domain.

## 3. What PatchWise IS NOT

1. **TB** — **Not a vulnerability scanner.** It does not probe networks, hosts, or applications, and it does not discover vulnerabilities. It only ranks vulnerabilities that are already publicly known and listed in its input data. *(Consistent with [P] and [B]: both describe the system as consuming scanner/feed output and public data, never producing it.)*
2. **O** — **Not an LLM-based ranker.** The LLM never calculates, modifies, or invents a priority or risk score.
3. **TB** — **Not a replacement for the analyst.** The human makes the final decision.
4. **O** — **Not using real organizational data.** Only synthetic and public data.
5. **TB** — **Not an enterprise vulnerability-management platform.** It has no agents, ticketing integration, patch deployment, or scheduling.
6. **TB** — **Not a different cybersecurity project.** It stays strictly Project 2.
7. **TB** — **Not a source of new security research claims.** We do not claim PatchWise "predicts" attacks. It combines existing public signals in a transparent formula.

---

## 4. Decision register (Proposed Decisions)

All PDs below are **pending supervisor confirmation**. Each will be explained again, in simple terms, right before the phase that implements it.

| ID | Proposed Decision | Related open item | Decided in phase |
|---|---|---|---|
| PD-01 | Use a **synthetic "findings" file** that simulates scanner output, linking synthetic assets to real CVE IDs. PatchWise treats it as input and never discovers findings itself. | OI-1 | 4–5 |
| PD-02 | Score with a **transparent weighted sum**, with weights stored in a config file and documented. | OI-2 | 8 |
| PD-03 | Treat **EPSS as the main "exploitability" signal**, **KEV as the "known exploitation" signal**, and **CVSS as a supporting severity input**. | OI-3 | 8 |
| PD-04 | Apply a **fixed tie-break order** so equal scores always sort identically. | OI-2 | 8 |
| PD-05 | Define **Accept = confirm computed priority, Bump = move up, Defer = move down**, with a mandatory reason note; overrides are stored **separately** from the base score. | OI-4 | 10–11 |
| PD-06 | Support **live data fetch** and **pinned offline snapshot files**; run all evaluations on snapshots. | OI-6 | 6 |
| PD-07 | Use the **SQLite table design** from the roadmap (assets, cves, kev, epss, findings, ranking_runs, ranked_items, explanations, overrides, ingest_runs). | OI-5 | 4 |
| PD-08 | Protect the LLM boundary with a **constrained prompt, low temperature, output validator, template fallback, and caching**. | OI-7 | 9 |
| PD-09 | Choose **one primary LLM provider** (Gemini or Groq) behind a swappable wrapper; free tier first. | OI-7, OI-11 | 9 |
| PD-10 | Build a **CLI first**, then a **simple Flask UI** on top of the same service layer. | OI-8 | 14 |
| PD-11 | Core exports **CSV and Markdown**; **PDF** is kept lightweight and built last. | OI-9 | 12 |
| PD-12 | Deploy with **Gunicorn + Nginx + HTTPS** on a VPS, with simple login protection for the demo. | OI-10 | 15 |
| PD-13 | Use the **repository layout** and **GitHub feature-branch workflow** from the roadmap. | — | 3 |
| PD-14 | Use a **shared service layer** so CLI and Flask call the same functions. | — | 2 |

### Team Boundaries that affect implementation (TB)

| ID | Boundary |
|---|---|
| TB-01 | No API keys or secrets in source code. Keys come from environment variables / an untracked `.env` file. |
| TB-02 | The ranking package must never import or call the LLM package. |
| TB-03 | Do not add features outside Project 2. Anything extra is labeled **Optional** and approved first. |
| TB-04 | Prefer simple, explainable, reproducible implementations. |
| TB-05 | Only synthetic and public data may enter the repository. |

---

## 5. Terminology lock

To keep the proposal, code, documentation, and defense consistent, we always use these names:

| Use this | Do not use |
|---|---|
| Deterministic Ranking Engine | "AI ranker", "scoring AI", "risk model" |
| LLM Explanation Layer / LLM Explainer | "AI decision maker", "AI scorer" |
| Human-in-the-Loop (HITL) review | "manual step", "approval bot" |
| Override actions: **Bump / Defer / Accept** | Other action names |
| Priority queue / ranked queue | "risk list" |
| Synthetic asset inventory | "real inventory", "company data" |
| CISA KEV, EPSS, CVE | Alternative abbreviations |
| Finding (asset + CVE pair) **[PD-01]** | Mixed use of "alert", "issue", "vuln" for the same thing |

*If a term must change, record the change here first.*

---

## 6. Phase 1 approval checklist

- [ ] All three members have read `01_SRS.md`, `02_glossary.md`, and this file.
- [ ] Every member can explain "ranking vs explanation" in one sentence.
- [ ] Open items OI-11 and OI-12 raised with the supervisor.
- [ ] Supervisor feedback recorded (date, comments): ______________________
- [ ] Documents committed to Git.