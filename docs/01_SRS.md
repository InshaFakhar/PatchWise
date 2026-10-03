# PatchWise — Software Requirements Specification (SRS)

**Project:** PatchWise: An AI-Assisted Vulnerability Management and Prioritization System
**Team:** Insha Fakhar, Anza Imtiaz, Rayyan Akram
**Supervisor:** Dr. Umar Shaoib
**Institution:** Department of Computer Science, Faculty of Computing & IT, University of Gujrat, Punjab, Pakistan
**Document version:** 0.1 (Phase 1 draft — pending supervisor review)

> **Source rule for this document.** Everything in Sections 1–9 comes **only** from two sources:
> - **[P]** = the approved FYP proposal (*PatchWise_FYP_Proposal_Final_5*)
> - **[B]** = the original brief (*Student Project Ideas, Project 2: AI-Assisted Vulnerability Management and Prioritization*, Dr. Ali Hur, ECU)
>
> Anything the two sources do **not** define is listed in Section 10 ("Open Items") and will be settled later as a *Proposed Decision (PD)* in `03_scope_and_decisions.md`. No PD is written into the requirements below.

---

## 1. Introduction

### 1.1 Purpose
This SRS states **what** PatchWise must do. It does not say **how** it will be built. It is the baseline for design, implementation, testing, and the final defense.

### 1.2 Problem statement
Security teams receive far more vulnerability alerts from scanners and public feeds than they can triage manually. Existing tools rarely combine **asset criticality, exploitability, and known exploitation** into one ranking that is both **explainable** and **reproducible** [P §2]. Analysts also need to review and override automated priorities before committing to a patch plan [P §1].

### 1.3 Product summary
PatchWise is a sandbox-friendly, AI-assisted system that:
1. loads a **synthetic asset inventory** together with **public vulnerability signals** (CVE, CISA KEV, EPSS);
2. computes a **deterministic, reproducible, factor-based priority ranking**;
3. uses an **LLM only to explain** each ranking by citing the computed factors, never inventing its own score;
4. lets an analyst **Accept, Bump, or Defer** each item (human-in-the-loop);
5. **exports** the final shortlist for patch planning [P Abstract, §3, §5; B Project Summary].

### 1.4 Intended audience of the product [P §6]
- Security analysts and patch-management teams
- Smaller organizations without expensive commercial prioritization tools
- Students and researchers exploring explainable AI in cybersecurity

### 1.5 Definitions
See `02_glossary.md`.

---

## 2. Overall Description

### 2.1 Core principle (architectural rule)
There is a **strict separation between ranking and explanation** [P §8]:
- The **Deterministic Ranking Engine** computes the numeric priority from documented factors.
- The **LLM Explanation Layer** only describes, in natural language, a ranking that has *already* been computed. It never generates or invents a risk score.

### 2.2 System flow [P §8, Figure 1]
```
Synthetic Asset Inventory + Public Vulnerability Data (CVE, CISA KEV, EPSS)
        -> Data Ingestion Pipeline
        -> Local Structured Data Store (SQLite)
        -> Deterministic Factor-Based Ranking Engine
        -> Reproducible Prioritized Vulnerability Queue
        -> LLM Explanation Layer
        -> Human-in-the-Loop Analyst Review (Bump / Defer / Accept)
        -> Updated Priority Queue
        -> Exportable Patch-Priority Report (CSV / Markdown / PDF)
```

### 2.3 User class
**Security analyst / reviewer:** reviews the ranked queue, reads explanations, overrides priorities, and exports the shortlist [P §1, §6].

### 2.4 Operating environment [P §9]
| Category | Specification |
|---|---|
| Development machine | Core i5 (8th gen or later) / i7, 8–16 GB RAM, 256 GB SSD |
| Operating system | Windows / Linux / macOS |
| Language | Python 3.x |
| Data handling | Pandas (CSV/JSON) |
| Data store | SQLite |
| Interface | Flask web UI or CLI |
| AI component | LLM API (Gemini/Groq, free tier, constrained prompts) |
| Tools | VS Code, Git/GitHub |

### 2.5 Constraints
- Uses **synthetic and public data only** [P §5; B Project Summary].
- Deliverables intended for **open-source release under the MIT license** [P Abstract; B Project Summary].
- Must be feasible for the 3-student team within **32 weeks** (7th and 8th semesters) [P §12].

---

## 3. Functional Requirements

All requirements below are **Official (O)**: they are stated or directly implied by [P] and/or [B]. "Source" shows where each comes from.

### 3.1 Data ingestion
| ID | Requirement | Source |
|---|---|---|
| FR-01 | The system shall load a **synthetic asset inventory** that includes **criticality** and **exposure** tags. | [B] Data Ingest Module; [P §7] |
| FR-02 | The system shall load public vulnerability signals: **CVE details/metadata, CISA KEV, and EPSS scores**. | [B] Data Ingest Module; [P §7] |
| FR-03 | The system shall store the ingested data in a **local structured data store** (SQLite). | [B] "local data store"; [P §7, §9, §11] |

### 3.2 Deterministic ranking
| ID | Requirement | Source |
|---|---|---|
| FR-04 | The system shall compute priority with a **deterministic, factor-based scoring system** that combines **asset criticality, exploitability, and known exploitation**. | [P §7] |
| FR-05 | The ranking shall also account for **exposure** (the brief names criticality, exploitability, and exposure as the documented factors). | [B] Success Criteria |
| FR-06 | The system shall produce a **ranked, prioritized queue** of vulnerabilities. | [B] Deliverables; [P §7] |
| FR-07 | The same inputs shall **always** produce the same ordering (**reproducible**). | [P §5, §8]; [B] Success Criteria |
| FR-08 | The ranking factors shall be **documented**. | [B] Success Criteria |
| FR-09 | The ranking engine shall operate **independently of the LLM**: it must work completely without any LLM call. | [B] Deliverables; [P §5, §7] |

### 3.3 LLM explanation
| ID | Requirement | Source |
|---|---|---|
| FR-10 | The system shall generate a **natural-language rationale** for each ranked item. | [B] LLM Explainer; [P §7] |
| FR-11 | Each rationale shall **explicitly cite the computed factors** of that item. | [B]; [P §7] |
| FR-12 | The LLM shall **never** generate, invent, or hallucinate numeric scores or priorities. | [B]; [P §3, §8, §11] |
| FR-13 | When the underlying factors change, **both the rank and the generated explanation** shall update. | [B] Success Criteria |

### 3.4 Human-in-the-loop (HITL) and export
| ID | Requirement | Source |
|---|---|---|
| FR-14 | The system shall provide a **simple web or CLI interface** for analyst review. | [B] HITL UI; [P §9, §11] |
| FR-15 | An analyst shall be able to **Bump, Defer, or Accept** any ranked item. | [B]; [P §3, §7] |
| FR-16 | After overrides, the system shall present an **updated priority queue**. | [P §8, Figure 1] |
| FR-17 | The system shall **export** the shortlist/report in **CSV, Markdown, or (lightweight) PDF**. | [B] HITL UI; [P §7] |
| FR-18 | The exported report shall be **clear and actionable** and ready for demonstration. | [B] Success Criteria |

### 3.5 Evaluation, demo, and deployment
| ID | Requirement | Source |
|---|---|---|
| FR-19 | The project shall provide a **structured evaluation set** that checks **expected orderings**. | [B] Demo & Evaluation Pack; [P §7] |
| FR-20 | The evaluation shall check **explanation consistency**. | [P §7] |
| FR-21 | The evaluation shall show that the ranking is **reproducible** and that **changing factors** changes rank and explanation accordingly. | [B] Success Criteria |
| FR-22 | The project shall include a **comprehensive README and sample data** for demonstration. | [B] Demo & Evaluation Pack; [P §12] |
| FR-23 | The Flask (or CLI) application and its local data store shall be **deployed to a cloud/VPS** environment, with a **domain** for the interface, for demonstration and evaluation. | [P §11, §10] |

---

## 4. Non-Functional Requirements

| ID | Requirement | Source |
|---|---|---|
| NFR-01 | **Reproducibility:** the priority queue is always reproducible and auditable. | [P §5] |
| NFR-02 | **Explainability:** every ranking can be explained to an analyst in terms of its factors. | [P §1, §3] |
| NFR-03 | **Data safety:** only synthetic and public data are used. | [P §5]; [B] |
| NFR-04 | **Open source:** all deliverables are intended for release under the MIT license. | [P Abstract]; [B] |
| NFR-05 | **Sandbox-friendly:** the system must run in a sandbox/local environment without proprietary infrastructure. | [P Abstract]; [B] Project Summary |
| NFR-06 | **Simplicity:** the interface is "light"/simple, not a full enterprise platform. | [B] Project Summary |
| NFR-07 | **Constrained AI use:** the LLM is used with *constrained prompts* that require citing computed factors. | [P §9, §11] |
| NFR-08 | **Low cost:** development uses free public data sources and a free-tier LLM API; the planning estimate for the demo deployment is PKR 21,500 (an estimate, not a guaranteed expenditure). | [P §10] |

---

## 5. Data Requirements (what the sources require us to handle)

- **Synthetic asset inventory** with at least: **criticality** and **exposure** tags [B; P §7].
- **CVE metadata/details** [B; P §7].
- **CISA KEV** data: indicates known exploitation [B; P §7].
- **EPSS scores**: exploit-probability scores [B; P §7].
- All data are **synthetic or public** [P §5].

*(Exact fields, table design, and file formats are not specified in [P] or [B]. See Open Items.)*

---

## 6. Deliverables

From [B] (Scope of Work & Deliverables) and [P] (§7, §12):

| # | Deliverable | Planned milestone [P §12] |
|---|---|---|
| D1 | Data Ingest Module / Working ingestion pipeline | Weeks 2–6 |
| D2 | Deterministic Ranking Engine | Weeks 6–12 |
| D3 | LLM Explainer (and mid-evaluation demo) | Weeks 12–16 |
| D4 | HITL Override & Export UI | Weeks 16–19 |
| D5 | Evaluation set and results | Weeks 19–22 |
| D6 | Integrated system and README | Weeks 22–27 |
| D7 | Deployed demo, final documentation, defense preparation | Weeks 27–32 |
| D0 | Project proposal and SRS | Weeks 1–2 |

---

## 7. Success Criteria [B]

1. The deterministic ranking engine **reliably produces a reproducible shortlist** driven by documented factors such as criticality, exploitability, and exposure.
2. The LLM **explains rankings by citing computed factors**; modifying the underlying factors **immediately updates both the rank and the explanation**.
3. The HITL interface lets reviewers **override priorities** and **export a clear, actionable report** ready for demonstration.

---

## 8. Work Division [P §13]

| Member | Responsibilities |
|---|---|
| Insha Fakhar | LLM explainer implementation and prompt design; HITL override and export interface (web/CLI) |
| Anza Imtiaz | Deterministic ranking and factor-engine development; deployment and hosting of the demo interface |
| Rayyan Akram | Asset and public feed ingestion and data modeling; evaluation set design, report export formatting, demo hardening |
| All | Joint responsibility for integration testing, documentation, and the MIT open-source release |

---

## 9. Out of Scope (derived from the sources)

- Anything that is not part of the five brief deliverables (ingest, deterministic ranking, LLM explainer, HITL/export, evaluation/demo pack) or the proposal's deployment goal.
- Real organizational or confidential data (the project is limited to synthetic and public data).
- An LLM that produces or alters priority scores (explicitly prohibited).

*(The fuller "IS / IS NOT" list is in `03_scope_and_decisions.md`.)*

---

## 10. Open Items (not defined by [P] or [B]; to be resolved as Proposed Decisions)

| # | Open item | Where it will be decided |
|---|---|---|
| OI-1 | How synthetic assets are linked to specific CVEs | Phase 4–5 |
| OI-2 | The exact scoring formula, weights, and tie-break rule | Phase 8 |
| OI-3 | What "exploitability" is measured by (e.g., EPSS, CVSS) | Phase 8 |
| OI-4 | Exact meaning of Accept / Bump / Defer and how they change the queue | Phase 10–11 |
| OI-5 | Database table and column design | Phase 4 |
| OI-6 | Handling of live feeds vs fixed snapshots for reproducible evaluation | Phase 6 |
| OI-7 | Which LLM provider (the proposal names Gemini/Groq) and how output is validated | Phase 9 |
| OI-8 | Web (Flask) vs CLI, or both | Phase 14 |
| OI-9 | PDF generation method and which formats are mandatory vs optional | Phase 12 |
| OI-10 | Hosting stack and access protection for the demo | Phase 15 |
| OI-11 | The proposal's cost table lists an LLM "paid tier" buffer while the tools section says "free tier". Confirm free tier is the primary plan. | Phase 9 |
| OI-12 | The brief lists exposure as a ranking factor; the proposal's objective lists criticality, exploitability, and known exploitation. We treat the union of both as official (FR-04, FR-05). Confirm with supervisor. | Phase 1 review |