# PatchWise — Glossary

Plain-language definitions for everyone on the team, and for the supervisor and examiners. Each entry says what the term means and **where it matters in PatchWise**.

> Terms marked **[PatchWise term]** are words we use inside the project, not official industry definitions.

---

## Vulnerability
A weakness in software or hardware that an attacker could use to harm a system (for example, to steal data or take control).
*Analogy:* a door lock with a known defect.
**In PatchWise:** a vulnerability is what we are ranking. PatchWise does **not** discover vulnerabilities. It prioritizes ones that are already publicly known.

## Patch
A software update that fixes a vulnerability.
**In PatchWise:** the final output is a *patch priority list*: which fixes to apply first.

## CVE (Common Vulnerabilities and Exposures)
A public ID given to one specific known vulnerability, written like `CVE-2021-44228`, together with a short description and other metadata (such as publication date).
*Analogy:* a case number for a vulnerability.
**In PatchWise:** CVE data tells us *what* the vulnerability is. It is one of the three public sources we ingest.

## CVSS (Common Vulnerability Scoring System)
A standard 0–10 score describing how **severe** a vulnerability is in general (for example, 9.8 is critical). It does **not** consider your organization: it rates the vulnerability in isolation.
**In PatchWise:** the proposal points out this limitation as part of the problem [Proposal §1]. CVSS is part of CVE metadata, so we have it available. How (or whether) it enters the formula is a decision for Phase 8.

## CISA KEV (Known Exploited Vulnerabilities catalog)
A list kept by CISA (the US Cybersecurity and Infrastructure Security Agency) of vulnerabilities that are **confirmed to be actively exploited by attackers in real life**.
*Meaning:* "being on the list" is strong evidence that attackers are already using it.
**In PatchWise:** KEV supplies the **known exploitation** factor. In simple terms it is a yes/no: listed or not listed.

## EPSS (Exploit Prediction Scoring System)
A score from **0 to 1** (also shown as a percentile) estimating the **probability that a vulnerability will be exploited** soon. It is published by FIRST and updated regularly. 0.90 means very likely, 0.01 means unlikely.
**In PatchWise:** EPSS is a public signal of how **exploitable** a vulnerability is expected to be.

## Asset
Anything in an organization's environment that has value and could be affected: a web server, a database, an employee laptop, a network device.
**In PatchWise:** assets come from a **synthetic** (made-up) inventory. No real company data is used.

## Asset criticality
How important an asset is to the organization. A payment database is more critical than a test laptop. It is usually a level such as Low, Medium, High, Critical.
**In PatchWise:** criticality is a required tag on every asset and a core ranking factor. The same vulnerability matters more on a critical asset.

## Exposure
How reachable an asset is to attackers. An internet-facing server is more exposed than a machine on an internal-only network.
**In PatchWise:** exposure is a required tag on every asset and a ranking factor. The same vulnerability is riskier on an internet-facing system.

## Finding **[PatchWise term]**
One pairing of "this asset is affected by this CVE." Prioritization ranks findings, because the same CVE on two different assets can deserve different priorities.
**In PatchWise:** how findings are created from synthetic data is an open item (OI-1) to be decided as a Proposed Decision. They are *input data*, never discovered by PatchWise.

## Deterministic ranking
A ranking method where **the same inputs always produce the same output**, with no randomness and no AI guessing. It uses a fixed, documented formula over defined factors.
**In PatchWise:** the Deterministic Ranking Engine produces the priority score and the ordered queue. This is why results are reproducible and auditable.

## LLM (Large Language Model) and LLM explainer
An LLM is an AI system that generates text (for example Gemini or Groq-hosted models). Its output can vary and can contain mistakes.
**LLM explainer / LLM Explanation Layer:** the PatchWise component that writes a plain-language explanation of **why an item got its already-computed rank**, citing the computed factors.
**In PatchWise:** the LLM **only explains**. It never calculates, changes, or invents a score or priority.

## HITL (Human-in-the-Loop)
A design where a human reviews and can change automated results before they become final.
**In PatchWise:** the analyst reviews the queue, reads explanations, and makes the final decision.

## Override
An analyst's decision that changes the effective priority of an item. PatchWise supports three actions: **Accept** (agree with the computed priority), **Bump** (raise priority), **Defer** (lower priority).
**In PatchWise:** the exact behavior of each action is an open item (OI-4) to be decided as a Proposed Decision. One principle we already plan to follow: an override should be recorded separately and should not erase the original computed score.

## Synthetic data
Artificial data created for testing and demonstration, containing no real organizational information.
**In PatchWise:** used for the asset inventory so the project is safe, shareable, and reproducible.

## Reproducibility
Running the same process on the same data gives the same result every time.
**In PatchWise:** a central success criterion, which we will test in the evaluation phase.

---

## Quick relationship map

```
Vulnerability (CVE) + Asset (criticality, exposure) + KEV + EPSS
        ->  Deterministic Ranking  ->  Priority queue
        ->  LLM explains it (never scores it)
        ->  Analyst overrides (HITL)  ->  Export
```