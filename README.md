# PatchWise

**An AI-Assisted Vulnerability Management and Prioritization System**

Final Year Project, Department of Computer Science, University of Gujrat.
Team: Insha Fakhar, Anza Imtiaz, Rayyan Akram. Supervisor: Dr. Umar Shaoib.

> **Status:** Phase 3 complete (project skeleton). No features implemented yet.

## What PatchWise is
A sandbox-friendly tool that ranks **known** vulnerabilities for patching using a
**synthetic asset inventory** and public signals (CVE, CISA KEV, EPSS).
A deterministic engine computes the ranking. An LLM only **explains** it.
An analyst can Accept, Bump or Defer items, then export a shortlist.

## What PatchWise is NOT
- Not a vulnerability scanner. It discovers nothing.
- Not an LLM-based ranker. The LLM never calculates or invents scores.

## Setup
```bash
python -m venv .venv
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
# Linux / macOS:         source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

## Project layout
See `docs/` for the SRS, glossary, and scope and decision register.

## License
MIT. See `LICENSE`.