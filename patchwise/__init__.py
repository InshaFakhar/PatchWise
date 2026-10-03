"""PatchWise: AI-Assisted Vulnerability Management and Prioritization System.

Architectural rule (Proposal Section 8): ranking and explanation are strictly
separate. The Deterministic Ranking Engine (patchwise.ranking) computes the
priority. The LLM Explanation Layer (patchwise.explain) only describes it.
"""

__version__ = "0.1.0"