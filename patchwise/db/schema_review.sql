
-- DECISIONS: the analyst's Accept / Bump / Defer decisions (FR-07).
-- APPEND-ONLY audit history: rows are never edited or deleted (the triggers below enforce it).
-- The current decision of a finding is its newest row. Findings are identified by
-- (component_id, cve_id) because the matches table is rebuilt every time matching runs.
CREATE TABLE IF NOT EXISTS decisions (
    decision_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id       INTEGER NOT NULL REFERENCES components (component_id),
    cve_id             TEXT NOT NULL REFERENCES cves (cve_id),
    action             TEXT NOT NULL CHECK (action IN ('accept', 'bump', 'defer')),
    reason             TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    analyst_name       TEXT NOT NULL CHECK (length(trim(analyst_name)) > 0),
    decided_at         TEXT NOT NULL,
    rank_at_decision   INTEGER,
    score_at_decision  REAL
);
CREATE INDEX IF NOT EXISTS idx_decisions_finding ON decisions (component_id, cve_id);
CREATE TRIGGER IF NOT EXISTS decisions_no_update BEFORE UPDATE ON decisions
BEGIN
    SELECT RAISE(ABORT, 'decisions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS decisions_no_delete BEFORE DELETE ON decisions
BEGIN
    SELECT RAISE(ABORT, 'decisions are append-only');
END;
