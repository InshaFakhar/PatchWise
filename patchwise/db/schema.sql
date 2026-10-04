-- PatchWise database schema (PD-07).
-- Tables are added one milestone at a time. Safe to run more than once.

-- ASSETS: the synthetic asset inventory (FR-01).
-- The allowed values for criticality / exposure / environment are a
-- Proposed Decision (PD): the brief only says "criticality and exposure tags".
CREATE TABLE IF NOT EXISTS assets (
    asset_id     TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL,
    asset_type   TEXT NOT NULL,
    criticality  TEXT NOT NULL
                 CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    exposure     TEXT NOT NULL
                 CHECK (exposure IN ('Internal', 'DMZ', 'Internet-facing')),
    environment  TEXT NOT NULL
                 CHECK (environment IN ('prod', 'staging', 'dev'))
);