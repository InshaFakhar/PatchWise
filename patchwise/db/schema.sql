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

-- CVES: public CVE metadata (FR-02). One row per CVE we track.
-- A missing CVSS score is stored as NULL ("unknown"), never as 0.
CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY
                    CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*'),
    description     TEXT,
    published_date  TEXT
                    CHECK (published_date IS NULL
                           OR published_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    cvss_score      REAL
                    CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    cvss_version    TEXT,
    cvss_vector     TEXT
);

-- KEV: CVEs listed in the CISA Known Exploited Vulnerabilities catalog (FR-02).
-- A row here means "known to be exploited". No row means "not listed".
CREATE TABLE IF NOT EXISTS kev (
    cve_id                TEXT PRIMARY KEY REFERENCES cves (cve_id),
    vendor_project        TEXT,
    product               TEXT,
    date_added            TEXT NOT NULL
                          CHECK (date_added GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    due_date              TEXT
                          CHECK (due_date IS NULL
                                 OR due_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    known_ransomware_use  TEXT
                          CHECK (known_ransomware_use IS NULL
                                 OR known_ransomware_use IN ('Known', 'Unknown'))
);

-- EPSS: exploit-probability score per CVE (FR-02).
-- score_date and model_version record WHICH EPSS publication we used,
-- so a ranking can be traced back to its data (reproducibility).
CREATE TABLE IF NOT EXISTS epss (
    cve_id         TEXT PRIMARY KEY REFERENCES cves (cve_id),
    epss_score     REAL NOT NULL CHECK (epss_score >= 0 AND epss_score <= 1),
    percentile     REAL NOT NULL CHECK (percentile >= 0 AND percentile <= 1),
    score_date     TEXT NOT NULL
                   CHECK (score_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    model_version  TEXT
);