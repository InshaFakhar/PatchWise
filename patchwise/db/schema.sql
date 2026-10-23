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
-- COMPONENTS: software found in an asset's SBOM (FR-03).
-- version may be NULL: matching will later label such rows "insufficient data".
CREATE TABLE IF NOT EXISTS components (
    component_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      TEXT NOT NULL REFERENCES assets (asset_id),
    name          TEXT NOT NULL,
    version       TEXT,
    vendor        TEXT,
    purl          TEXT,
    cpe           TEXT,
    UNIQUE (asset_id, name, version)
);

-- DATA_FETCH_LOG: one row per load of a public data source (FR-02).
-- Records WHAT was loaded, FROM where, WHEN, and how it went.
CREATE TABLE IF NOT EXISTS data_fetch_log (
    log_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    source            TEXT NOT NULL CHECK (source IN ('NVD', 'KEV', 'EPSS')),
    origin            TEXT NOT NULL,
    mode              TEXT NOT NULL CHECK (mode IN ('snapshot', 'live')),
    fetched_at        TEXT NOT NULL,
    records_read      INTEGER NOT NULL,
    records_loaded    INTEGER NOT NULL,
    records_rejected  INTEGER NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'failed')),
    note              TEXT
);

-- CVE_AFFECTED_PRODUCTS: which software/version ranges each CVE affects (FR-02).
-- Source: the NVD "configurations" -> "cpeMatch" entries marked vulnerable.
-- No version columns filled = the CVE applies to ALL versions of that product.
CREATE TABLE IF NOT EXISTS cve_affected_products (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                   TEXT NOT NULL REFERENCES cves (cve_id),
    cpe_part                 TEXT NOT NULL CHECK (cpe_part IN ('a', 'o', 'h')),
    vendor                   TEXT NOT NULL,
    product                  TEXT NOT NULL,
    version_exact            TEXT,
    version_start_including  TEXT,
    version_start_excluding  TEXT,
    version_end_including    TEXT,
    version_end_excluding    TEXT,
    cpe_criteria             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_affected_product ON cve_affected_products (product);
CREATE INDEX IF NOT EXISTS idx_affected_cve ON cve_affected_products (cve_id);