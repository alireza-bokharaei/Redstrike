-- =============================================================================
-- Redstrike 2.3.1 — intel outcomes, coverage ledger and response fingerprints
--
-- Three tables, three jobs:
--   intel_outcomes      append-only record of what was tried and what happened.
--                       This is the ONLY state the intel engine learns from: a
--                       ranking is otherwise a pure function of its inputs.
--   coverage_records    one row per (engagement, surface) actually tested, with
--                       the checks performed. "Covered" means recorded, never
--                       "we looked at the page once".
--   response_fingerprints  a stable hash per (asset, status, body shape) so a
--                       change is visible between two runs instead of hidden
--                       behind an unchanged HTTP 200.
-- =============================================================================

CREATE TABLE IF NOT EXISTS intel_outcomes (
    outcome_id     TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    vuln_class     TEXT NOT NULL,
    result         TEXT NOT NULL CHECK (result IN (
                       'confirmed', 'rejected', 'inconclusive', 'blocked')),
    evidence_id    TEXT,
    note           TEXT NOT NULL DEFAULT '',
    operator_id    TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intel_outcome_engagement
    ON intel_outcomes(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intel_outcome_class
    ON intel_outcomes(engagement_id, vuln_class, result);

-- Coverage is a record of work performed against a named surface. A partial
-- record is honest; an empty record is not coverage.
CREATE TABLE IF NOT EXISTS coverage_records (
    coverage_id    TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    surface        TEXT NOT NULL,
    category       TEXT NOT NULL DEFAULT '',
    checks_json    TEXT NOT NULL DEFAULT '[]',
    depth          TEXT NOT NULL DEFAULT 'shallow' CHECK (depth IN (
                       'shallow', 'standard', 'deep')),
    status         TEXT NOT NULL DEFAULT 'covered' CHECK (status IN (
                       'covered', 'partial', 'skipped', 'out_of_scope')),
    skip_reason    TEXT NOT NULL DEFAULT '',
    operator_id    TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (engagement_id, surface)
);
CREATE INDEX IF NOT EXISTS idx_coverage_engagement
    ON coverage_records(engagement_id, status);

CREATE TABLE IF NOT EXISTS response_fingerprints (
    fingerprint_id TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    asset          TEXT NOT NULL,
    status_code    INTEGER NOT NULL DEFAULT 0,
    body_sha256    TEXT NOT NULL DEFAULT '',
    title_sha256   TEXT NOT NULL DEFAULT '',
    length_bucket  TEXT NOT NULL DEFAULT '',
    headers_json   TEXT NOT NULL DEFAULT '{}',
    observed_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fingerprint_asset
    ON response_fingerprints(engagement_id, asset, observed_at DESC);
