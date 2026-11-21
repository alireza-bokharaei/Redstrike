-- Redstrike 2.3: offensive surface, declarative policies, bug-bounty sync,
-- attack chains and pwntools job records. Additive only: no 2.1/2.2 row is
-- rewritten or deleted, and every immersive table below is append-only unless it
-- is an explicitly mutable policy/workflow record.

-- ---------------------------------------------------------------------------
-- Declarative policy store. Seeded from config/policies.yaml and editable at
-- runtime by an admin. `declaration_json` holds the bounds: who may use the
-- policy, in which modes, under which consent levels, and with what caps.
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    policy_id          TEXT PRIMARY KEY,
    policy_type        TEXT NOT NULL CHECK (policy_type IN (
                           'posture', 'tool', 'exploitation', 'credential',
                           'mass_scan', 'pwntools', 'scope_expansion')),
    name               TEXT NOT NULL,
    enabled            INTEGER NOT NULL DEFAULT 1,
    consent_required   TEXT NOT NULL DEFAULT 'none' CHECK (consent_required IN (
                           'none', 'requester', 'operator', 'approver', 'admin')),
    risk_level         TEXT NOT NULL DEFAULT 'medium' CHECK (risk_level IN (
                           'low', 'medium', 'high', 'critical')),
    two_person         INTEGER NOT NULL DEFAULT 0,
    declaration_json   TEXT NOT NULL DEFAULT '{}',
    updated_by         TEXT NOT NULL DEFAULT 'config-seed',
    updated_at         TEXT NOT NULL
);
CREATE INDEX idx_policies_type ON policies(policy_type, enabled);

-- Engagement posture binding. Separate table (not a column on engagements) so
-- existing 2.1/2.2 rows and the config seeder are untouched.
CREATE TABLE engagement_postures (
    engagement_id TEXT PRIMARY KEY REFERENCES engagements(id),
    posture_id    TEXT NOT NULL,
    updated_by    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Consent records. One row per explicit human acknowledgement. The hash covers
-- the exact declaration text shown at the time, so a later edit to the policy
-- cannot retroactively "cover" an earlier consent.
-- ---------------------------------------------------------------------------
CREATE TABLE consent_records (
    consent_id     TEXT PRIMARY KEY,
    engagement_id  TEXT REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    operator_id    TEXT NOT NULL,
    level          TEXT NOT NULL CHECK (level IN ('operator', 'approver', 'admin')),
    policy_id      TEXT REFERENCES policies(policy_id),
    declaration_sha256 TEXT NOT NULL CHECK (length(declaration_sha256) = 64),
    statement      TEXT NOT NULL,
    granted_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    revoked_at     TEXT
);
CREATE INDEX idx_consent_operator ON consent_records(operator_id, level);
CREATE INDEX idx_consent_mission ON consent_records(mission_id);
CREATE TRIGGER consent_no_delete BEFORE DELETE ON consent_records
BEGIN SELECT RAISE(ABORT, 'Consent records are append-only'); END;

-- ---------------------------------------------------------------------------
-- Exploitation evidence: a reproducible proof of concept and its verification.
-- ---------------------------------------------------------------------------
CREATE TABLE exploitation_evidence (
    exploit_id     TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    target         TEXT NOT NULL,
    vulnerability  TEXT NOT NULL,
    severity       TEXT NOT NULL,
    requested_by   TEXT NOT NULL,
    approved_by    TEXT,
    approval_id    TEXT REFERENCES approval_queue(request_id),
    language       TEXT NOT NULL,
    poc_body       TEXT NOT NULL,
    poc_sha256     TEXT NOT NULL CHECK (length(poc_sha256) = 64),
    reproduction_steps_json TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'drafted' CHECK (status IN (
                      'drafted', 'validated', 'executed', 'verified',
                      'unverified', 'failed', 'rejected')),
    output_sha256  TEXT,
    result_json    TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    verified_at    TEXT
);
CREATE INDEX idx_exploit_engagement ON exploitation_evidence(engagement_id, created_at DESC);
CREATE INDEX idx_exploit_mission ON exploitation_evidence(mission_id);
CREATE INDEX idx_exploit_status ON exploitation_evidence(status);
CREATE TRIGGER exploit_no_update_poc BEFORE UPDATE ON exploitation_evidence
WHEN OLD.poc_sha256 != NEW.poc_sha256
BEGIN SELECT RAISE(ABORT, 'A stored PoC body is immutable; create a new record'); END;

-- ---------------------------------------------------------------------------
-- Attack chains: ordered references to confirmed findings, with the weakest
-- link named. Chain state never upgrades a finding's own verification.
-- ---------------------------------------------------------------------------
CREATE TABLE attack_chains (
    chain_id       TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    requested_by   TEXT NOT NULL,
    rationale      TEXT NOT NULL,
    weakest_link   TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN (
                      'proposed', 'validated', 'partially_validated', 'rejected')),
    payload_json   TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL
);
CREATE INDEX idx_chain_engagement ON attack_chains(engagement_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Bug bounty program synchronisation. `source` records where the scope came
-- from; a locally-typed scope is `manual` and never claims to be synced.
-- ---------------------------------------------------------------------------
CREATE TABLE bounty_programs (
    program_id       TEXT PRIMARY KEY,
    engagement_id    TEXT NOT NULL REFERENCES engagements(id),
    platform         TEXT NOT NULL CHECK (platform IN (
                         'hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'manual')),
    handle           TEXT NOT NULL,
    display_name     TEXT NOT NULL DEFAULT '',
    scope_json       TEXT NOT NULL DEFAULT '[]',
    source           TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'synced', 'cached')),
    last_synced_at   TEXT,
    sync_error       TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    UNIQUE (engagement_id, platform, handle)
);
CREATE TRIGGER bounty_scope_no_update BEFORE UPDATE ON bounty_programs
WHEN OLD.scope_json != NEW.scope_json AND OLD.source = 'synced'
BEGIN SELECT RAISE(ABORT, 'A synced scope must be re-synced, not hand-edited'); END;

CREATE TABLE bounty_duplicate_checks (
    check_id       TEXT PRIMARY KEY,
    program_id     TEXT NOT NULL REFERENCES bounty_programs(program_id),
    finding_key    TEXT NOT NULL,
    endpoint       TEXT NOT NULL DEFAULT '',
    outcome        TEXT NOT NULL CHECK (outcome IN (
                      'no_match', 'possible_duplicate', 'likely_duplicate', 'unverified')),
    confidence     REAL NOT NULL DEFAULT 0.0 CHECK (confidence BETWEEN 0 AND 1),
    evidence_json  TEXT NOT NULL DEFAULT '{}',
    checked_by     TEXT NOT NULL,
    checked_at     TEXT NOT NULL
);
CREATE INDEX idx_dupcheck_program ON bounty_duplicate_checks(program_id, checked_at DESC);
CREATE TRIGGER dupcheck_no_update BEFORE UPDATE ON bounty_duplicate_checks
BEGIN SELECT RAISE(ABORT, 'Duplicate checks are append-only'); END;

CREATE TABLE bounty_reports (
    report_id      TEXT PRIMARY KEY,
    program_id     TEXT REFERENCES bounty_programs(program_id),
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    finding_key    TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    body_markdown  TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'draft' CHECK (status IN (
                      'draft', 'ready', 'submitted', 'closed')),
    duplicate_check_id TEXT REFERENCES bounty_duplicate_checks(check_id),
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX idx_report_engagement ON bounty_reports(engagement_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- pwntools job records. The PoC/script body is stored exactly as executed and
-- pinned by digest, matching the existing validated-scripts contract.
-- ---------------------------------------------------------------------------
CREATE TABLE pwntools_jobs (
    job_id         TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    requested_by   TEXT NOT NULL,
    target         TEXT NOT NULL,
    action         TEXT NOT NULL CHECK (action IN (
                      'elf_analyze', 'checksec', 'rop_search', 'asm', 'disasm',
                      'cyclic', 'shellcode', 'run_script')),
    script_body    TEXT NOT NULL DEFAULT '',
    script_sha256  TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                      'pending', 'running', 'completed', 'failed', 'refused', 'unavailable')),
    output         TEXT NOT NULL DEFAULT '',
    output_sha256  TEXT NOT NULL DEFAULT '',
    pwntools_version TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    finished_at    TEXT
);
CREATE INDEX idx_pwntools_engagement ON pwntools_jobs(engagement_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Mass-scan authorisations. A row exists only after an approved expansion that
-- explicitly granted a scan budget, which is what makes "outside budget" a
-- checkable condition rather than a promise.
-- ---------------------------------------------------------------------------
CREATE TABLE scan_authorizations (
    authorization_id TEXT PRIMARY KEY,
    engagement_id    TEXT NOT NULL REFERENCES engagements(id),
    mission_id       TEXT REFERENCES missions(mission_id),
    approval_id      TEXT NOT NULL REFERENCES approval_queue(request_id),
    granted_by       TEXT NOT NULL,
    granted_to       TEXT NOT NULL,
    max_hosts        INTEGER NOT NULL CHECK (max_hosts BETWEEN 1 AND 4096),
    max_requests     INTEGER NOT NULL CHECK (max_requests BETWEEN 1 AND 1000000),
    requests_used    INTEGER NOT NULL DEFAULT 0 CHECK (requests_used >= 0),
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
CREATE INDEX idx_scan_auth_engagement ON scan_authorizations(engagement_id, expires_at);
