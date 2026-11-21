-- Redstrike 2.2: additive migration. No 2.1 row is rewritten or deleted.
-- Adds the operational mode binding, deep-TLS audit records, expansion
-- requests and evidence-gate decisions. Applied transactionally.

-- ---------------------------------------------------------------------------
-- Mission mode binding. Nullable so every existing 2.1 mission stays valid and
-- is treated as "unclassified (legacy 2.1 plan)" by the API.
-- ---------------------------------------------------------------------------
ALTER TABLE missions ADD COLUMN mode_id TEXT;
ALTER TABLE missions ADD COLUMN mode_ceiling_json TEXT NOT NULL DEFAULT '{}';
CREATE INDEX idx_missions_mode ON missions(mode_id);

-- ---------------------------------------------------------------------------
-- Deep TLS audit records. Immutable payload + digest, mirroring http_evidence.
-- ---------------------------------------------------------------------------
CREATE TABLE tls_audits (
    audit_id      TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    mission_id    TEXT REFERENCES missions(mission_id),
    target        TEXT NOT NULL,
    port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    requested_by  TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    sha256        TEXT NOT NULL CHECK (length(sha256) = 64),
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_tls_audits_engagement ON tls_audits(engagement_id, created_at DESC);
CREATE INDEX idx_tls_audits_mission ON tls_audits(mission_id);
CREATE TRIGGER tls_audit_no_update BEFORE UPDATE ON tls_audits
BEGIN SELECT RAISE(ABORT, 'TLS audit records are immutable'); END;
CREATE TRIGGER tls_audit_no_delete BEFORE DELETE ON tls_audits
BEGIN SELECT RAISE(ABORT, 'TLS audit records are immutable'); END;

-- ---------------------------------------------------------------------------
-- Mid-engagement expansion requests. The decision itself also lives in
-- approval_queue so the existing Two-Person CHECK applies unchanged.
-- ---------------------------------------------------------------------------
CREATE TABLE expansion_requests (
    expansion_id  TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    mission_id    TEXT REFERENCES missions(mission_id),
    kind          TEXT NOT NULL CHECK (kind IN ('targets', 'budget', 'quota', 'privilege')),
    requested_by  TEXT NOT NULL,
    approval_id   TEXT NOT NULL REFERENCES approval_queue(request_id),
    roe_clause    TEXT NOT NULL,
    justification TEXT NOT NULL,
    payload_json  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'withdrawn')),
    applied_json  TEXT NOT NULL DEFAULT '{}',
    decided_by    TEXT,
    decided_at    TEXT,
    note          TEXT NOT NULL DEFAULT '',
    expires_at    TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_expansion_mission ON expansion_requests(mission_id, created_at DESC);
CREATE INDEX idx_expansion_status ON expansion_requests(engagement_id, status);

-- ---------------------------------------------------------------------------
-- Evidence gate decisions. One row per evaluated finding; append-only so a
-- later analyst cannot quietly rewrite how a confirmation was reached.
-- ---------------------------------------------------------------------------
CREATE TABLE evidence_gate_results (
    gate_id       TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    mission_id    TEXT REFERENCES missions(mission_id),
    finding_key   TEXT NOT NULL,
    target        TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('confirmed', 'candidate', 'rejected')),
    payload_json  TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_gate_engagement ON evidence_gate_results(engagement_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Capability mode allow-list toggle (optional). Absent row = manifest decides.
-- Seeded disabled-by-default so widening is always an explicit admin act.
-- ---------------------------------------------------------------------------
INSERT INTO tool_policy (tool_name, enabled, max_timeout, allowed_params_json,
                         risk_level, requires_approval, description)
VALUES ('redgate_capability_mode', 1, 5, '{"modes": null}', 'medium', 0,
        'Administrative toggle for 2.2 operational modes. modes=null means the manifest is authoritative.')
ON CONFLICT(tool_name) DO NOTHING;
