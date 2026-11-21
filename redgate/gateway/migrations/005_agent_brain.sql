-- =============================================================================
-- Redstrike 2.3 — Agent hunt loops and persistent brain
--
-- A "hunt loop" is a bounded hypothesis-test cycle owned by an advisory role.
-- The 7-Question Gate (also in this file's schema) is what a loop must pass
-- before its hypothesis is allowed to become a *candidate* finding.
--
-- The brain is persistent across sessions on purpose: an operator returning to
-- an engagement must be able to read what was already tried and killed, instead
-- of re-running the same dead ends and burning budget.
-- =============================================================================

CREATE TABLE IF NOT EXISTS hunt_loops (
    loop_id        TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    role_id        TEXT NOT NULL,
    hypothesis     TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open' CHECK (status IN (
                       'open', 'testing', 'advanced', 'killed', 'escalated', 'blocked')),
    iteration      INTEGER NOT NULL DEFAULT 0 CHECK (iteration >= 0),
    max_iterations INTEGER NOT NULL DEFAULT 8 CHECK (max_iterations BETWEEN 1 AND 64),
    kill_reason    TEXT NOT NULL DEFAULT '',
    requested_by   TEXT NOT NULL,
    payload_json   TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loop_engagement ON hunt_loops(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_loop_status ON hunt_loops(engagement_id, status);

-- Append-only brain. Nothing in the brain is ever updated: a corrected belief is
-- a new entry that supersedes the old one, so the reasoning trail survives.
CREATE TABLE IF NOT EXISTS brain_entries (
    entry_id       TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL REFERENCES engagements(id),
    mission_id     TEXT REFERENCES missions(mission_id),
    loop_id        TEXT REFERENCES hunt_loops(loop_id),
    role_id        TEXT NOT NULL DEFAULT '',
    kind           TEXT NOT NULL CHECK (kind IN (
                       'hypothesis', 'question', 'evidence', 'verdict', 'lesson', 'note')),
    question_id    TEXT NOT NULL DEFAULT '',
    content        TEXT NOT NULL,
    verdict        TEXT NOT NULL DEFAULT '',
    evidence_ref   TEXT NOT NULL DEFAULT '',
    author         TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_brain_engagement ON brain_entries(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_brain_loop ON brain_entries(loop_id, created_at);

CREATE TRIGGER IF NOT EXISTS brain_no_update BEFORE UPDATE ON brain_entries
BEGIN SELECT RAISE(ABORT, 'The agent brain is append-only; supersede instead of editing'); END;

CREATE TRIGGER IF NOT EXISTS brain_no_delete BEFORE DELETE ON brain_entries
BEGIN SELECT RAISE(ABORT, 'The agent brain is append-only; entries cannot be deleted'); END;
