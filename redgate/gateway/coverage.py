"""Coverage ledger and response fingerprinting (2.3.1).

Two failure modes this module exists to prevent:

1. **Unrecorded coverage.** "We tested the login flow" is a memory, not a fact.
   A ``coverage_records`` row names the surface, the checks actually performed and
   the depth. Anything not recorded renders as ``uncovered`` in the summary, so the
   gap is visible in the report instead of being implied away.
2. **Invisible change.** Two runs of the same endpoint returning HTTP 200 with
   different content is the most common way a regression (or a re-deploy) hides.
   Fingerprints store a hash of the body shape, the title and the length bucket,
   and ``diff`` says what changed between the two most recent observations.

Neither module contacts a target. They record what a governed tool run already
observed; the caller supplies the status, headers and body digest.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Iterable

from gateway.db import Database

DEPTHS = ("shallow", "standard", "deep")
STATUSES = ("covered", "partial", "skipped", "out_of_scope")
MAX_CHECKS = 32

_WS_RE = re.compile(r"\s+")
_DIGITS_RE = re.compile(r"\d+")


class CoverageError(ValueError):
    """A coverage or fingerprint record was malformed."""


def _now() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalise_checks(checks: Iterable[Any]) -> list[str]:
    """Deduplicate check names, preserving order, bounded in count and length."""
    out: list[str] = []
    for raw in checks:
        name = _WS_RE.sub(" ", str(raw)).strip()[:64]
        if name and name not in out:
            out.append(name)
    if len(out) > MAX_CHECKS:
        raise CoverageError(f"At most {MAX_CHECKS} checks may be recorded per surface.")
    return out


class CoverageLedger:
    """Upserting record of what was actually tested, per engagement."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        *,
        engagement_id: str,
        surface: str,
        checks: Iterable[Any] | None = None,
        category: str = "",
        depth: str = "standard",
        status: str = "covered",
        skip_reason: str = "",
        mission_id: str | None = None,
        operator_id: str = "",
    ) -> dict[str, Any]:
        name = str(surface or "").strip()
        if not name or len(name) > 253:
            raise CoverageError("A coverage record needs a surface name (1-253 chars).")
        if depth not in DEPTHS:
            raise CoverageError(f"depth must be one of {DEPTHS}.")
        if status not in STATUSES:
            raise CoverageError(f"status must be one of {STATUSES}.")
        clean = normalise_checks(checks or [])
        reason = str(skip_reason or "").strip()[:400]
        if status == "skipped" and not reason:
            raise CoverageError("A skipped surface must state why it was skipped.")
        if status == "covered" and not clean:
            # "Covered" without a single named check is the exact claim this
            # ledger exists to refuse.
            raise CoverageError(
                "A covered surface must name at least one check it performed."
            )
        existing = self.get(engagement_id, name)
        coverage_id = existing["coverage_id"] if existing else f"cov-{uuid.uuid4().hex[:12]}"
        now = _now()
        if existing:
            merged = list(dict.fromkeys(existing["checks"] + clean))
            with self.db.transaction() as conn:
                conn.execute(
                    """UPDATE coverage_records
                          SET checks_json=?, category=?, depth=?, status=?, skip_reason=?,
                              mission_id=COALESCE(?, mission_id), operator_id=?, updated_at=?
                        WHERE coverage_id=?""",
                    (
                        json.dumps(merged), category[:64], depth, status, reason,
                        mission_id, operator_id, now, coverage_id,
                    ),
                )
        else:
            with self.db.transaction() as conn:
                conn.execute(
                    """INSERT INTO coverage_records
                       (coverage_id, engagement_id, mission_id, surface, category,
                        checks_json, depth, status, skip_reason, operator_id,
                        created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        coverage_id, engagement_id, mission_id, name, category[:64],
                        json.dumps(clean), depth, status, reason, operator_id, now, now,
                    ),
                )
        return self.get(engagement_id, name) or {}

    def get(self, engagement_id: str, surface: str) -> dict[str, Any] | None:
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM coverage_records WHERE engagement_id=? AND surface=?",
                (engagement_id, surface),
            ).fetchone()
        if row is None:
            return None
        record = dict(row)
        record["checks"] = json.loads(record.pop("checks_json") or "[]")
        return record

    def list(self, engagement_id: str) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM coverage_records WHERE engagement_id=? ORDER BY surface",
                (engagement_id,),
            ).fetchall()
        out = []
        for row in rows:
            record = dict(row)
            record["checks"] = json.loads(record.pop("checks_json") or "[]")
            out.append(record)
        return out

    def summary(self, engagement_id: str, expected: Iterable[str] | None = None) -> dict[str, Any]:
        """Coverage percentages, with named gaps rather than a single number.

        ``expected`` is the surface list the engagement declared it would cover
        (for example the discovered asset inventory). Surfaces in ``expected``
        with no record are listed as ``uncovered`` — silence is never coverage.
        """
        rows = self.list(engagement_id)
        counts: dict[str, int] = {s: 0 for s in STATUSES}
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        known = {row["surface"] for row in rows}
        expected_set = {str(s).strip() for s in (expected or []) if str(s).strip()}
        uncovered = sorted(expected_set - known)
        considered = len(expected_set | known)
        covered = counts.get("covered", 0)
        return {
            "engagement_id": engagement_id,
            "counts": counts,
            "recorded": len(rows),
            "considered": considered,
            "coverage_ratio": round(covered / considered, 3) if considered else 0.0,
            "uncovered": uncovered,
            "shallow_only": [r["surface"] for r in rows if r["depth"] == "shallow"],
            "surfaces": [
                {"surface": r["surface"], "status": r["status"], "depth": r["depth"],
                 "checks": r["checks"], "skip_reason": r["skip_reason"]}
                for r in rows
            ],
            "note": (
                "A surface with no record counts as uncovered. 'partial' and 'skipped' "
                "are recorded states, not failures of the ledger."
            ),
        }

    def drop(self, engagement_id: str, surface: str) -> bool:
        """Remove a record (used when a surface turns out never to have existed)."""
        with self.db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM coverage_records WHERE engagement_id=? AND surface=?",
                (engagement_id, surface),
            )
            return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Response fingerprints
# ---------------------------------------------------------------------------
def shape_of(body: str | bytes) -> dict[str, str]:
    """Reduce a response body to the parts worth comparing.

    Only a *shape* is kept: every run of digits collapses to ``N`` and every
    whitespace run to one space. Two responses that differ only by a timestamp or
    a counter therefore share a fingerprint, while a changed sentence does not.
    """
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    collapsed = _WS_RE.sub(" ", _DIGITS_RE.sub("N", text)).strip()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = _WS_RE.sub(" ", title_match.group(1)).strip() if title_match else ""
    return {
        "body_sha256": hashlib.sha256(collapsed.encode("utf-8")).hexdigest(),
        "title_sha256": hashlib.sha256(title.encode("utf-8")).hexdigest(),
        "title": title[:200],
        "length_bucket": _bucket(len(collapsed)),
    }


def _bucket(length: int) -> str:
    for edge in (128, 512, 2048, 8192, 32768):
        if length < edge:
            return f"<{edge}"
    return ">=32768"


def _stable_headers(headers: dict[str, Any]) -> dict[str, str]:
    """Keep the headers that describe behaviour, not the ones that describe time."""
    volatile = {"date", "set-cookie", "expires", "last-modified", "etag", "age", "x-request-id",
                "x-runtime", "server-timing", "cf-ray", "x-cache", "via"}
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key).strip().lower()
        if not name or name in volatile:
            continue
        out[name] = _WS_RE.sub(" ", str(value)).strip()[:200]
    return dict(sorted(out.items()))


class ResponseTracker:
    """Stores a comparable fingerprint per observation and diffs the last two."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def observe(
        self,
        *,
        engagement_id: str,
        asset: str,
        status_code: int = 0,
        body: str | bytes = "",
        headers: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        name = str(asset or "").strip()
        if not name or len(name) > 253:
            raise CoverageError("An observation needs an asset name (1-253 chars).")
        if not 0 <= int(status_code) <= 599:
            raise CoverageError("status_code must be between 0 and 599.")
        shape = shape_of(body)
        fingerprint_id = f"fp-{uuid.uuid4().hex[:12]}"
        payload = {
            "fingerprint_id": fingerprint_id,
            "engagement_id": engagement_id,
            "asset": name,
            "status_code": int(status_code),
            "body_sha256": shape["body_sha256"],
            "title_sha256": shape["title_sha256"],
            "length_bucket": shape["length_bucket"],
            "headers_json": json.dumps(_stable_headers(headers or {})),
            "observed_at": _now(),
        }
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO response_fingerprints
                   (fingerprint_id, engagement_id, asset, status_code, body_sha256,
                    title_sha256, length_bucket, headers_json, observed_at)
                   VALUES (:fingerprint_id, :engagement_id, :asset, :status_code,
                           :body_sha256, :title_sha256, :length_bucket, :headers_json,
                           :observed_at)""",
                payload,
            )
        return {**payload, "title": shape["title"]}

    def diff(self, engagement_id: str, asset: str) -> dict[str, Any]:
        """Compare the two most recent observations of one asset."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT * FROM response_fingerprints
                   WHERE engagement_id=? AND asset=?
                   ORDER BY observed_at DESC, rowid DESC LIMIT 2""",
                (engagement_id, asset),
            ).fetchall()
        if len(rows) < 2:
            return {
                "asset": asset,
                "changed": False,
                "reason": "fewer than two observations; nothing to compare yet",
                "observations": len(rows),
            }
        latest, previous = dict(rows[0]), dict(rows[1])
        fields = ("status_code", "body_sha256", "title_sha256", "length_bucket")
        changes = {f: {"from": previous[f], "to": latest[f]} for f in fields
                   if previous[f] != latest[f]}
        prev_headers = json.loads(previous["headers_json"] or "{}")
        new_headers = json.loads(latest["headers_json"] or "{}")
        header_changes = {
            key: {"from": prev_headers.get(key), "to": new_headers.get(key)}
            for key in sorted(set(prev_headers) | set(new_headers))
            if prev_headers.get(key) != new_headers.get(key)
        }
        return {
            "asset": asset,
            "changed": bool(changes or header_changes),
            "field_changes": changes,
            "header_changes": header_changes,
            "latest": latest["observed_at"],
            "previous": previous["observed_at"],
            "interpretation": (
                "status/body shape changed — re-verify any finding that depended on the "
                "previous observation"
                if changes else "only headers changed — check security-header regressions"
                if header_changes else "no material change between the two observations"
            ),
        }

    def history(self, engagement_id: str, asset: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT * FROM response_fingerprints
                   WHERE engagement_id=? AND asset=?
                   ORDER BY observed_at DESC LIMIT ?""",
                (engagement_id, asset, limit),
            ).fetchall()
        return [dict(r) for r in rows]
