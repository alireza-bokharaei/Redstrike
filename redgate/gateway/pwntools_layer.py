"""pwntools binary layer for CTF / binary missions (2.3).

Enabled by default for ``ctf`` and ``full_pentest`` missions against binary
artifacts, exactly as the prompt asks. Every call runs in a child process with a
scrubbed environment, a private temporary working directory, and no inherited
file descriptors, and every result is recorded in ``pwntools_jobs`` with the
script body pinned by SHA-256.

**Honest status.** ``pwn`` is imported inside the child, never in the Gateway
process. If the interpreter there cannot import pwntools, the job is recorded
with ``status='unavailable'`` and a message naming the missing module. Nothing
is emulated: there is no fake checksec, no synthesised ROP chain. The read-only
ELF facts the Gateway can compute itself live in ``binary_triage`` and are
reported separately so a consumer can tell which layer produced what.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.auth import OperatorPrincipal
from gateway.db import Database
from gateway.exploitation import scan_for_destructive
from gateway.offensive_policy import OffensivePolicyEngine
from gateway.policy import ScopePolicyEngine

ACTIONS = (
    "elf_analyze",
    "checksec",
    "rop_search",
    "asm",
    "disasm",
    "cyclic",
    "shellcode",
    "run_script",
)
MAX_SCRIPT_BYTES = 64_000
MAX_OUTPUT_BYTES = 512_000
DEFAULT_TIMEOUT = 60
#: Only these actions are read-only analysis; the rest execute code.
READ_ONLY_ACTIONS = {"checksec", "elf_analyze", "rop_search", "disasm"}

_DRIVER = r'''
import json, sys
try:
    import pwn
    from pwn import ELF, ROP, asm, disasm, cyclic, shellcraft, context
except Exception as exc:  # noqa: BLE001
    print(json.dumps({"ok": False, "unavailable": True,
                      "error": f"{type(exc).__name__}: {exc}"}))
    raise SystemExit(3)

request = json.loads(sys.stdin.read())
action = request["action"]
try:
    if action in ("checksec", "elf_analyze"):
        e = ELF(request["path"], checksec=True)
        data = {
            "path": request["path"],
            "arch": e.arch, "bits": e.bits, "endian": e.endian,
            "pie": bool(e.pie), "nx": bool(e.nx), "canary": bool(e.canary),
            "relro": e.relro or "none", "type": e.elftype and str(e.elftype) or "",
            "entry": hex(e.entry) if e.entry is not None else "",
            "symbols": sorted(e.symbols)[:200],
            "got": sorted(e.got)[:200],
            "plt": sorted(e.plt)[:200],
        }
        if action == "elf_analyze":
            data["checksec_text"] = str(e.checksec())
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__, "result": data}))
    elif action == "rop_search":
        e = ELF(request["path"], checksec=False)
        rop = ROP(e)
        gadgets = {str(k): hex(v) for k, v in list(rop.gadgets.items())[:120]}
        try:
            found = rop.find_gadget(request.get("registers") or ["pop rdi", "ret"])
            found = [hex(x) for x in (found or [])]
        except Exception:  # noqa: BLE001
            found = []
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__,
                          "result": {"gadgets": gadgets, "found": found}}))
    elif action == "asm":
        context.clear(arch=request.get("arch") or "amd64")
        out = asm(request["source"])
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__,
                          "result": {"hex": out.hex(), "length": len(out)}}))
    elif action == "disasm":
        raw = bytes.fromhex(request["hex_bytes"])
        context.clear(arch=request.get("arch") or "amd64")
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__,
                          "result": {"text": disasm(raw)}}))
    elif action == "cyclic":
        pattern = cyclic(request.get("length") or 64)
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__,
                          "result": {"pattern": pattern.decode() if isinstance(pattern, bytes) else pattern}}))
    elif action == "shellcode":
        arch = request.get("arch") or "amd64"
        context.clear(arch=arch)
        sc = getattr(shellcraft, arch.replace("amd64", "amd64"), shellcraft).sh()
        raw = asm(sc)
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__,
                          "result": {"source": sc, "hex": raw.hex(), "length": len(raw)}}))
    elif action == "run_script":
        g = {"__name__": "__pwn_job__", "pwn": pwn, "json": json}
        try:
            from pwn import *  # noqa: F401,F403
            g.update({k: v for k, v in vars(pwn).items() if not k.startswith("__")})
        except Exception:  # noqa: BLE001
            pass
        exec(compile(request["script"], "<pwn_job>", "exec"), g)  # noqa: S102
        print(json.dumps({"ok": True, "pwn_version": pwn.__version__, "result": {"executed": True}}))
    else:
        print(json.dumps({"ok": False, "error": "unsupported action"}))
        raise SystemExit(2)
except SystemExit:
    raise
except Exception as exc:  # noqa: BLE001
    print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
    raise SystemExit(4)
'''


class PwntoolsError(ValueError):
    """The pwntools request is malformed or not permitted."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utcnow() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class PwntoolsAvailability:
    available: bool
    version: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def probe(timeout: int = 20) -> PwntoolsAvailability:
    """Is ``pwn`` importable in the child interpreter this layer would use?"""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-c", "import pwn; print(pwn.__version__)"],
            capture_output=True,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
                 "PYTHONPATH": "", "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return PwntoolsAvailability(False, "", f"Could not start the interpreter: {exc}")
    if proc.returncode == 0:
        return PwntoolsAvailability(True, proc.stdout.decode().strip(), "pwntools is importable.")
    err = (proc.stderr or b"").decode(errors="replace").strip().splitlines()
    tail = err[-1] if err else f"exit {proc.returncode}"
    return PwntoolsAvailability(
        False,
        "",
        f"pwntools is not installed in this runtime ({tail}). Install it to enable this layer.",
    )


class PwntoolsLayer:
    """Governed pwntools execution."""

    def __init__(
        self,
        *,
        db: Database,
        scope: ScopePolicyEngine,
        policies: OffensivePolicyEngine,
        artifact_root: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.db = db
        self.scope = scope
        self.policies = policies
        self.artifact_root = Path(artifact_root or os.environ.get("REDGATE_ARTIFACT_ROOT", ".")).resolve()
        self.timeout = max(5, min(int(timeout), 600))
        self._probe: PwntoolsAvailability | None = None

    # ------------------------------------------------------------------
    def availability(self, *, refresh: bool = False) -> dict[str, Any]:
        if refresh or self._probe is None:
            self._probe = probe()
        return self._probe.to_dict()

    def run(
        self,
        *,
        principal: OperatorPrincipal,
        engagement_id: str,
        action: str,
        target: str = "",
        artifact_path: str | None = None,
        source: str = "",
        hex_bytes: str = "",
        length: int = 64,
        arch: str = "amd64",
        registers: list[str] | None = None,
        script: str = "",
        mission_id: str | None = None,
    ) -> dict[str, Any]:
        if action not in ACTIONS:
            raise PwntoolsError(f"Unknown pwntools action '{action}'.")
        if not principal.can_access_engagement(engagement_id):
            raise PermissionError("The operator is not assigned to this engagement.")

        path = self._resolve_artifact(artifact_path) if artifact_path else None
        if action in {"checksec", "elf_analyze", "rop_search"} and not path:
            raise PwntoolsError(f"'{action}' needs an artifact inside the configured root.")
        if action == "asm" and not source.strip():
            raise PwntoolsError("'asm' needs assembly source.")
        if action == "disasm":
            try:
                bytes.fromhex(hex_bytes)
            except ValueError as exc:
                raise PwntoolsError("'disasm' needs valid hex bytes.") from exc
        if action == "run_script":
            body = script.strip()
            if not body:
                raise PwntoolsError("'run_script' needs a script body.")
            if len(body.encode()) > MAX_SCRIPT_BYTES:
                raise PwntoolsError(f"Script exceeds {MAX_SCRIPT_BYTES} bytes.")
            destructive = scan_for_destructive(body)
            if destructive:
                raise PwntoolsError("Refusing a destructive script: " + "; ".join(destructive))
        else:
            body = ""

        # Scope: a binary target must be in scope when a target host is given.
        if target:
            decision = self.scope.evaluate_target(engagement_id, target)
            if not decision.allowed:
                raise PwntoolsError(decision.reason or "Target is out of scope.")

        # Posture: script execution is not read-only, so it needs consent.
        policy_id = "tool:pwntools" if action == "run_script" else "tool:pwntools_readonly"
        decision = self.policies.evaluate_action(
            principal=principal,
            engagement_id=engagement_id,
            action=f"pwntools:{action}",
            policy_id=policy_id if self.policies.get(policy_id) else None,
        )
        if not decision.allowed:
            raise PwntoolsError(decision.reason)

        job_id = f"pwn-{uuid.uuid4().hex[:12]}"
        created = _utcnow()
        script_digest = _sha256(body) if body else ""
        self._insert_job(
            job_id=job_id,
            engagement_id=engagement_id,
            mission_id=mission_id,
            principal=principal,
            target=target or (str(path) if path else ""),
            action=action,
            body=body,
            digest=script_digest,
            created=created,
        )

        avail = self.availability()
        if not avail["available"]:
            message = avail["detail"]
            self._finish_job(job_id, "unavailable", message, "")
            self._audit(principal, engagement_id, target, job_id, action, "unavailable", message)
            return {
                "job_id": job_id,
                "action": action,
                "status": "unavailable",
                "detail": message,
                "layer": "pwntools",
                "hint": (
                    "binary_triage still reports ELF hardening facts computed by the Gateway "
                    "itself; use it if you only need checksec-style answers."
                ),
                "script_sha256": script_digest,
            }

        payload = {
            "action": action,
            "path": str(path) if path else "",
            "source": source,
            "hex_bytes": hex_bytes,
            "length": int(max(1, min(length, 65536))),
            "arch": arch,
            "registers": registers or [],
            "script": body,
        }
        status, output, error = self._execute(payload)
        if error:
            output = (output + "\n" + error).strip()
        output = output[:MAX_OUTPUT_BYTES]
        self._finish_job(job_id, status, output, _sha256(output) if output else "", avail["version"])
        self._audit(principal, engagement_id, target, job_id, action, status, output[:400])
        return {
            "job_id": job_id,
            "action": action,
            "status": status,
            "pwntools_version": avail["version"],
            "output": output,
            "output_sha256": _sha256(output) if output else "",
            "script_sha256": script_digest,
            "layer": "pwntools",
        }

    # ------------------------------------------------------------------
    def list_jobs(self, engagement_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.db.connection() as conn:
            rows = conn.execute(
                """SELECT job_id, mission_id, target, action, status, pwntools_version,
                          script_sha256, output_sha256, created_at, finished_at
                     FROM pwntools_jobs WHERE engagement_id=?
                    ORDER BY created_at DESC LIMIT ?""",
                (engagement_id, max(1, min(limit, 200))),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_job(self, job_id: str) -> dict[str, Any]:
        with self.db.connection() as conn:
            row = conn.execute("SELECT * FROM pwntools_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            raise PwntoolsError("Unknown pwntools job.")
        return dict(row)

    # ------------------------------------------------------------------
    def _resolve_artifact(self, raw: str | None) -> Path:
        if not raw:
            raise PwntoolsError("An artifact path is required.")
        candidate = Path(raw)
        resolved = (candidate if candidate.is_absolute() else self.artifact_root / candidate).resolve()
        root = self.artifact_root.resolve()
        if root != resolved and root not in resolved.parents:
            raise PwntoolsError("Artifact path escapes the configured root.")
        if not resolved.is_file():
            raise PwntoolsError(f"No such artifact: {resolved.name}")
        return resolved

    def _execute(self, payload: dict[str, Any]) -> tuple[str, str, str]:
        workdir = Path(tempfile.mkdtemp(prefix="pwn-job-"))
        try:
            argv = [sys.executable, "-I", "-c", _DRIVER]
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                input=json.dumps(payload).encode(),
                capture_output=True,
                timeout=self.timeout,
                cwd=str(workdir),
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "LANG": "C.UTF-8",
                    "HOME": str(workdir),
                    "TMPDIR": str(workdir),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    # No network by default: pwntools remote() would otherwise be a
                    # ready-made bypass of the Gateway's scope engine.
                    "PWNLIB_NOTERM": "1",
                },
            )
        except subprocess.TimeoutExpired:
            return "failed", "", f"pwntools job exceeded {self.timeout}s."
        except OSError as exc:
            return "failed", "", f"Could not launch pwntools: {exc}"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        stdout = (proc.stdout or b"").decode(errors="replace").strip()
        stderr = (proc.stderr or b"").decode(errors="replace").strip()
        parsed: dict[str, Any] | None = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                    break
                except ValueError:
                    continue
        if parsed is None:
            status = "completed" if proc.returncode == 0 else "failed"
            return status, stdout, stderr
        if parsed.get("unavailable"):
            return "unavailable", "", str(parsed.get("error", ""))
        if not parsed.get("ok"):
            return "failed", "", str(parsed.get("error", "pwntools reported a failure"))
        result = parsed.get("result")
        return "completed", json.dumps(result, indent=2, ensure_ascii=False, default=str), ""

    def _insert_job(
        self,
        *,
        job_id: str,
        engagement_id: str,
        mission_id: str | None,
        principal: OperatorPrincipal,
        target: str,
        action: str,
        body: str,
        digest: str,
        created: str,
    ) -> None:
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """INSERT INTO pwntools_jobs
                     (job_id, engagement_id, mission_id, requested_by, target, action,
                      script_body, script_sha256, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?)""",
                (
                    job_id,
                    engagement_id,
                    mission_id,
                    principal.operator_id,
                    target[:400],
                    action,
                    body,
                    digest,
                    created,
                ),
            )

    def _finish_job(
        self, job_id: str, status: str, output: str, output_digest: str, version: str = ""
    ) -> None:
        with self.db._write_lock, self.db.connection() as conn:  # noqa: SLF001
            conn.execute(
                """UPDATE pwntools_jobs
                      SET status=?, output=?, output_sha256=?, pwntools_version=?, finished_at=?
                    WHERE job_id=?""",
                (status, output, output_digest, version, _utcnow(), job_id),
            )

    def _audit(
        self,
        principal: OperatorPrincipal,
        engagement_id: str,
        target: str,
        job_id: str,
        action: str,
        status: str,
        summary: str,
    ) -> None:
        self.db.write_audit_log(
            engagement_id=engagement_id,
            operator_id=principal.operator_id,
            target=target or engagement_id,
            tool_or_script=f"pwntools:{action}",
            params={"job_id": job_id, "layer": "pwntools"},
            status="completed" if status in {"completed", "unavailable"} else status,
            stdout_summary=summary[:500],
        )
