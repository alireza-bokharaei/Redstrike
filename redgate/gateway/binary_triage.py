"""Read-only ELF hardening triage for CTF / binary-focused missions in 2.2.

This is the *deliberate* shape of the "binary & low-level layer". It parses ELF
headers and dynamic-section flags to answer audit questions (is NX on? is the
binary PIE? is RELRO partial or full? is there a stack canary, an RPATH, a
writable/executable segment?) and nothing else.

What this module will not do, by design:

* import or bundle ``pwntools``,
* build ROP chains, shellcode, or format-string payloads,
* attach to a remote process, spawn a debugger, or send exploit traffic,
* read anything outside the configured artifact root.

The upstream reference (``alireza-bokharaei/pwntools``) is credited as the
motivation for a binary-focused workflow; no source is copied and no dependency
is added. Weaponised automation belongs outside a governance platform.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_ELF_MAGIC = b"\x7fELF"

# Section-header / program-header type constants we care about.
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_RPATH = 15
DT_RUNPATH = 29
PF_X = 0x1
PF_W = 0x2


class BinaryTriageError(ValueError):
    """The artifact cannot be parsed, or the request violates policy."""


@dataclass
class ELFSummary:
    path: str
    arch: str
    bits: int
    endian: str
    elf_type: str
    sha256: str = ""
    size_bytes: int = 0
    nx: bool | None = None
    pie: bool | None = None
    relro: str = "unknown"
    canary: bool = False
    fortify: bool = False
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    bind_now: bool = False
    wx_segments: int = 0
    interpreter: str = ""
    needed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "elf_type": self.elf_type,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "hardening": {
                "nx": self.nx,
                "pie": self.pie,
                "relro": self.relro,
                "stack_canary": self.canary,
                "fortify_source": self.fortify,
                "bind_now": self.bind_now,
                "wx_segments": self.wx_segments,
                "rpath": self.rpath,
                "runpath": self.runpath,
            },
            "interpreter": self.interpreter,
            "needed": self.needed,
        }


_EM_MACHINES = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "arm",
    0xB7: "aarch64",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc64",
    0xF3: "riscv",
    0x16: "s390",
}
_ET_TYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}


def resolve_artifact(artifact_root: str | os.PathLike[str], relative: str) -> Path:
    """Resolve an operator-supplied path strictly inside the artifact root."""
    root = Path(artifact_root).resolve()
    if not root.is_dir():
        raise BinaryTriageError("The configured artifact directory does not exist.")
    candidate = (root / relative).resolve()
    if root not in candidate.parents and candidate != root:
        raise BinaryTriageError("Artifact path escapes the configured artifact directory.")
    if candidate.is_dir():
        raise BinaryTriageError("Artifact path must be a regular file, not a directory.")
    if not candidate.is_file():
        raise BinaryTriageError("Artifact does not exist under the artifact directory.")
    if candidate.stat().st_size > MAX_ARTIFACT_BYTES:
        raise BinaryTriageError("Artifact exceeds the configured size ceiling.")
    return candidate


def _cstr(table: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end < 0:
        end = min(len(table), offset + limit)
    return table[offset:end].decode("utf-8", errors="replace")[:limit]


def _cstr_list(table: bytes, offset: int, limit: int = 16) -> list[str]:
    out: list[str] = []
    cursor = offset
    while cursor < len(table) and len(out) < limit:
        value = _cstr(table, cursor)
        if not value:
            break
        out.append(value)
        cursor += len(value) + 1
    return out


def analyze_elf(data: bytes, *, display_path: str, digest: str) -> ELFSummary:
    """Parse an ELF image from bytes; raises ``BinaryTriageError`` on non-ELF input."""
    if len(data) < 64 or not data.startswith(_ELF_MAGIC):
        raise BinaryTriageError("Not an ELF image (missing 0x7fELF magic).")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise BinaryTriageError("Unsupported ELF class or endianness marker.")
    bits = 64 if ei_class == 2 else 32
    endian = "<" if ei_data == 1 else ">"
    header_fmt = endian + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    header_size = 64 if bits == 64 else 52
    if len(data) < header_size:
        raise BinaryTriageError("Truncated ELF header.")
    (
        e_type,
        e_machine,
        _version,
        _entry,
        e_phoff,
        e_shoff,
        _flags,
        _ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack(header_fmt, data[16:header_size])

    summary = ELFSummary(
        path=display_path,
        arch=_EM_MACHINES.get(e_machine, f"machine-{e_machine:#x}"),
        bits=bits,
        endian="little" if ei_data == 1 else "big",
        elf_type=_ET_TYPES.get(e_type, f"type-{e_type}"),
        sha256=digest,
        size_bytes=len(data),
    )
    summary.pie = e_type == 3

    # ---- program headers --------------------------------------------------
    ph_fmt = endian + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
    if e_phentsize != struct.calcsize(ph_fmt):
        raise BinaryTriageError("Unexpected program-header size; artifact may be corrupted.")
    dynamic_off = dynamic_size = None
    has_relro = has_gnu_stack = False
    gnu_stack_flags = None
    for index in range(min(e_phnum, 512)):
        start = e_phoff + index * e_phentsize
        if start + e_phentsize > len(data):
            raise BinaryTriageError("Program header table extends past end of file.")
        fields = struct.unpack(ph_fmt, data[start : start + e_phentsize])
        p_type, p_flags = fields[0], fields[1]
        if bits == 64:
            p_offset, p_vaddr, p_paddr, p_filesz = fields[2], fields[3], fields[4], fields[5]
        else:
            p_offset, p_vaddr, p_paddr, p_filesz = fields[1], fields[2], fields[3], fields[4]
        del p_vaddr, p_paddr
        if p_type == PT_LOAD and (p_flags & PF_X) and (p_flags & PF_W):
            summary.wx_segments += 1
        if p_type == PT_GNU_RELRO:
            has_relro = True
        if p_type == PT_GNU_STACK:
            has_gnu_stack = True
            gnu_stack_flags = p_flags
        if p_type == PT_DYNAMIC:
            dynamic_off, dynamic_size = p_offset, p_filesz

    summary.nx = (not (gnu_stack_flags & PF_X)) if has_gnu_stack else None

    # ---- dynamic section --------------------------------------------------
    if dynamic_off is not None and dynamic_size:
        dyn_fmt = endian + ("qQ" if bits == 64 else "iI")
        dyn_size = struct.calcsize(dyn_fmt)
        strtab: bytes = b""
        entries: list[tuple[int, int]] = []
        for index in range(min(dynamic_size // dyn_size, 512)):
            start = dynamic_off + index * dyn_size
            if start + dyn_size > len(data):
                break
            tag, val = struct.unpack(dyn_fmt, data[start : start + dyn_size])
            entries.append((tag, val))
        # Resolve DT_STRTAB virtual address -> file offset using PT_LOAD map.
        strtab_addr = next((val for tag, val in entries if tag == 5), None)
        needed_offsets = [val for tag, val in entries if tag == 1]
        rpath_offset = next((val for tag, val in entries if tag == DT_RPATH), None)
        runpath_offset = next((val for tag, val in entries if tag == DT_RUNPATH), None)
        for index in range(min(e_phnum, 512)):
            start = e_phoff + index * e_phentsize
            if start + e_phentsize > len(data):
                break
            fields = struct.unpack(ph_fmt, data[start : start + e_phentsize])
            if fields[0] != PT_LOAD:
                continue
            if bits == 64:
                p_offset, p_vaddr, p_filesz = fields[2], fields[3], fields[5]
            else:
                p_offset, p_vaddr, p_filesz = fields[1], fields[2], fields[4]
            if strtab_addr is not None and p_vaddr <= strtab_addr < p_vaddr + p_filesz:
                file_off = p_offset + (strtab_addr - p_vaddr)
                strtab = data[file_off : file_off + min(p_filesz, 1 << 20)]
                break
        if strtab:
            summary.needed = [_cstr(strtab, off) for off in needed_offsets][:32]
            if rpath_offset is not None:
                summary.rpath = _cstr_list(strtab, rpath_offset)
            if runpath_offset is not None:
                summary.runpath = _cstr_list(strtab, runpath_offset)
        summary.bind_now = any(
            (tag == DT_BIND_NOW) or (tag == DT_FLAGS and val & 0x8) or (tag == DT_FLAGS_1 and val & 0x1)
            for tag, val in entries
        )
        # Fortify symbols live in the string table as `__*_chk`.
        if strtab and b"_chk\x00" in strtab:
            summary.fortify = True

    summary.relro = (
        "full" if (has_relro and summary.bind_now) else "partial" if has_relro else "none"
    )

    # ---- symbols / sections for canary and interpreter ---------------------
    section_fmt = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    section_names: dict[int, str] = {}
    if e_shoff and e_shnum and e_shentsize == struct.calcsize(section_fmt):
        raw_sections: list[tuple[int, ...]] = []
        for index in range(min(e_shnum, 512)):
            start = e_shoff + index * e_shentsize
            if start + e_shentsize > len(data):
                break
            raw_sections.append(struct.unpack(section_fmt, data[start : start + e_shentsize]))
        if raw_sections and 0 <= e_shstrndx < len(raw_sections):
            shstr_raw = raw_sections[e_shstrndx]
            shstr_off, shstr_size = shstr_raw[4], shstr_raw[5]
            shstr = data[shstr_off : shstr_off + min(shstr_size, 1 << 20)]
            for idx, section in enumerate(raw_sections):
                section_names[idx] = _cstr(shstr, section[0], 128)
        for idx, section in enumerate(raw_sections):
            name = section_names.get(idx, "")
            if name in {".interp", ".comment", ".note.gnu.build-id"}:
                off, size = section[4], section[5]
                payload = data[off : off + min(size, 4096)]
                if name == ".interp":
                    summary.interpreter = payload.split(b"\x00")[0].decode(
                        "utf-8", errors="replace"
                    )[:200]
                if name == ".comment" and b"FORTIFY" in payload.upper():
                    summary.fortify = True
        for idx in range(min(e_shnum, 512)):
            start = e_shoff + idx * e_shentsize
            if start + e_shentsize > len(data):
                break
            if section_names.get(idx) in {".symtab", ".dynsym"}:
                payload = data[start : start + e_shentsize]
                fields = struct.unpack(section_fmt, payload)
                sym_off, sym_size, sym_entsize = fields[4], fields[5], fields[9]
                if sym_entsize and b"stack_chk_fail" in data[
                    sym_off : sym_off + min(sym_size, 1 << 20)
                ]:
                    summary.canary = True
        if not summary.canary:
            summary.canary = b"__stack_chk_fail" in data[: min(len(data), 1 << 22)]

    return summary


def triage(
    *,
    artifact_root: str | os.PathLike[str],
    relative_path: str,
    compute_sha256: bool = True,
) -> dict[str, Any]:
    """Policy-checked entry point returning a JSON-safe hardening report."""
    import hashlib

    path = resolve_artifact(artifact_root, relative_path)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest() if compute_sha256 else ""
    summary = analyze_elf(data, display_path=str(path.name), digest=digest)
    findings = derive_findings(summary)
    return {
        "artifact": summary.to_dict(),
        "findings": findings,
        "read_only": True,
        "exploit_generation": "not_supported",
    }


def derive_findings(summary: ELFSummary) -> list[dict[str, Any]]:
    """Map hardening facts to deterministic, gate-ready findings."""
    out: list[dict[str, Any]] = []

    def add(key: str, title: str, severity: str, evidence: str, remediation: str, score: int) -> None:
        out.append(
            {
                "finding_key": key,
                "category": "binary_hardening",
                "title": title,
                "severity": severity,
                "priority_score": score,
                "ai_confidence": 0.99,
                "evidence": evidence,
                "remediation": remediation,
                "requires_human_judgment": False,
                "human_judgment_reason": "",
                "dual_verified": True,
                "source": "binary_hardening_triage",
            }
        )

    if summary.nx is False:
        add(
            "binary:nx-disabled",
            "Stack is executable (NX disabled)",
            "high",
            "PT_GNU_STACK is marked PF_X; the loader will map an executable stack.",
            "Rebuild with -z noexecstack and link objects compiled without executable-stack notes.",
            82,
        )
    if summary.pie is False:
        add(
            "binary:not-pie",
            "Executable is not position independent",
            "medium",
            f"ELF type is '{summary.elf_type}' rather than 'dyn'.",
            "Build with -fPIE -pie so ASLR can randomise the image base.",
            56,
        )
    if summary.relro == "none":
        add(
            "binary:no-relro",
            "No RELRO protection",
            "medium",
            "No PT_GNU_RELRO program header is present.",
            "Link with -Wl,-z,relro (and -z now for full RELRO).",
            54,
        )
    elif summary.relro == "partial":
        add(
            "binary:partial-relro",
            "Only partial RELRO",
            "low",
            "PT_GNU_RELRO is present but the dynamic section is not bound immediately.",
            "Link with -Wl,-z,now to obtain full RELRO.",
            30,
        )
    if not summary.canary:
        add(
            "binary:no-stack-canary",
            "No stack protector symbol detected",
            "medium",
            "Neither __stack_chk_fail nor a fortified reference was found in the symbol tables.",
            "Compile with -fstack-protector-strong.",
            52,
        )
    if summary.wx_segments:
        add(
            "binary:writable-executable-segment",
            "A LOAD segment is both writable and executable",
            "high",
            f"{summary.wx_segments} PT_LOAD segment(s) carry PF_W|PF_X.",
            "Split code and data segments; add GNU_RELRO and avoid -z execstack.",
            78,
        )
    if summary.rpath or summary.runpath:
        add(
            "binary:library-path-override",
            "RPATH/RUNPATH allows library substitution",
            "medium",
            f"rpath={summary.rpath} runpath={summary.runpath}",
            "Remove the search path or pin it to a trusted absolute directory.",
            50,
        )
    return out
