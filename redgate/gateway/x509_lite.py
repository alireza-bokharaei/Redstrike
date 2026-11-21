"""Minimal, dependency-free DER reader for the certificate facts Redstrike needs.

Python's ``SSLSocket.getpeercert()`` returns an empty mapping whenever the
handshake was not verified, which is exactly the case Redstrike must describe
during a deep audit (an untrusted chain is a finding, not a reason to stop). This
module parses the DER blob directly and returns only the handful of fields the
audit reports, so no third-party X.509 library is added to the runtime.

The parser is intentionally strict and bounded: it refuses unsupported/indefinite
lengths, caps every loop, and raises :class:`X509Error` rather than guessing.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

MAX_CERT_BYTES = 64 * 1024
MAX_DEPTH = 12


class X509Error(ValueError):
    """The DER blob is not a certificate this parser can describe."""


# --- OID table (only the identifiers the audit reports on) --------------------
_OID_CN = bytes.fromhex("550403")
_OID_SAN = bytes.fromhex("551d11")
_OID_BASIC_CONSTRAINTS = bytes.fromhex("551d13")
_OID_RSA = bytes.fromhex("2a864886f70d010101")
_OID_EC = bytes.fromhex("2a8648ce3d0201")

_SIGNATURE_OIDS: dict[bytes, str] = {
    bytes.fromhex("2a864886f70d010104"): "md5WithRSAEncryption",
    bytes.fromhex("2a864886f70d010105"): "sha1WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010b"): "sha256WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010c"): "sha384WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010d"): "sha512WithRSAEncryption",
    bytes.fromhex("2a8648ce3d0401"): "ecdsa-with-SHA1",
    bytes.fromhex("2a8648ce3d0403"): "ecdsa-with-SHA384",
    bytes.fromhex("2a8648ce3d040302"): "ecdsa-with-SHA256",
    bytes.fromhex("2a864886f70d01010e"): "sha224WithRSAEncryption",
    # Ed25519 / Ed448
    bytes.fromhex("2b6570"): "Ed25519",
    bytes.fromhex("2b6571"): "Ed448",
}

_CURVE_BITS: dict[bytes, tuple[str, int]] = {
    bytes.fromhex("2a8648ce3d030107"): ("P-256", 256),
    bytes.fromhex("2b81040022"): ("P-384", 384),
    bytes.fromhex("2b81040023"): ("P-521", 521),
    bytes.fromhex("2b8104000a"): ("secp256k1", 256),
    bytes.fromhex("2a8648ce3d030101"): ("P-192", 192),
    bytes.fromhex("2b81040021"): ("P-224", 224),
}


def _tlv(buf: bytes, offset: int) -> tuple[int, int, int]:
    """Return ``(tag, value_start, value_end)`` for the TLV at ``offset``."""
    if offset + 2 > len(buf):
        raise X509Error("Truncated DER element.")
    tag = buf[offset]
    if tag & 0x1F == 0x1F:
        raise X509Error("Multi-byte DER tags are not supported.")
    first = buf[offset + 1]
    cursor = offset + 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise X509Error("Indefinite lengths are not valid DER.")
        if count > 4 or cursor + count > len(buf):
            raise X509Error("Unsupported DER length encoding.")
        length = int.from_bytes(buf[cursor : cursor + count], "big")
        cursor += count
    else:
        length = first
    end = cursor + length
    if end > len(buf):
        raise X509Error("DER element extends past the buffer.")
    return tag, cursor, end


def _children(buf: bytes, start: int, end: int, limit: int = 64) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    cursor = start
    while cursor < end and len(out) < limit:
        tag, vstart, vend = _tlv(buf, cursor)
        out.append((tag, vstart, vend))
        cursor = vend
    return out


def _expect(tag: int, wanted: int, what: str) -> None:
    if tag != wanted:
        raise X509Error(f"Expected {what} (tag {wanted:#x}), found tag {tag:#x}.")


def _oid(buf: bytes, start: int, end: int) -> bytes:
    return buf[start:end]


def _parse_time(buf: bytes, start: int, end: int, tag: int) -> dt.datetime:
    raw = buf[start:end].decode("ascii", errors="strict")
    if tag == 0x17:  # UTCTime
        if not raw.endswith("Z") or len(raw) < 11:
            raise X509Error("UTCTime must be UTC-suffixed.")
        body = raw[:-1]
        year = int(body[0:2])
        year += 1900 if year >= 50 else 2000
        rest = body[2:]
    elif tag == 0x18:  # GeneralizedTime
        if not raw.endswith("Z"):
            raise X509Error("GeneralizedTime must be UTC-suffixed.")
        year, rest = int(raw[0:4]), raw[4:-1]
    else:
        raise X509Error("Certificate time is neither UTCTime nor GeneralizedTime.")
    digits = "".join(ch for ch in rest if ch.isdigit())
    if len(digits) < 10:
        raise X509Error("Certificate timestamp is too short.")
    month, day, hour, minute = (int(digits[i : i + 2]) for i in (0, 2, 4, 6))
    second = int(digits[8:10])
    return dt.datetime(
        year, month, day, hour, minute, second, tzinfo=dt.timezone.utc
    )


def _name_cn(buf: bytes, start: int, end: int) -> str | None:
    """Return the last commonName in an X.501 Name, or None."""
    last: str | None = None
    for _tag, rdstart, rdend in _children(buf, start, end, limit=32):
        for _stag, setstart, setend in _children(buf, rdstart, rdend, limit=16):
            pairs = _children(buf, setstart, setend, limit=8)
            for position, (tag, oidstart, oidend) in enumerate(pairs):
                if tag != 0x06 or _oid(buf, oidstart, oidend) != _OID_CN:
                    continue
                if position + 1 >= len(pairs):
                    continue
                _vtag, vstart, vend = pairs[position + 1]
                last = buf[vstart:vend].decode("utf-8", errors="replace")[:128]
    return last


def _parse_san(buf: bytes, start: int, end: int) -> list[str]:
    """Extract dNSName and iPAddress general names from a SAN extension value."""
    names: list[str] = []
    for tag, vstart, vend in _children(buf, start, end, limit=64):
        if tag == 0x82:  # dNSName (context-specific primitive)
            names.append(buf[vstart:vend].decode("ascii", errors="replace")[:253])
        elif tag == 0x87 and (vend - vstart) in (4, 16):  # iPAddress
            raw = buf[vstart:vend]
            if len(raw) == 4:
                names.append(".".join(str(b) for b in raw))
            else:
                names.append(raw.hex())
    return names


def _key_bits(buf: bytes, alg_oid: bytes, key_start: int, key_end: int, params: bytes) -> tuple[str, int]:
    if alg_oid == _OID_RSA:
        # BIT STRING (unused-bits byte) -> RSAPublicKey SEQUENCE -> modulus INTEGER
        try:
            # key_start points at the BIT STRING value; its first octet is the
            # unused-bit count, so the RSAPublicKey SEQUENCE starts one byte later.
            seq_tag, sstart, _send = _tlv(buf, key_start + 1)
            if seq_tag != 0x30:
                return ("RSA", 0)
            modulus_tag, mstart, mend = _tlv(buf, sstart)
            if modulus_tag != 0x02:
                return ("RSA", 0)
            return ("RSA", int.from_bytes(buf[mstart:mend], "big").bit_length())
        except X509Error:
            return ("RSA", 0)
    if alg_oid == _OID_EC:
        curve = _CURVE_BITS.get(params)
        if curve:
            return (f"EC/{curve[0]}", curve[1])
        return ("EC", 0)
    if alg_oid == bytes.fromhex("2b6570"):
        return ("Ed25519", 256)
    if alg_oid == bytes.fromhex("2b6571"):
        return ("Ed448", 456)
    return ("unknown", 0)


def parse_certificate_der(der: bytes) -> dict[str, Any]:
    """Describe a DER certificate; raises :class:`X509Error` if it cannot."""
    if not der or len(der) > MAX_CERT_BYTES:
        raise X509Error("Certificate blob is empty or oversized.")
    tag, cstart, cend = _tlv(der, 0)
    _expect(tag, 0x30, "Certificate SEQUENCE")
    parts = _children(der, cstart, cend, limit=4)
    if len(parts) < 3:
        raise X509Error("Certificate must contain tbs, algorithm and signature.")
    tbs_tag, tbs_start, tbs_end = parts[0]
    _expect(tbs_tag, 0x30, "TBSCertificate SEQUENCE")
    sigalg_tag, sigalg_start, sigalg_end = parts[1]
    _expect(sigalg_tag, 0x30, "signatureAlgorithm SEQUENCE")

    signature_algorithm = "unknown"
    sig_children = _children(der, sigalg_start, sigalg_end, limit=4)
    if sig_children and sig_children[0][0] == 0x06:
        signature_algorithm = _SIGNATURE_OIDS.get(
            _oid(der, sig_children[0][1], sig_children[0][2]), "unknown"
        )

    fields = _children(der, tbs_start, tbs_end, limit=24)
    index = 0
    if fields and fields[0][0] == 0xA0:  # [0] version
        index = 1
    needed = ("serial", "signature", "issuer", "validity", "subject", "spki")
    if len(fields) < index + len(needed):
        raise X509Error("TBSCertificate is missing required fields.")
    serial_tag, serial_start, serial_end = fields[index]
    _expect(serial_tag, 0x02, "serialNumber INTEGER")
    _issuer_tag, issuer_start, issuer_end = fields[index + 2]
    validity_tag, validity_start, validity_end = fields[index + 3]
    _expect(validity_tag, 0x30, "Validity SEQUENCE")
    _subject_tag, subject_start, subject_end = fields[index + 4]
    _spki_tag, spki_start, spki_end = fields[index + 5]

    validity = _children(der, validity_start, validity_end, limit=2)
    if len(validity) != 2:
        raise X509Error("Validity must contain notBefore and notAfter.")
    not_before = _parse_time(der, validity[0][1], validity[0][2], validity[0][0])
    not_after = _parse_time(der, validity[1][1], validity[1][2], validity[1][0])

    subject_cn = _name_cn(der, subject_start, subject_end)
    issuer_cn = _name_cn(der, issuer_start, issuer_end)

    spki_children = _children(der, spki_start, spki_end, limit=4)
    key_alg_oid = b""
    params = b""
    alg_bits: tuple[str, int] = ("unknown", 0)
    if spki_children and spki_children[0][0] == 0x30:
        alg_children = _children(der, spki_children[0][1], spki_children[0][2], limit=4)
        if alg_children and alg_children[0][0] == 0x06:
            key_alg_oid = _oid(der, alg_children[0][1], alg_children[0][2])
        if len(alg_children) > 1 and alg_children[1][0] == 0x06:
            params = _oid(der, alg_children[1][1], alg_children[1][2])
        if len(spki_children) > 1 and spki_children[1][0] == 0x03:
            alg_bits = _key_bits(
                der, key_alg_oid, spki_children[1][1], spki_children[1][2], params
            )

    sans: list[str] = []
    is_ca = False
    for tag, vstart, vend in fields:
        if tag != 0xA3:  # [3] extensions
            continue
        ext_wrapper = _children(der, vstart, vend, limit=2)
        if not ext_wrapper:
            continue
        for _etag, estart, eend in _children(
            der, ext_wrapper[0][1], ext_wrapper[0][2], limit=32
        ):
            ext_parts = _children(der, estart, eend, limit=6)
            if len(ext_parts) < 2 or ext_parts[0][0] != 0x06:
                continue
            oid = _oid(der, ext_parts[0][1], ext_parts[0][2])
            value_part = ext_parts[-1]
            if value_part[0] != 0x04:
                continue
            if oid == _OID_SAN:
                inner_tag, inner_start, inner_end = _tlv(der, value_part[1])
                if inner_tag == 0x30:
                    sans.extend(_parse_san(der, inner_start, inner_end))
            elif oid == _OID_BASIC_CONSTRAINTS:
                inner_tag, inner_start, inner_end = _tlv(der, value_part[1])
                if inner_tag == 0x30:
                    for ctag, cstart, cend in _children(der, inner_start, inner_end, limit=4):
                        if ctag == 0x01 and cend > cstart and der[cstart] != 0:
                            is_ca = True

    now = dt.datetime.now(dt.timezone.utc)
    dns_names = [n for n in sans if not _looks_like_ip(n)]
    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "san_names": sans,
        "san_dns": dns_names,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - now).days,
        "serial_number": der[serial_start:serial_end].hex()[:80],
        "signature_algorithm": signature_algorithm,
        "key_type": alg_bits[0],
        "key_bits": alg_bits[1],
        "is_ca": is_ca,
        "self_issued": bool(subject_cn and issuer_cn and subject_cn == issuer_cn),
        "sha256": hashlib.sha256(der).hexdigest(),
    }


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return ":" in value and all(ch in "0123456789abcdef:" for ch in value.lower())
