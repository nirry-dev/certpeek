"""Fetch and read the TLS certificate a host serves.

The trick worth knowing: Python's ``getpeercert()`` only returns a *parsed*
certificate when validation succeeds, so an expired or self-signed cert — the
ones you most want to look at — comes back empty. certpeek instead fetches the
certificate with verification turned off (so any cert comes back as DER), decodes
it with the standard library's own X.509 decoder, and runs a *separate*
validating connection just to learn whether the chain and hostname check out.
"""

from __future__ import annotations

import _ssl
import os
import socket
import ssl
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

__all__ = ["inspect", "Report", "split_target"]

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class Report:
    """What one host's TLS certificate looks like. Truthy when nothing's wrong."""

    host: str
    port: int
    connected: bool = False
    error: Optional[str] = None
    subject_cn: Optional[str] = None
    sans: List[str] = field(default_factory=list)
    issuer_cn: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_left: Optional[int] = None
    serial: Optional[str] = None
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    trusted: bool = False
    self_signed: bool = False
    flags: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.connected and self.error is None and not self.flags

    def __bool__(self) -> bool:
        return self.ok


def split_target(target: str, default_port: int = 443) -> Tuple[str, int]:
    """Reduce a target (host / host:port / URL) to (host, port)."""
    t = target.strip()
    if "://" in t:
        u = urlsplit(t)
        return (u.hostname or t), (u.port or default_port)
    if t.startswith("["):  # [IPv6] or [IPv6]:port
        end = t.find("]")
        if end != -1:
            rest = t[end + 1:]
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
            return t[1:end], port
    if t.count(":") == 1:
        host, _, p = t.partition(":")
        return host, (int(p) if p.isdigit() else default_port)
    return t, default_port


def _decode_der(der: bytes) -> Optional[dict]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return _ssl._test_decode_cert(path)
    finally:
        os.unlink(path)


def _fetch(host: str, port: int, sni: str, timeout: float):
    """Connect without validating and return (cert dict, protocol, cipher)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            protocol = tls.version()
            cipher = tls.cipher()
    cert = _decode_der(der) if der else None
    return cert, protocol, (cipher[0] if cipher else None)


def _validate(host: str, port: int, sni: str, timeout: float) -> Tuple[bool, Optional[str]]:
    """A separate validating connection: does the chain and hostname check out?"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True, None
    except ssl.SSLCertVerificationError as err:
        return False, (getattr(err, "verify_message", None) or str(err))
    except (ssl.SSLError, OSError) as err:
        return False, str(err)


def _cn(name) -> Optional[str]:
    for rdn in name or ():
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _as_dt(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def evaluate(cert: dict, *, trusted: bool, reason: Optional[str], protocol: Optional[str], expiry_days: int, now: datetime) -> dict:
    """Pure: turn a parsed certificate into summary fields and flags."""
    out: dict = {
        "subject_cn": _cn(cert.get("subject")),
        "issuer_cn": _cn(cert.get("issuer")),
        "sans": [v for t, v in cert.get("subjectAltName", ()) if t in ("DNS", "IP Address")],
        "serial": cert.get("serialNumber"),
    }
    nb, na = cert.get("notBefore"), cert.get("notAfter")
    out["not_before"] = _as_dt(nb).isoformat() if nb else None
    out["not_after"] = _as_dt(na).isoformat() if na else None
    self_signed = bool(cert.get("subject")) and cert.get("subject") == cert.get("issuer")
    out["self_signed"] = self_signed

    flags: List[str] = []
    days_left = None
    if na:
        na_dt = _as_dt(na)
        days_left = (na_dt - now).days
        if na_dt <= now:
            flags.append("expired")
        elif days_left < expiry_days:
            flags.append(f"expires in {days_left}d")
    if nb and _as_dt(nb) > now:
        flags.append("not yet valid")
    out["days_left"] = days_left

    if self_signed:
        flags.append("self-signed")
    elif not trusted:
        flags.append("hostname mismatch" if reason and "hostname" in reason.lower() else "untrusted")
    if protocol in _WEAK_PROTOCOLS:
        flags.append(f"weak protocol ({protocol})")

    out["flags"] = flags
    return out


def inspect(host: str, port: int = 443, *, timeout: float = 10.0, server_name: Optional[str] = None, expiry_days: int = 30) -> Report:
    """Inspect the TLS certificate at *host:port*."""
    report = Report(host=host, port=port)
    sni = server_name or host
    try:
        cert, protocol, cipher = _fetch(host, port, sni, timeout)
    except socket.gaierror:
        report.error = "could not resolve host"
        return report
    except (socket.timeout, TimeoutError):
        report.error = "connection timed out"
        return report
    except ConnectionError:
        report.error = "connection refused"
        return report
    except (ssl.SSLError, OSError) as err:
        report.error = f"TLS error: {err}"
        return report

    report.connected = True
    report.protocol = protocol
    report.cipher = cipher
    if not cert:
        report.error = "no certificate presented"
        return report

    report.trusted, reason = _validate(host, port, sni, timeout)
    summary = evaluate(cert, trusted=report.trusted, reason=reason, protocol=protocol, expiry_days=expiry_days, now=datetime.now(timezone.utc))
    for key, value in summary.items():
        setattr(report, key, value)
    return report
