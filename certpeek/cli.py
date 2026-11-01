"""Command line: ``certpeek`` inspects the TLS certificate of each host.

    certpeek example.com
    certpeek example.com:8443 https://api.example.com --days 14
    cat hosts.txt | certpeek --json

Exit status: 0 when every certificate is fine, 1 when any has a problem (expired,
expiring within --days, self-signed, untrusted, hostname mismatch, weak protocol,
or unreachable), 2 for a bad call.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from typing import Sequence

from . import __version__
from .inspect import Report, inspect, split_target


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certpeek", description="Inspect the TLS certificate a host serves.")
    p.add_argument("hosts", nargs="*", help="hosts to check: host, host:port, or URL (default: read stdin)")
    p.add_argument("-p", "--port", type=int, default=443, help="default port (default: 443)")
    p.add_argument("-d", "--days", type=int, default=30, metavar="N", help="flag certs expiring within N days (default: 30)")
    p.add_argument("-t", "--timeout", type=float, default=10.0, metavar="S", help="connection timeout in seconds (default: 10)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("-V", "--version", action="version", version=f"certpeek {__version__}")
    return p


def _line(r: Report) -> str:
    where = f"{r.host}:{r.port}"
    if r.error:
        return f"{where}  ERROR: {r.error}"
    status = "OK" if r.ok else "[" + ", ".join(r.flags) + "]"
    bits = [where, status]
    if r.not_after:
        bits.append(f"expires {r.not_after[:10]} ({r.days_left}d)")
    if r.issuer_cn:
        bits.append(f"issuer={r.issuer_cn}")
    if r.protocol:
        bits.append(r.protocol)
    return "  ".join(bits)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.hosts:
        targets = args.hosts
    else:
        targets = [line.strip() for line in sys.stdin if line.strip()]
    if not targets:
        print("certpeek: no hosts given", file=sys.stderr)
        return 2

    reports = []
    any_problem = False
    for target in targets:
        host, port = split_target(target, args.port)
        report = inspect(host, port, timeout=args.timeout, expiry_days=args.days)
        reports.append(report)
        if not report.ok:
            any_problem = True
        if not args.json:
            print(_line(report))

    if args.json:
        print(json.dumps([{**dataclasses.asdict(r), "ok": r.ok} for r in reports], indent=2))

    return 1 if any_problem else 0


if __name__ == "__main__":
    raise SystemExit(main())
