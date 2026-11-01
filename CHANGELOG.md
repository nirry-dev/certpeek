# Changelog

All notable changes to certpeek are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-11-01

First release.

### Added
- `inspect(host, port=443, ...)` — fetch and read a host's TLS certificate,
  **including certificates that don't validate**: it fetches with verification
  off, decodes the certificate, and runs a separate validating connection to
  learn trust. Returns a `Report` (truthy when healthy) with subject, SANs,
  issuer, validity, `days_left`, serial, negotiated protocol/cipher, `trusted`,
  `self_signed`, and `flags`.
- Flags: `expired`, `not yet valid`, `expires in Nd`, `self-signed`, `untrusted`,
  `hostname mismatch`, and `weak protocol (…)`.
- A `certpeek` command-line tool: hosts / `host:port` / URLs from arguments or
  stdin, `--days`, `--timeout`, `--json`, and monitoring-friendly exit codes.
  Also runnable as `python -m certpeek`.
- Pure standard library.
