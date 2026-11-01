# Security Policy

## Reporting a vulnerability

Please report security issues privately to **info@nirry.net** rather than in a
public issue. Include the host or input that reproduces the problem. You'll get an
acknowledgement, and a fix or a clear explanation.

## Design notes

- certpeek deliberately fetches certificates **without verifying** them, so it can
  show you an expired or self-signed cert. It never *trusts* such a certificate:
  trust is decided only by the separate, fully validating connection, and
  reported as `trusted` / `flags`. certpeek reads and reports; it never sends data
  over the connection or acts on what it finds.
- It connects only to the hosts you give it, on the port you give it.

## Supported versions

Fixes land on the latest release.
