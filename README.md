# certpeek

**Inspect the TLS certificate a host serves — including the broken ones.**

Point it at a host and it tells you what certificate is on the other end: who
it's for, who signed it, when it expires, whether the chain and hostname check
out, and the TLS version negotiated. Crucially, it reads **certificates that
don't validate** — expired, self-signed, wrong-hostname — which are exactly the
ones you need to see.

```bash
$ certpeek example.com badssl.com expired.badssl.com
example.com:443  OK  expires 2026-03-09 (128d)  issuer=R11  TLSv1.3
badssl.com:443  OK  expires 2026-05-18 (198d)  issuer=R11  TLSv1.3
expired.badssl.com:443  [expired, untrusted]  expires 2015-04-12 (-3855d)  issuer=COMODO RSA  TLSv1.2
```

No dependencies — just the Python standard library. Python 3.9+.

---

## Why

The obvious way to read a certificate — `ssl.getpeercert()` — only returns it
when verification *succeeds*. So the moment a cert is expired or self-signed, the
one time you actually want to look, it comes back empty. certpeek works the way
you'd want instead: it fetches the certificate with verification off (so any cert
comes back), decodes it with the standard library's own X.509 decoder, and runs a
**separate validating connection** just to learn whether the chain and hostname
are trusted. You get the facts *and* the verdict, for any certificate.

## Install

```bash
pip install certpeek
```

Or vendor the `certpeek/` package — it's pure standard library, no build step.

## Use it

### On the command line

```bash
certpeek example.com                        # one host
certpeek example.com:8443 https://api.x.io  # host:port and URLs
certpeek example.com --days 14              # flag anything expiring within 14 days
cat hosts.txt | certpeek --json             # a list from stdin, as JSON
```

Exit status: `0` when every certificate is fine, `1` when any has a problem
(expired, expiring within `--days`, self-signed, untrusted, hostname mismatch,
weak protocol, or unreachable), `2` for a bad call. That makes it a one-liner for
monitoring:

```bash
certpeek api.example.com --days 21 || alert "cert needs attention"
```

### In Python

```python
from certpeek import inspect

r = inspect("example.com")
r.days_left        # days until it expires (negative if already expired)
r.not_after        # ISO expiry timestamp
r.sans             # the subject alternative names
r.issuer_cn        # who signed it
r.trusted          # did the chain + hostname validate?
r.protocol         # negotiated TLS version
r.flags            # [] when healthy, else ['expired', 'self-signed', ...]
bool(r)            # True when connected and nothing's wrong
```

`inspect(host, port=443, *, timeout=10, server_name=None, expiry_days=30)` returns
a `Report`. It never raises for a bad host or a bad certificate — failures land in
`r.error` and `r.flags`.

## What it flags

`expired` · `not yet valid` · `expires in Nd` (within the threshold) ·
`self-signed` · `untrusted` (unknown CA or broken chain) · `hostname mismatch` ·
`weak protocol (TLSv1.1)` — and an `ERROR` line for a host it can't reach.

## What it is not

- **Not a scanner.** It inspects the certificate on one port; it doesn't sweep
  ports or crawl a site. Pair it with [netprobe](https://github.com/nirry-dev/netprobe)
  to find the services first.
- **Not a full X.509 toolkit.** It reports the fields that matter for operating a
  service — identity, validity, trust, protocol — not every extension. For
  deep certificate surgery, reach for OpenSSL or `cryptography`.

## License

MIT. Part of [Nirry Labs](https://nirry.net) — local-first AI and security tools,
dependency-light and auditable by design.
