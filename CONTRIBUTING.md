# Contributing to certpeek

Thanks for taking a look. certpeek's job is to tell the truth about a
certificate, especially a broken one.

## Good contributions

A real host whose certificate certpeek reads wrong — the host, what it reported,
and what's actually true. A missing flag (a problem certpeek should surface but
doesn't), or a clearer one. Keeping it dependency-free.

## Ground rules

- **Standard library only.** No runtime dependencies. Tests use `unittest`.
- **Every change comes with a test.** Flag logic is a pure function tested with
  synthetic certificates and a fixed clock (`tests/test_evaluate.py`); the real
  path is tested against a local TLS server with a self-signed cert
  (`tests/test_integration.py`), so the suite needs no network.
- **Never raise for bad input.** A dead host or a broken certificate is a
  `Report` with an `error` or `flags`, not an exception.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

No install needed — the tests import the package from the repo root. The fixture
cert in `tests/fixtures/` is a throwaway self-signed localhost certificate.

## Scope

In: reading a certificate's identity, validity, trust and protocol. Out: port
scanning, and deep X.509 surgery (reach for OpenSSL or `cryptography`). Security
reports go to **info@nirry.net** — see [SECURITY.md](SECURITY.md).
