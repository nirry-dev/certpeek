"""Unit tests for the pure flag logic, with synthetic certificates and a fixed clock."""

import unittest
from datetime import datetime, timezone

from certpeek.inspect import evaluate

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)


def cert(subject="example.com", issuer="Test CA", not_before="Jan 15 00:00:00 2024 GMT", not_after="Jan 15 00:00:00 2030 GMT", sans=("example.com",)):
    return {
        "subject": ((("commonName", subject),),),
        "issuer": ((("commonName", issuer),),),
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": tuple(("DNS", s) for s in sans),
        "serialNumber": "AB12",
    }


def flags(c, *, trusted=True, reason=None, protocol="TLSv1.3", days=30):
    return evaluate(c, trusted=trusted, reason=reason, protocol=protocol, expiry_days=days, now=NOW)["flags"]


class TestEvaluate(unittest.TestCase):
    def test_healthy(self):
        out = evaluate(cert(), trusted=True, reason=None, protocol="TLSv1.3", expiry_days=30, now=NOW)
        self.assertEqual(out["flags"], [])
        self.assertEqual(out["subject_cn"], "example.com")
        self.assertEqual(out["issuer_cn"], "Test CA")
        self.assertEqual(out["sans"], ["example.com"])
        self.assertFalse(out["self_signed"])

    def test_expired(self):
        out = evaluate(cert(not_after="Jan 15 00:00:00 2024 GMT"), trusted=True, reason=None, protocol="TLSv1.3", expiry_days=30, now=NOW)
        self.assertIn("expired", out["flags"])
        self.assertLess(out["days_left"], 0)

    def test_expiring_soon(self):
        out = evaluate(cert(not_after="Jan 11 00:00:00 2025 GMT"), trusted=True, reason=None, protocol="TLSv1.3", expiry_days=30, now=NOW)
        self.assertIn("expires in 10d", out["flags"])

    def test_not_yet_valid(self):
        self.assertIn("not yet valid", flags(cert(not_before="Jan 15 00:00:00 2026 GMT")))

    def test_self_signed(self):
        self.assertIn("self-signed", flags(cert(subject="me", issuer="me"), trusted=False))

    def test_untrusted(self):
        self.assertIn("untrusted", flags(cert(), trusted=False, reason="unable to get local issuer certificate"))

    def test_hostname_mismatch(self):
        self.assertIn("hostname mismatch", flags(cert(), trusted=False, reason="Hostname mismatch, not valid for 'x'"))

    def test_weak_protocol(self):
        self.assertIn("weak protocol (TLSv1.1)", flags(cert(), protocol="TLSv1.1"))


if __name__ == "__main__":
    unittest.main()
