# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Unit tests for HMAC signing/verification. Pure — no Frappe site required.

Run standalone:
    env/bin/python -m unittest brew93_connector.tests.test_signing
(from apps/brew93_connector, or with that dir on sys.path)
"""

import hashlib
import hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from brew93_connector.api import signing  # noqa: E402

SECRET = "test-secret-not-a-real-one"


class TestSigning(unittest.TestCase):
    def test_signing_string_format(self):
        self.assertEqual(signing.signing_string(1700000000, "abc"), b"1700000000.abc")
        self.assertEqual(signing.signing_string(1700000000, b"abc"), b"1700000000.abc")

    def test_compute_matches_reference_hmac(self):
        ts, body = 1700000000, '{"event_id":"e1"}'
        expected = hmac.new(SECRET.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
        self.assertEqual(signing.compute_signature(SECRET, ts, body), expected)

    def test_empty_secret_raises(self):
        with self.assertRaises(ValueError):
            signing.compute_signature("", 1, "x")

    def test_build_headers_shape(self):
        h = signing.build_signed_headers(SECRET, '{"a":1}', "evt-1", timestamp=1700000000)
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertEqual(h[signing.HEADER_TIMESTAMP], "1700000000")
        self.assertEqual(h[signing.HEADER_EVENT_ID], "evt-1")
        self.assertTrue(h[signing.HEADER_SIGNATURE].startswith("v1="))

    def test_verify_roundtrip_ok(self):
        body = '{"event_id":"e2"}'
        h = signing.build_signed_headers(SECRET, body, "e2", timestamp=1700000000)
        ok, reason = signing.verify_signature(
            SECRET, body, h[signing.HEADER_TIMESTAMP], h[signing.HEADER_SIGNATURE], now=1700000010
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_verify_expired(self):
        body = "{}"
        h = signing.build_signed_headers(SECRET, body, "e", timestamp=1700000000)
        ok, reason = signing.verify_signature(
            SECRET, body, h[signing.HEADER_TIMESTAMP], h[signing.HEADER_SIGNATURE],
            replay_window_seconds=300, now=1700000600,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")

    def test_verify_tampered_body(self):
        h = signing.build_signed_headers(SECRET, '{"amount":1}', "e", timestamp=1700000000)
        ok, reason = signing.verify_signature(
            SECRET, '{"amount":9999}', h[signing.HEADER_TIMESTAMP], h[signing.HEADER_SIGNATURE], now=1700000010
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "signature_mismatch")

    def test_verify_wrong_secret(self):
        body = "{}"
        h = signing.build_signed_headers(SECRET, body, "e", timestamp=1700000000)
        ok, reason = signing.verify_signature(
            "other-secret", body, h[signing.HEADER_TIMESTAMP], h[signing.HEADER_SIGNATURE], now=1700000010
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "signature_mismatch")

    def test_verify_bad_format(self):
        ok, reason = signing.verify_signature(SECRET, "{}", "1700000000", "deadbeef", now=1700000000)
        self.assertFalse(ok)
        self.assertEqual(reason, "bad_signature_format")

    def test_verify_bad_timestamp(self):
        ok, reason = signing.verify_signature(SECRET, "{}", "not-a-number", "v1=abc", now=1700000000)
        self.assertFalse(ok)
        self.assertEqual(reason, "bad_timestamp")

    def test_resign_changes_with_timestamp(self):
        body = "{}"
        s1 = signing.compute_signature(SECRET, 1700000000, body)
        s2 = signing.compute_signature(SECRET, 1700000300, body)
        self.assertNotEqual(s1, s2)  # retry must re-sign with a fresh timestamp


if __name__ == "__main__":
    unittest.main()
