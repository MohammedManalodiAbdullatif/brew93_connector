# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Proves the outbound events sender signs the EXACT bytes it transmits and sets
Content-Type: application/json — the two things the Brew93 receiver is strict
about (it rejects a re-serialized body). No site or network required."""

import hashlib
import hmac
import json
import os
import sys
import unittest
import base64
import time
from unittest.mock import MagicMock, patch

import frappe
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from brew93_connector.api import client, signing  # noqa: E402

SECRET = "throwaway-test-secret"
URL = "https://example.invalid/api/v1/integrations/erpnext/events"


class _Resp:
    status_code = 200

    def json(self):
        return {"status": "processed"}


class TestSenderSignsExactBytes(unittest.TestCase):
    def test_http_service_login_rejects_before_post_or_password_use(self):
        session = MagicMock()
        with patch.object(client.cfg, "get_service_password") as get_password:
            with self.assertRaisesRegex(client.Brew93ConfigError, "HTTPS"):
                client._login(session, {"brew93_base_url": "http://example.invalid",
                                        "service_email": "service@example.invalid",
                                        "request_timeout": 5})
        session.post.assert_not_called()
        get_password.assert_not_called()
        self.assertNotIn("service-password", repr(session.mock_calls))

    def test_http_user_login_rejects_before_session_or_password_use(self):
        session = MagicMock()
        with patch.object(client, "_session", return_value=session) as make_session, \
             patch.object(client.cfg, "get_service_password") as get_password:
            with self.assertRaisesRegex(client.Brew93ConfigError, "HTTPS"):
                client._user_login({"brew93_base_url": "http://example.invalid", "request_timeout": 5},
                                   "user@example.invalid", "login-password")
        make_session.assert_not_called()
        get_password.assert_not_called()
        self.assertNotIn("login-password", repr(session.mock_calls))

    def test_http_crm_login_rejects_before_session_or_password_use(self):
        session = MagicMock()
        with patch.object(client, "_session", return_value=session) as make_session, \
             patch.object(client.cfg, "get_service_password") as get_password:
            with self.assertRaisesRegex(client.Brew93ConfigError, "HTTPS"):
                client.crm_login({"brew93_base_url": "http://example.invalid",
                                  "service_email": "admin@example.invalid", "request_timeout": 5})
        make_session.assert_not_called()
        get_password.assert_not_called()
        self.assertNotIn("admin-password", repr(session.mock_calls))

    def test_http_refresh_rejects_before_session_or_refresh_token_use(self):
        session = MagicMock()
        with patch.object(client, "_session", return_value=session) as make_session, \
             patch.object(client.cfg, "get_user_refresh_token") as get_refresh:
            with self.assertRaisesRegex(client.Brew93ConfigError, "HTTPS"):
                client._get_user_crm_token({"brew93_base_url": "http://example.invalid",
                                            "request_timeout": 5}, "user@example.com")
        make_session.assert_not_called()
        get_refresh.assert_not_called()
        self.assertNotIn("refresh-secret", repr(session.mock_calls))

    def test_http_public_user_login_rejects_before_session(self):
        session = MagicMock()
        with patch.object(client, "_session", return_value=session) as make_session:
            with self.assertRaisesRegex(client.Brew93ConfigError, "HTTPS"):
                client.brew93_user_login("http://example.invalid", "user@example.invalid",
                                         "login-password", None)
        make_session.assert_not_called()
        self.assertNotIn("login-password", repr(session.mock_calls))

    def test_jwt_claims_fail_closed_without_trust_key(self):
        def token(header, claims):
            enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
            return f"{enc(header)}.{enc(claims)}.signature"

        with patch.object(client.cfg, "get_jwt_verification_settings", return_value={}):
            with self.assertRaises(client.Brew93ConfigError):
                client._verified_claims(token({"alg": "HS256"}, {"exp": 9999999999}))

    def test_jwt_signature_failure_is_rejected(self):
        with patch.object(client.cfg, "get_jwt_verification_settings", return_value={"public_key": "bad-key"}):
            with self.assertRaises(client.Brew93ConfigError):
                client._verified_claims("eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjQxMDA3NTIwMDB9.invalid")

    def test_jwt_ttl_never_caches_short_lived_or_expired_tokens(self):
        now = int(time.time())
        self.assertEqual(client._jwt_ttl({"exp": now + 10}), 0)
        self.assertEqual(client._jwt_ttl({"exp": now - 1}), 0)

    def test_refresh_rotation_uses_password_api(self):
        with patch.object(client.cfg, "set_user_refresh_token") as save, patch.object(client.frappe, "cache") as cache:
            with patch.object(client, "_jwt_ttl", return_value=0), patch.object(client, "_session") as session_factory:
                response = MagicMock(status_code=200)
                response.json.return_value = {"data": {"access_token": "jwt", "refresh_token": "new", "expires_in": 600, "token_type": "Bearer"}}
                session = session_factory.return_value
                session.post.return_value = response
                me = MagicMock(status_code=200)
                me.json.return_value = {"data": {"sub": "user", "tenant_id": "tenant"}}
                session.get.return_value = me
                cache.return_value.get_value.return_value = None
                values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_slug": "kly",
                          "brew93_tenant_id": "tenant", "request_timeout": 5}
                with patch.object(client.cfg, "get_user_refresh_token", return_value="old"), \
                     patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "exp": 4100752000, "sub": "user"}):
                    client._get_user_crm_token(values, "user@example.com")
            save.assert_called_once_with("user@example.com", "new")

    def test_workspace_refresh_token_is_used_when_user_has_no_connection(self):
        values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_slug": "kly",
                  "brew93_tenant_id": "tenant", "source_site": "site-a", "request_timeout": 5}
        with patch.object(client.cfg, "get_user_refresh_token", return_value=None), \
             patch.object(client.cfg, "get_workspace_refresh_token", return_value="workspace-refresh"):
            with patch.object(client, "_session") as session_factory, \
                 patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "sub": "workspace"}), \
                 patch.object(client, "_validate_remote_identity"), \
                 patch.object(client, "_jwt_ttl", return_value=0):
                response = MagicMock(status_code=200)
                response.json.return_value = {"data": {"access_token": "workspace-access", "expires_in": 600,
                                                        "token_type": "Bearer"}}
                session_factory.return_value.post.return_value = response
                self.assertEqual(client._get_user_crm_token(values, "Administrator"), "workspace-access")
                request = session_factory.return_value.post.call_args
                self.assertEqual(request.kwargs["json"]["refresh_token"], "workspace-refresh")

    def test_user_refresh_token_precedes_workspace_token(self):
        values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_slug": "kly",
                  "brew93_tenant_id": "tenant", "source_site": "site-a", "request_timeout": 5}
        with patch.object(client.cfg, "get_user_refresh_token", return_value="user-refresh"), \
             patch.object(client.cfg, "get_workspace_refresh_token", return_value="workspace-refresh"), \
             patch.object(client, "_session") as session_factory, \
             patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "sub": "user"}), \
             patch.object(client, "_validate_remote_identity"), \
             patch.object(client, "_jwt_ttl", return_value=0):
            response = MagicMock(status_code=200)
            response.json.return_value = {"data": {"access_token": "user-access", "expires_in": 600,
                                                    "token_type": "Bearer"}}
            session_factory.return_value.post.return_value = response
            self.assertEqual(client._get_user_crm_token(values, "user@example.com"), "user-access")
            self.assertEqual(session_factory.return_value.post.call_args.kwargs["json"]["refresh_token"], "user-refresh")

    def test_refresh_cache_is_tenant_scoped(self):
        first = {"source_site": "site-a", "brew93_tenant_id": "tenant-a"}
        second = {"source_site": "site-a", "brew93_tenant_id": "tenant-b"}
        self.assertNotEqual(client._scoped_cache_key("crm", first), client._scoped_cache_key("crm", second))

    def test_service_fallback_requires_explicit_setting_and_no_workspace_token(self):
        values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_id": "tenant",
                  "allow_service_fallback": False}
        with patch.object(client.cfg, "get_user_refresh_token", return_value=None), \
             patch.object(client.cfg, "get_workspace_refresh_token", return_value=None), \
             self.assertRaisesRegex(client.Brew93ConfigError, "user or workspace"):
            client._get_user_crm_token(values, "Administrator")

    def test_user_login_sends_tenant_context_and_returns_refresh_token(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {
            "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDA3NTIwMDB9.sig",
            "refresh_token": "refresh-secret",
            "expires_in": 600,
            "token_type": "Bearer",
        }}
        captured = {}
        def post(*args, **kwargs):
            captured.update(kwargs)
            captured["json"] = dict(kwargs["json"])
            return response
        session.post.side_effect = post
        me = MagicMock(status_code=200)
        me.json.return_value = {"data": {"sub": "user", "tenant_id": "tenant"}}
        session.get.return_value = me
        values = {"brew93_base_url": URL.rsplit("/integrations", 1)[0], "brew93_tenant_slug": "kly",
                  "brew93_tenant_id": "tenant", "request_timeout": 5}
        with patch.object(client, "_session", return_value=session), \
             patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "exp": 4100752000, "sub": "user"}):
            result = client._user_login(values, "user@example.invalid", "never-log-this")
        self.assertEqual(captured["headers"]["x-tenant-slug"], "kly")
        self.assertEqual(captured["json"]["tenant_slug"], "kly")
        self.assertEqual(result["data"]["refresh_token"], "refresh-secret")
        self.assertNotIn("never-log-this", repr(session.mock_calls))

    def test_user_login_rejected_credentials_are_authentication_errors(self):
        for status_code in (400, 401, 403):
            with self.subTest(status_code=status_code):
                session = MagicMock()
                session.post.return_value = MagicMock(status_code=status_code)
                values = {
                    "brew93_base_url": "https://example.invalid",
                    "brew93_tenant_slug": "private-tenant",
                    "request_timeout": 5,
                }

                with patch.object(client, "_session", return_value=session):
                    with self.assertRaises(frappe.AuthenticationError) as raised:
                        client._user_login(values, "real-user@example.invalid", "never-log-this")

                self.assertEqual(str(raised.exception), "Invalid Brew93 email or password.")
                self.assertNotIn("real-user@example.invalid", repr(session.mock_calls))
                self.assertNotIn("never-log-this", repr(session.mock_calls))

    def test_user_login_server_failure_remains_config_error(self):
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=500)
        values = {"brew93_base_url": "https://example.invalid", "request_timeout": 5}

        with patch.object(client, "_session", return_value=session):
            with self.assertRaisesRegex(client.Brew93ConfigError, r"HTTP 500"):
                client._user_login(values, "user@example.invalid", "never-log-this")

    def test_user_login_network_failure_is_config_error(self):
        session = MagicMock()
        error = requests.exceptions.ConnectionError("network down")
        session.post.side_effect = error
        values = {"brew93_base_url": "https://example.invalid", "request_timeout": 5}

        with patch.object(client, "_session", return_value=session):
            with self.assertRaisesRegex(client.Brew93ConfigError, "Brew93 login is unavailable") as raised:
                client._user_login(values, "user@example.invalid", "never-log-this")

        self.assertIs(raised.exception.__cause__, error)
        session.close.assert_called_once_with()

    def test_signs_exact_bytes_and_content_type(self):
        raw = json.dumps({"event_id": "e1", "event_type": "lead.upserted", "data": {"external_id": "L1"}},
                         separators=(",", ":"))
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured.update(url=url, data=data, headers=headers)
            return _Resp()

        session = MagicMock()
        session.post.side_effect = fake_post

        with patch.object(client, "cfg") as cfgm, patch.object(client, "_session", return_value=session):
            cfgm.get_settings.return_value = {"events_url": URL, "request_timeout": 5}
            cfgm.get_hmac_secret.return_value = SECRET
            res = client.post_event(raw, "e1")

        # exact bytes transmitted == the raw body we passed
        self.assertEqual(captured["data"], raw.encode("utf-8"))
        self.assertEqual(captured["headers"]["Content-Type"], "application/json")
        self.assertEqual(captured["headers"][signing.HEADER_EVENT_ID], "e1")

        # signature header == HMAC-SHA256(secret, "{ts}." + exact_bytes_sent)
        ts = captured["headers"][signing.HEADER_TIMESTAMP]
        sig = captured["headers"][signing.HEADER_SIGNATURE].split("=", 1)[1]
        expected = hmac.new(SECRET.encode(), (ts + ".").encode() + captured["data"], hashlib.sha256).hexdigest()
        self.assertEqual(sig, expected)
        self.assertTrue(res.ok)

    def test_missing_secret_raises_config_error(self):
        with patch.object(client, "cfg") as cfgm:
            cfgm.get_settings.return_value = {"events_url": URL, "request_timeout": 5}
            cfgm.get_hmac_secret.return_value = None
            with self.assertRaises(client.Brew93ConfigError):
                client.post_event("{}", "e2")

    def test_outbound_token_does_not_read_legacy_connection_token(self):
        session = MagicMock()
        with patch.object(client, "cfg") as cfgm, patch.object(client.frappe, "cache") as cache:
            cfgm.get_service_password.return_value = "service-secret"
            cfgm.get_connection_token.side_effect = AssertionError("legacy token must not be read")
            cache.return_value.get_value.return_value = None
            cache.return_value.set_value.return_value = None
            response = MagicMock(status_code=200)
            response.json.return_value = {"data": {"access_token": "jwt", "expires_in": 600, "token_type": "Bearer"}}
            session.post.return_value = response
            me = MagicMock(status_code=200)
            me.json.return_value = {"data": {"sub": "service", "tenant_id": "tenant"}}
            session.get.return_value = me
            values = {
                "brew93_base_url": "https://example.invalid/api/v1",
                "service_email": "sync@example.invalid",
                "source_site": "test.local",
                "request_timeout": 5,
            }
            with patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "exp": 4100752000, "sub": "service"}), \
                 patch.object(client, "_assert_tenant"), patch.object(client, "_validate_remote_identity"):
                self.assertEqual(client._get_token(session, values), "jwt")

    def test_service_login_rejects_invalid_signature_before_tenant_check(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"access_token": "invalid", "expires_in": 600, "token_type": "Bearer"}}
        session.post.return_value = response
        values = {"brew93_base_url": URL, "service_email": "service@example.invalid", "request_timeout": 5}
        with patch.object(client.cfg, "get_service_password", return_value="password"), \
             patch.object(client, "_verified_claims", side_effect=client.Brew93ConfigError("Invalid Brew93 JWT")), \
             patch.object(client, "_assert_tenant") as assert_tenant:
            with self.assertRaises(client.Brew93ConfigError):
                client._login(session, values)
        assert_tenant.assert_not_called()

    def test_crm_login_rejects_invalid_signature_before_tenant_check(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"access_token": "invalid", "expires_in": 600, "token_type": "Bearer"}}
        session.post.return_value = response
        values = {"brew93_base_url": URL, "service_email": "service@example.invalid", "request_timeout": 5}
        with patch.object(client, "_session", return_value=session), \
             patch.object(client.cfg, "get_service_password", return_value="password"), \
             patch.object(client, "_verified_claims", side_effect=client.Brew93ConfigError("Invalid Brew93 JWT")), \
             patch.object(client, "_assert_tenant") as assert_tenant:
            with self.assertRaises(client.Brew93ConfigError):
                client.crm_login(values)
        assert_tenant.assert_not_called()

    def test_crm_login_validates_identity_with_auth_me(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"access_token": "access-token", "expires_in": 600, "token_type": "Bearer"}}
        session.post.return_value = response
        me = MagicMock(status_code=200)
        me.json.return_value = {"data": {"sub": "service", "tenant_id": "tenant"}}
        session.get.return_value = me
        values = {"brew93_base_url": "https://example.invalid/api/v1", "brew93_tenant_slug": "kly", "brew93_tenant_id": "tenant",
                  "service_email": "service@example.invalid", "request_timeout": 5}
        with patch.object(client, "_session", return_value=session), \
             patch.object(client.cfg, "get_service_password", return_value="password"), \
             patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "sub": "service"}):
            self.assertEqual(client.crm_login(values), "access-token")
        session.get.assert_called_once_with(
            "https://example.invalid/api/v1/auth/me",
            headers={"Authorization": "Bearer access-token", "x-tenant-slug": "kly"},
            timeout=(5, 5),
        )

    def test_crm_login_fails_closed_on_auth_me_identity_mismatch(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"access_token": "access-token", "expires_in": 600, "token_type": "Bearer"}}
        session.post.return_value = response
        me = MagicMock(status_code=200)
        me.json.return_value = {"data": {"sub": "service", "tenant_id": "other"}}
        session.get.return_value = me
        values = {"brew93_base_url": "https://example.invalid/api/v1", "brew93_tenant_slug": "kly", "brew93_tenant_id": "tenant",
                  "service_email": "service@example.invalid", "request_timeout": 5}
        with patch.object(client, "_session", return_value=session), \
             patch.object(client.cfg, "get_service_password", return_value="password"), \
             patch.object(client, "_verified_claims", return_value={"tenant_id": "tenant", "sub": "service"}):
            with self.assertRaises(client.Brew93ConfigError):
                client.crm_login(values)

    def test_refresh_persists_rotation_even_when_later_validation_fails(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {
            "access_token": "invalid", "refresh_token": "new", "expires_in": 600, "token_type": "Bearer"
        }}
        session.post.return_value = response
        me = MagicMock(status_code=200)
        me.json.return_value = {"data": {"sub": "user", "tenant_id": "tenant"}}
        session.get.return_value = me
        values = {"brew93_base_url": URL, "brew93_tenant_slug": "kly", "brew93_tenant_id": "tenant", "request_timeout": 5}
        with patch.object(client, "_session", return_value=session), \
             patch.object(client.cfg, "get_user_refresh_token", return_value="old"), \
             patch.object(client, "_verified_claims", side_effect=client.Brew93ConfigError("Invalid Brew93 JWT")), \
             patch.object(client.cfg, "set_user_refresh_token") as save, \
             patch.object(client.frappe, "cache") as cache:
            cache.return_value.get_value.return_value = None
            with self.assertRaises(client.Brew93ConfigError):
                client._get_user_crm_token(values, "user@example.com")
        save.assert_called_once_with("user@example.com", "new")
        cache.return_value.set_value.assert_not_called()

    def test_auth_me_tenant_mismatch_fails_closed(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"sub": "user", "tenant_id": "other"}}
        session.get.return_value = response
        values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_slug": "kly",
                  "brew93_tenant_id": "tenant", "request_timeout": 5}
        with self.assertRaises(client.Brew93ConfigError):
            client._validate_remote_identity(session, values, "header.payload.signature",
                                             {"sub": "user", "tenant_id": "tenant"})

    def test_auth_me_missing_tenant_fails_closed(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"sub": "user", "email_verified": True}}
        session.get.return_value = response
        values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_slug": "kly",
                  "brew93_tenant_id": "tenant", "request_timeout": 5}
        with self.assertRaises(client.Brew93ConfigError):
            client._validate_remote_identity(session, values, "header.payload.signature",
                                              {"sub": "user", "tenant_id": "tenant"})

    def test_auth_me_is_authenticated_with_bearer_and_tenant_header(self):
        session = MagicMock()
        response = MagicMock(status_code=200)
        response.json.return_value = {"data": {"sub": "user", "tenant_id": "tenant", "email_verified": True}}
        session.get.return_value = response
        values = {"brew93_base_url": "https://example.invalid", "brew93_tenant_slug": "kly",
                  "brew93_tenant_id": "tenant", "request_timeout": 5}
        client._validate_remote_identity(session, values, "access-token",
                                         {"sub": "user", "tenant_id": "tenant"})
        kwargs = session.get.call_args.kwargs
        self.assertEqual(kwargs["headers"], {"Authorization": "Bearer access-token", "x-tenant-slug": "kly"})


if __name__ == "__main__":
    unittest.main()
