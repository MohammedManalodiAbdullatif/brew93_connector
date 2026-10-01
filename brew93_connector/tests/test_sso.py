# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""DB-backed tests for the hardened SSO mapping (Phase 7).

Exercises the security guards directly (tenant pin, stable-id match, email
bootstrap, verified-email, privileged refusal, auto-create) without needing a
web login_manager. Everything stays disabled on the site.
"""

import uuid
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import frappe
from frappe.tests.utils import FrappeTestCase

from brew93_connector.api import settings
from brew93_connector.api import sso

TENANT = "00000000-0000-0000-0000-000000000000"
# Distinctive first_name so the Contact that Frappe auto-creates for each test
# User can be cleaned up unambiguously (User creation commits, escaping rollback).
MARKER = "Brew93SSOTestArtifact"
VALUES = {
    "brew93_base_url": "https://example.invalid/api/v1",
    "brew93_tenant_id": TENANT,
    "brew93_tenant_slug": "kly",
}


def _mk_user(roles=None, brew93_user_id=None, user_type="System User"):
    email = f"sso-{uuid.uuid4().hex[:10]}@example.com"
    d = frappe.new_doc("User")
    d.email = email
    d.first_name = MARKER
    d.send_welcome_email = 0
    d.user_type = user_type
    if brew93_user_id:
        d.brew93_user_id = brew93_user_id
    for r in roles or []:
        d.append("roles", {"role": r})
    d.flags.ignore_permissions = True
    d.insert(ignore_permissions=True)
    frappe.db.set_value("User", d.name, "user_type", user_type)
    return d.name


class TestSSOGuards(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")

    def tearDown(self):
        # Safety net: creating a User commits and also spawns a Contact, both of
        # which escape the test rollback. Remove every test artifact.
        for u in frappe.get_all("User", filters={"email": ["like", "sso-%@example.com"]}, pluck="name"):
            frappe.delete_doc("User", u, ignore_permissions=True, force=True)
        for c in frappe.get_all("Contact", filters={"first_name": MARKER}, pluck="name"):
            frappe.delete_doc("Contact", c, ignore_permissions=True, force=True)
        frappe.db.commit()

    def test_tenant_pin(self):
        sso._assert_tenant({"tenant_id": TENANT}, TENANT)  # ok, no raise
        with self.assertRaises(frappe.AuthenticationError):
            sso._assert_tenant({"tenant_id": "some-other-tenant"}, TENANT)

    def test_stable_id_match_ignores_email(self):
        sub = str(uuid.uuid4())
        user = _mk_user(brew93_user_id=sub)
        # email in the claim is different/irrelevant; match is by id
        got = sso._resolve_user({"sub": sub, "email": "unrelated@x.com"}, VALUES)
        self.assertEqual(got, user)

    def test_email_bootstrap_stamps_id(self):
        user = _mk_user()
        email = frappe.db.get_value("User", user, "email")
        sub = str(uuid.uuid4())
        got = sso._resolve_user({"sub": sub, "email": email}, VALUES)
        self.assertEqual(got, user)
        self.assertEqual(frappe.db.get_value("User", user, "brew93_user_id"), sub)  # linked for next time

    def test_unverified_email_refused(self):
        with self.assertRaises(frappe.AuthenticationError):
            sso._resolve_user({"sub": str(uuid.uuid4()), "email": "x@y.com", "email_verified": False}, VALUES)

    def test_unknown_user_autocreate_off_refused(self):
        with self.assertRaises(frappe.AuthenticationError):
            sso._resolve_user({"sub": str(uuid.uuid4()), "email": f"nobody-{uuid.uuid4().hex}@x.com"}, VALUES)

    def test_administrator_refused(self):
        with self.assertRaises(frappe.AuthenticationError):
            sso._refuse_privileged("Administrator")

    def test_system_manager_refused(self):
        user = _mk_user(roles=["System Manager"])
        with self.assertRaises(frappe.AuthenticationError):
            sso._refuse_privileged(user)

    def test_email_match_onto_system_manager_is_refused_not_linked(self):
        user = _mk_user(roles=["System Manager"])
        email = frappe.db.get_value("User", user, "email")
        with self.assertRaises(frappe.AuthenticationError):
            sso._resolve_user({"sub": str(uuid.uuid4()), "email": email}, VALUES)
        # must NOT have been stamped
        self.assertFalse(frappe.db.get_value("User", user, "brew93_user_id"))

    def test_login_refused_when_disabled(self):
        with patch("brew93_connector.api.sso.cfg.sso_enabled", return_value=False):
            with self.assertRaises(frappe.AuthenticationError):
                sso.login("a@b.com", "pw")

    def test_login_propagates_safe_invalid_credentials_error(self):
        values = dict(VALUES, brew93_tenant_slug="klyonix")
        auth_error = frappe.AuthenticationError("Invalid Brew93 email or password.")
        with patch("brew93_connector.api.sso.cfg.sso_enabled", return_value=True), \
             patch("brew93_connector.api.sso.cfg.get_settings", return_value=values), \
             patch("brew93_connector.api.sso.client.brew93_user_authenticate", side_effect=auth_error):
            with self.assertRaises(frappe.AuthenticationError) as raised:
                sso.login("user@example.com", "never-log-this")
        self.assertEqual(str(raised.exception), "Invalid Brew93 email or password.")

    def test_sso_page_predicate_requires_switch_and_tenant_configuration(self):
        with patch.object(settings, "_doc", return_value=frappe._dict(
            sso_enabled=0,
            brew93_base_url="https://brew93.example",
            brew93_tenant_id=TENANT,
        )):
            self.assertFalse(settings.sso_is_enabled_and_configured())

        with patch.object(settings, "_doc", return_value=frappe._dict(
            sso_enabled=1,
            brew93_base_url="https://brew93.example",
            brew93_tenant_id=TENANT,
            brew93_tenant_slug="kly",
        )):
            self.assertTrue(settings.sso_is_enabled_and_configured())

    def test_disabled_user_refused(self):
        user = _mk_user()
        frappe.db.set_value("User", user, "enabled", 0)
        with self.assertRaises(frappe.AuthenticationError):
            sso._refuse_disabled(user)

    def test_sales_user_is_eligible_for_login(self):
        user = _mk_user(roles=["Sales User"])
        sso._refuse_ineligible(user)

    def test_system_user_with_lead_permission_is_eligible_regardless_of_role_name(self):
        user = _mk_user(roles=["Sales Manager"])
        sso._refuse_ineligible(user)

    def test_system_user_is_eligible_with_all_lead_permissions(self):
        user = _mk_user()
        with patch("brew93_connector.api.sso.frappe.has_permission", return_value=True) as has_permission:
            sso._refuse_ineligible(user)
        self.assertEqual(
            [call.args[1] for call in has_permission.call_args_list],
            ["read", "create", "write"],
        )

    def test_website_user_is_refused(self):
        user = _mk_user(user_type="Website User")
        with self.assertRaises(frappe.AuthenticationError):
            sso._refuse_ineligible(user)

    def test_system_user_missing_any_lead_permission_is_refused(self):
        for missing in ("read", "create", "write"):
            with self.subTest(missing=missing):
                user = _mk_user()

                def has_permission(doctype, ptype, user):
                    return ptype != missing

                with patch("brew93_connector.api.sso.frappe.has_permission", side_effect=has_permission):
                    with self.assertRaises(frappe.AuthenticationError):
                        sso._refuse_ineligible(user)

    def test_email_bootstrap_cannot_relink_user_bound_to_other_brew93_account(self):
        original = str(uuid.uuid4())
        user = _mk_user(brew93_user_id=original)
        email = frappe.db.get_value("User", user, "email")
        with self.assertRaises(frappe.AuthenticationError):
            sso._resolve_user({"sub": str(uuid.uuid4()), "email": email}, VALUES)
        self.assertEqual(frappe.db.get_value("User", user, "brew93_user_id"), original)

    def test_legacy_login_endpoint_is_routed_to_hardened_login(self):
        self.assertEqual(
            frappe.override_whitelisted_method("brew93_ai.brew93_sso.auth.login"),
            "brew93_connector.api.sso.login",
        )
        # Through the real API dispatcher: the legacy (email-only) client is never reached.
        form = frappe._dict(cmd="brew93_ai.brew93_sso.auth.login", email="a@b.com", password="pw", workspace="any")
        with patch.object(frappe.local, "form_dict", form), \
             patch.object(frappe.local, "request", frappe._dict(method="POST"), create=True), \
             patch.object(frappe.local, "request_ip", "127.0.0.1", create=True), \
             patch("brew93_connector.api.sso.cfg.sso_enabled", return_value=False), \
             patch("brew93_ai.brew93_sso.auth.login") as legacy_login:
            with self.assertRaises(frappe.AuthenticationError):
                frappe.handler.execute_cmd("brew93_ai.brew93_sso.auth.login")
            legacy_login.assert_not_called()

    # --- full login() flow with Brew93 mocked -------------------------------
    def _run_login(self, claims, login_manager):
        vals = dict(VALUES, brew93_tenant_slug="klyonix")
        with patch("brew93_connector.api.sso.cfg.sso_enabled", return_value=True), \
             patch("brew93_connector.api.sso.cfg.get_settings", return_value=vals), \
             patch("brew93_connector.api.sso.client.brew93_user_authenticate", return_value={
                 "claims": claims, "refresh_token": "test-refresh-token"
             }) as brew93, \
             patch.object(frappe.local, "login_manager", login_manager, create=True):
            try:
                return sso.login(claims.get("email", "x@example.com"), "pw", workspace="attacker-chosen")
            finally:
                # the visitor-typed workspace is ignored; the configured slug is used
                self.assertEqual(brew93.call_args.args[1:], (claims.get("email", "x@example.com"), "pw"))

    def test_login_success_starts_session_for_linked_user(self):
        from unittest.mock import MagicMock

        sub = str(uuid.uuid4())
        user = _mk_user(roles=["Sales User"], brew93_user_id=sub)  # desk role => System User
        lm = MagicMock()
        out = self._run_login({"sub": sub, "tenant_id": TENANT, "email": "whatever@example.com"}, lm)
        self.assertEqual(out, {"success": True, "user": user, "redirect_to": "/app"})
        lm.login_as.assert_called_once_with(user)

    def test_login_persists_refresh_token_through_password_api(self):
        from unittest.mock import MagicMock
        sub = str(uuid.uuid4())
        user = _mk_user(roles=["Sales User"], brew93_user_id=sub)
        lm = MagicMock()
        with patch("brew93_connector.api.sso.cfg.set_user_refresh_token") as save, \
             patch("brew93_connector.api.sso.cfg.sso_enabled", return_value=True), \
             patch("brew93_connector.api.sso.cfg.get_settings", return_value=dict(VALUES, brew93_tenant_slug="kly")), \
             patch("brew93_connector.api.sso.client.brew93_user_authenticate", return_value={
                 "claims": {"sub": sub, "tenant_id": TENANT, "email": "whatever@example.com"},
                 "refresh_token": "refresh-secret",
             }), patch.object(frappe.local, "login_manager", lm, create=True):
            sso.login("whatever@example.com", "pw")
        save.assert_called_once_with(user, "refresh-secret")

    def test_refresh_token_helper_uses_password_field_save(self):
        meta = MagicMock()
        meta.has_field.return_value = True
        with patch.object(settings.frappe, "get_meta", return_value=meta), \
             patch.object(settings, "set_encrypted_password") as set_password, \
             patch.object(settings.frappe, "get_doc") as get_doc:
            settings.set_user_refresh_token("user@example.com", "refresh-secret")
        set_password.assert_called_once_with(
            "User", "user@example.com", "refresh-secret", "brew93_refresh_token"
        )
        get_doc.assert_not_called()

    def test_user_token_helpers_are_safe_before_custom_fields_install(self):
        meta = MagicMock()
        meta.has_field.return_value = False
        with patch.object(settings.frappe, "get_meta", return_value=meta), \
             patch.object(settings, "set_encrypted_password") as set_password, \
             patch.object(settings.frappe, "get_doc") as get_doc:
            settings.set_user_refresh_token("user@example.com", "refresh-secret")
            self.assertIsNone(settings.get_user_refresh_token("user@example.com"))
        set_password.assert_not_called()
        get_doc.assert_not_called()

    def test_connection_status_redacts_tokens(self):
        meta = MagicMock()
        meta.has_field.return_value = True
        with patch.object(settings.frappe, "get_meta", return_value=meta), \
             patch.object(settings.frappe, "get_settings", create=True), \
             patch.object(settings, "get_settings", return_value={"brew93_tenant_id": TENANT}), \
             patch.object(settings.frappe.db, "get_value", return_value={
                 "brew93_tenant_id": TENANT, "brew93_connection_status": "Connected"
             }), patch.object(settings, "get_user_refresh_token", return_value="secret-refresh-token"):
            with patch.dict(settings.frappe.session, {"user": "user@example.com"}):
                result = settings.get_connection_status()
        self.assertEqual(result, {"connected": True, "status": "Connected", "tenant_id": TENANT})
        self.assertNotIn("secret-refresh-token", result)

    def test_login_refuses_other_tenant_without_session(self):
        from unittest.mock import MagicMock

        sub = str(uuid.uuid4())
        _mk_user(brew93_user_id=sub)
        lm = MagicMock()
        with self.assertRaises(frappe.AuthenticationError):
            self._run_login({"sub": sub, "tenant_id": "another-tenant", "email": "x@example.com"}, lm)
        lm.login_as.assert_not_called()

    def test_login_refuses_system_manager_linked_by_id(self):
        from unittest.mock import MagicMock

        sub = str(uuid.uuid4())
        _mk_user(roles=["System Manager"], brew93_user_id=sub)
        lm = MagicMock()
        with self.assertRaises(frappe.AuthenticationError):
            self._run_login({"sub": sub, "tenant_id": TENANT, "email": "x@example.com"}, lm)
        lm.login_as.assert_not_called()

    def test_login_refuses_administrator(self):
        lm = MagicMock()
        with patch.object(sso, "_resolve_user", return_value="Administrator"), \
             patch.object(sso.client, "brew93_user_authenticate", return_value={
                 "claims": {"sub": str(uuid.uuid4()), "tenant_id": TENANT},
                 "refresh_token": "refresh-secret",
             }), \
             patch.object(sso.cfg, "sso_enabled", return_value=True), \
             patch.object(sso.cfg, "get_settings", return_value=VALUES), \
             patch.object(frappe.local, "login_manager", lm, create=True):
            with self.assertRaises(frappe.AuthenticationError):
                sso.login("administrator@example.com", "password")
        lm.login_as.assert_not_called()

    def test_workspace_link_is_admin_only_and_does_not_store_login_secrets(self):
        auth = {
            "claims": {"sub": "brew-user-1", "tenant_id": TENANT, "email": "admin@brew93.test"},
            "identity": {"sub": "brew-user-1", "tenant_id": TENANT, "workspace_slug": "kly"},
            "refresh_token": "refresh-secret",
        }
        settings_doc = MagicMock(name="Brew93 Connector Settings")
        settings_doc.name = "Brew93 Connector Settings"
        with patch.object(frappe.local, "session", frappe._dict(user="Sales User")), \
             patch.object(frappe, "get_roles", return_value=["Sales User"]):
            with self.assertRaises(frappe.PermissionError):
                settings.link_workspace("https://brew93.test", "kly", "admin@brew93.test", "password")

        with patch.object(frappe.local, "session", frappe._dict(user="Administrator")), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", return_value=auth) as authenticate, \
             patch.object(settings, "set_encrypted_password") as encrypt, \
             patch.object(settings_doc, "db_set") as db_set:
            result = settings.link_workspace("https://brew93.test", "kly", "admin@brew93.test", "password")

        authenticate.assert_called_once_with(
            {"brew93_base_url": "https://brew93.test/api/v1", "brew93_tenant_slug": "kly", "request_timeout": 10},
            "admin@brew93.test", "password",
        )
        encrypt.assert_called_once_with(
            settings.SETTINGS_DOCTYPE, settings_doc.name, "refresh-secret", "brew93_refresh_token"
        )
        stored = repr(db_set.call_args)
        self.assertNotIn("password", stored)
        self.assertNotIn("access_token", stored)
        self.assertEqual(result["tenant_id"], TENANT)

    def test_workspace_link_uses_canonical_default_when_url_is_omitted(self):
        auth = {
            "claims": {"sub": "brew-user-1", "tenant_id": TENANT, "email": "admin@brew93.test"},
            "identity": {"sub": "brew-user-1", "tenant_id": TENANT, "workspace_slug": "kly"},
            "refresh_token": "refresh-secret",
        }
        settings_doc = MagicMock(name="Brew93 Connector Settings")
        settings_doc.name = "Brew93 Connector Settings"
        with patch.object(frappe.local, "session", frappe._dict(user="Administrator")), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "set_encrypted_password"), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", return_value=auth) as authenticate, \
             patch.object(settings_doc, "db_set"):
            settings.link_workspace(None, "kly", "admin@brew93.test", "password")
        self.assertEqual(authenticate.call_args.args[0]["brew93_base_url"], settings.DEFAULT_BREW93_BASE_URL)

    def test_setup_connector_registers_server_side_credentials_only(self):
        settings_doc = MagicMock(name="Brew93 Connector Settings")
        settings_doc.name = "Brew93 Connector Settings"
        settings_doc.get.side_effect = lambda field: {
            "enabled": 0, "brew93_tenant_id": TENANT, "brew93_tenant_slug": "kly",
        }.get(field)
        auth = {"claims": {"sub": "brew-user-1", "tenant_id": TENANT, "email": "admin@brew93.test"},
                "identity": {"sub": "brew-user-1", "tenant_id": TENANT, "workspace_slug": "kly"},
                "refresh_token": "refresh-secret"}
        credentials = {"user": "brew93-integration@rag.klyonix.in", "api_key": "api-key", "api_secret": "api-secret"}
        with patch.object(frappe.local, "session", frappe._dict(user="Administrator")), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "set_encrypted_password"), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", return_value=auth), \
             patch("brew93_connector.setup.integration_user.ensure_integration_credentials", return_value=credentials), \
             patch("brew93_connector.api.client.register_frappe_integration") as register:
            result = settings.setup_connector("https://brew93.test", "kly", "admin@brew93.test", "password")

        register.assert_called_once()
        self.assertEqual(register.call_args.args[1:], ("api-key", "api-secret"))
        self.assertNotIn("api-secret", repr(result))
        self.assertEqual(result["tenant_id"], TENANT)
        registered_values = register.call_args.args[0]
        self.assertEqual(registered_values["brew93_base_url"], "https://brew93.test/api/v1")

    def test_setup_connector_preserves_current_frappe_session(self):
        settings_doc = MagicMock(name="Brew93 Connector Settings")
        settings_doc.name = "Brew93 Connector Settings"
        settings_doc.get.side_effect = lambda field: {"enabled": 0}.get(field)
        auth = {
            "claims": {"sub": "brew-user-1", "tenant_id": TENANT, "email": "admin@brew93.test"},
            "identity": {"sub": "brew-user-1", "tenant_id": TENANT, "workspace_slug": "kly"},
            "refresh_token": "refresh-secret",
        }
        login_manager = MagicMock(user="Administrator")
        session = frappe._dict(user="Administrator", sid="current-sid", data={"marker": "current"})
        with patch.object(frappe.local, "session", session), \
             patch.object(frappe.local, "login_manager", login_manager, create=True), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "set_encrypted_password"), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", return_value=auth), \
             patch("brew93_connector.setup.integration_user.ensure_integration_credentials", return_value={"user": "u", "api_key": "k", "api_secret": "s"}), \
             patch("brew93_connector.api.client.register_frappe_integration"):
            settings.setup_connector("https://brew93.test", "kly", "admin@brew93.test", "password")

        self.assertEqual(session.user, "Administrator")
        self.assertEqual(session.sid, "current-sid")
        self.assertEqual(session.data, {"marker": "current"})
        self.assertEqual(login_manager.user, "Administrator")
        login_manager.login_as.assert_not_called()
        login_manager.logout.assert_not_called()

    def test_setup_connector_preserves_current_frappe_session_on_failure(self):
        session = frappe._dict(user="System Manager", sid="current-sid", data={"marker": "current"})
        login_manager = MagicMock(user="System Manager")
        with patch.object(frappe.local, "session", session), \
             patch.object(frappe, "get_roles", return_value=["System Manager"]), \
             patch.object(frappe.local, "login_manager", login_manager, create=True), \
             patch.object(settings, "_link_workspace", side_effect=RuntimeError("Brew93 unavailable")):
            with self.assertRaises(RuntimeError):
                settings.setup_connector("https://brew93.test", "kly", "admin@brew93.test", "password")

        self.assertEqual(session.user, "System Manager")
        self.assertEqual(session.sid, "current-sid")
        self.assertEqual(session.data, {"marker": "current"})
        self.assertEqual(login_manager.user, "System Manager")
        login_manager.login_as.assert_not_called()
        login_manager.logout.assert_not_called()

    def test_setup_connector_auth_failure_raises_validation_error_to_preserve_session(self):
        auth_err = frappe.AuthenticationError("Invalid Brew93 email or password.")
        with patch.object(frappe.local, "session", frappe._dict(user="Administrator")), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", side_effect=auth_err):
            with self.assertRaises(frappe.ValidationError):
                settings._link_workspace("https://brew93.test", "kly", "admin@brew93.test", "bad-pass")

    def test_setup_connector_preserves_response_and_nested_session_state(self):
        settings_doc = MagicMock(name="Brew93 Connector Settings")
        settings_doc.name = "Brew93 Connector Settings"
        settings_doc.get.side_effect = lambda field: {"enabled": 0}.get(field)
        auth = {
            "claims": {"sub": "brew-user-1", "tenant_id": TENANT, "email": "admin@brew93.test"},
            "identity": {"sub": "brew-user-1", "tenant_id": TENANT, "workspace_slug": "kly"},
            "refresh_token": "refresh-secret",
        }
        session = frappe._dict(user="System Manager", sid="current-sid", data={"marker": {"keep": True}})
        response = {"home_page": "/app", "cookies": [{"name": "sid", "value": "current"}]}
        with patch.object(frappe.local, "session", session), \
             patch.object(frappe, "get_roles", return_value=["System Manager"]), \
             patch.object(frappe.local, "response", response, create=True), \
             patch.object(frappe.local, "login_manager", MagicMock(user="System Manager"), create=True), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "set_encrypted_password"), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", return_value=auth), \
             patch("brew93_connector.setup.integration_user.ensure_integration_credentials", return_value={"user": "u", "api_key": "k", "api_secret": "s"}), \
             patch("brew93_connector.api.client.register_frappe_integration"):
            settings.setup_connector("https://brew93.test", "kly", "admin@brew93.test", "password")

        self.assertEqual(session.data, {"marker": {"keep": True}})
        self.assertEqual(response, {"home_page": "/app", "cookies": [{"name": "sid", "value": "current"}]})

    def test_setup_status_allows_system_manager_without_exposing_secrets(self):
        settings_doc = MagicMock()
        settings_doc.get.side_effect = lambda field: {
            "enabled": 1,
            "brew93_connection_status": "Connected",
            "brew93_tenant_id": TENANT,
            "brew93_tenant_slug": "kly",
        }.get(field)
        with patch.object(frappe.local, "session", frappe._dict(user="System Manager")), \
             patch.object(frappe, "get_roles", return_value=["System Manager"]), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "get_workspace_refresh_token", return_value="refresh-secret"), \
             patch("brew93_connector.api.constants.INTEGRATION_USER", "integration@example.com"), \
             patch.object(frappe.db, "exists", return_value=False):
            result = settings.get_setup_status()

        self.assertEqual(result["status"], "Connected")
        self.assertNotIn("refresh-secret", repr(result))

    def test_setup_status_does_not_redirect_or_replace_response(self):
        settings_doc = MagicMock()
        settings_doc.get.side_effect = lambda field: {"enabled": 0}.get(field)
        response = {"home_page": "/app", "cookies": [{"name": "sid", "value": "current"}]}
        with patch.object(frappe.local, "session", frappe._dict(user="Administrator")), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "get_workspace_refresh_token", return_value=None), \
             patch.object(frappe.db, "exists", return_value=False), \
             patch.object(frappe.local, "response", response, create=True):
            result = settings.get_setup_status()

        self.assertFalse(result["connected"])
        self.assertEqual(response, {"home_page": "/app", "cookies": [{"name": "sid", "value": "current"}]})
        self.assertFalse(getattr(frappe.local.flags, "redirect_location", None))

    def test_setup_page_does_not_auto_login_on_load(self):
        page = Path(__file__).parents[1] / "brew93_connector/page/brew93_integration/brew93_integration.js"
        source = page.read_text()
        load_body = source.split("page.set_primary_action", 1)[0]
        self.assertNotIn("api.sso.login", load_body)
        self.assertNotIn("login_as", load_body)
        self.assertNotIn("setup_connector", load_body)

    def test_setup_resolves_canonical_tenant_id_from_authenticated_identity(self):
        settings_doc = MagicMock(name="Brew93 Connector Settings")
        settings_doc.name = "Brew93 Connector Settings"
        settings_doc.get.side_effect = lambda field: {
            "brew93_base_url": "https://brew93.test/api/v1",
            "brew93_tenant_id": None,
            "brew93_tenant_slug": "kly",
            "request_timeout": 30,
        }.get(field)
        auth = {
            "claims": {"sub": "brew-user-1"},
            "identity": {"sub": "brew-user-1", "tenant_id": TENANT, "workspace_slug": "kly"},
            "refresh_token": "refresh-secret",
        }
        with patch.object(frappe.local, "session", frappe._dict(user="Administrator")), \
             patch.object(settings, "_doc", return_value=settings_doc), \
             patch.object(settings, "set_encrypted_password"), \
             patch("brew93_connector.api.client.brew93_workspace_authenticate", return_value=auth), \
             patch("brew93_connector.setup.integration_user.ensure_integration_credentials", return_value={"user": "u", "api_key": "k", "api_secret": "s"}), \
             patch("brew93_connector.api.client.register_frappe_integration"):
            result = settings.setup_connector("https://brew93.test", "kly", "admin@brew93.test", "password")
        stored = settings_doc.db_set.call_args_list[0].args[0]
        self.assertEqual(stored["brew93_tenant_id"], TENANT)
        self.assertEqual(result["tenant_id"], TENANT)

    def test_setup_does_not_accept_a_user_supplied_tenant_id(self):
        with self.assertRaises(TypeError):
            settings.setup_connector("https://brew93.test", TENANT, "kly", "admin@brew93.test", "password")

    def test_setup_connector_allows_system_manager_but_link_workspace_remains_admin_only(self):
        with patch.object(frappe.local, "session", frappe._dict(user="System Manager")), \
             patch.object(frappe, "get_roles", return_value=["System Manager"]):
            settings._require_system_manager()
            with self.assertRaises(frappe.PermissionError):
                settings._require_setup_admin()

    def test_login_refuses_disabled_user(self):
        from unittest.mock import MagicMock

        sub = str(uuid.uuid4())
        user = _mk_user(brew93_user_id=sub)
        frappe.db.set_value("User", user, "enabled", 0)
        lm = MagicMock()
        with self.assertRaises(frappe.AuthenticationError):
            self._run_login({"sub": sub, "tenant_id": TENANT, "email": "x@example.com"}, lm)
        lm.login_as.assert_not_called()
