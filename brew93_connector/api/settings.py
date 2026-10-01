# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Typed accessor for `Brew93 Connector Settings` with site_config precedence.

Secrets (service password, HMAC secret) are read from `site_config.json` when
present, else from the encrypted Password fields on the single DocType. They are
never returned in bulk dicts, never cached in plaintext, and never logged.
"""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager

import frappe
from frappe.utils.password import set_encrypted_password
from urllib.parse import urlsplit, urlunsplit
import re

SETTINGS_DOCTYPE = "Brew93 Connector Settings"
DEFAULT_BREW93_BASE_URL = "https://mcp.brew93.com/api/v1"


def normalize_base_url(value: str | None = None) -> str:
    """Return a Brew93 API root, accepting legacy and human-friendly forms."""
    raw = (value or DEFAULT_BREW93_BASE_URL).strip() or DEFAULT_BREW93_BASE_URL
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Brew93 API URL must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Brew93 API URL must not contain credentials, query, or fragment")
    path = re.sub(r"(?:/api/v1)+/?$", "", parsed.path.rstrip("/"), flags=re.IGNORECASE)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.rstrip("/"), (path or "") + "/api/v1", "", ""))

# Non-secret fields safe to expose to diagnostics/UI.
PUBLIC_FIELDS = (
    "enabled",
    "brew93_base_url",
    "brew93_tenant_id",
    "brew93_tenant_slug",
    "source_site",
    "service_email",
    "request_timeout",
    "max_retries",
    "retry_backoff_base",
    "max_backoff_seconds",
    "events_enabled",
    "events_url",
    "sso_enabled",
    "allow_service_fallback",
    "brew93_connection_status",
    "brew93_connected_user_id",
    "brew93_connected_username",
)


def _doc():
    return frappe.get_cached_doc(SETTINGS_DOCTYPE)


def get_settings() -> dict:
    """Return the non-secret settings as a plain dict."""
    doc = _doc()
    values = {f: doc.get(f) for f in PUBLIC_FIELDS}
    values["enabled"] = bool(values.get("enabled"))
    values["events_enabled"] = bool(values.get("events_enabled"))
    values["brew93_base_url"] = normalize_base_url(values.get("brew93_base_url"))
    values["events_url"] = (values.get("events_url") or "").rstrip("/")
    values["source_site"] = (values.get("source_site") or frappe.local.site or "").strip()
    values["request_timeout"] = int(values.get("request_timeout") or 30)
    values["max_retries"] = int(values.get("max_retries") or 5)
    values["retry_backoff_base"] = float(values.get("retry_backoff_base") or 2.0)
    values["max_backoff_seconds"] = int(values.get("max_backoff_seconds") or 3600)
    return values


def is_enabled() -> bool:
    return bool(_doc().get("enabled"))


def events_enabled() -> bool:
    doc = _doc()
    return bool(doc.get("enabled")) and bool(doc.get("events_enabled"))


def sso_enabled() -> bool:
    # SSO has its own switch; independent of the data-sync `enabled` master flag.
    return bool(_doc().get("sso_enabled"))


@frappe.whitelist(allow_guest=True)
def sso_is_enabled_and_configured() -> bool:
    """Return whether the hardened connector SSO is ready for public login."""
    values = get_settings()
    return bool(values.get("sso_enabled") and values.get("brew93_base_url") and
                values.get("brew93_tenant_id") and values.get("brew93_tenant_slug"))


def _require_setup_admin() -> None:
    user = frappe.session.user
    if user == "Administrator":
        return
    frappe.throw(frappe._("Only the ERPNext Administrator can link Brew93."), frappe.PermissionError)


def _require_system_manager() -> None:
    user = frappe.session.user
    if user == "Administrator" or "System Manager" in frappe.get_roles(user):
        return
    frappe.throw(frappe._("Only a System Manager can configure Brew93."), frappe.PermissionError)


@contextmanager
def _preserve_frappe_session():
    """Keep setup side effects from changing the caller's Frappe session."""
    session = frappe.local.session
    session_state = {
        key: deepcopy(getattr(session, key, None))
        for key in ("user", "sid", "data")
    }
    response = getattr(frappe.local, "response", None)
    response_state = deepcopy(response) if isinstance(response, dict) else None
    login_manager = getattr(frappe.local, "login_manager", None)
    login_manager_user = getattr(login_manager, "user", None)
    try:
        yield
    finally:
        for key, value in session_state.items():
            setattr(session, key, value)
        if login_manager is not None:
            login_manager.user = login_manager_user
        if response_state is not None and response is getattr(frappe.local, "response", None):
            response.clear()
            response.update(deepcopy(response_state))


@frappe.whitelist(methods=["POST"])
def link_workspace(base_url=None, workspace_slug=None, username=None, password=None) -> dict:
    """Verify and link Brew93, retaining only encrypted refresh-token material."""
    _require_setup_admin()
    return _link_workspace(base_url, workspace_slug, username, password)


def _link_workspace(base_url=None, workspace_slug=None, username=None, password=None) -> dict:
    """Perform the server-side link after the caller has authorized setup."""
    if not all((workspace_slug, username, password)):
        frappe.throw(frappe._("Brew93 workspace, login, and password are required."))
    try:
        base_url = normalize_base_url(base_url)
    except ValueError:
        frappe.throw(frappe._("Brew93 API URL is invalid."))

    values = {
        "brew93_base_url": base_url,
        "brew93_tenant_slug": workspace_slug.strip(),
        "request_timeout": 10,
    }
    from brew93_connector.api import client

    try:
        auth = client.brew93_workspace_authenticate(values, username.strip(), password)
    except frappe.AuthenticationError as exc:
        frappe.throw(
            exc.args[0] if exc.args else frappe._("Invalid Brew93 email or password."),
            frappe.ValidationError,
        )
    except Exception:
        frappe.throw(frappe._("Brew93 workspace verification failed. Check the URL, tenant, workspace, and credentials."))
    finally:
        password = None

    claims = auth["claims"]
    identity = auth.get("identity") or {}
    workspace = identity.get("workspace") if isinstance(identity.get("workspace"), dict) else {}
    tenant_id = (identity.get("tenant_id") or identity.get("tenantId") or
                 workspace.get("tenant_id") or workspace.get("tenantId"))
    if not tenant_id:
        frappe.throw(frappe._("Brew93 did not return a canonical tenant ID."))
    if not claims.get("sub") and not claims.get("user_id"):
        frappe.throw(frappe._("Brew93 did not return a stable user ID."))
    refresh_token = auth.get("refresh_token")
    if not refresh_token:
        frappe.throw(frappe._("Brew93 did not return a refresh token."))

    doc = _doc()
    doc.db_set({
        "brew93_base_url": values["brew93_base_url"],
        "brew93_tenant_id": str(tenant_id),
        "brew93_tenant_slug": values["brew93_tenant_slug"],
        "brew93_connection_status": "Connected",
        "brew93_connected_user_id": claims.get("sub") or claims.get("user_id"),
        "brew93_connected_username": (claims.get("email") or username).strip().lower(),
        "sso_enabled": 1,
    })
    set_encrypted_password(SETTINGS_DOCTYPE, doc.name, refresh_token, "brew93_refresh_token")
    return {
        "connected": True,
        "tenant_id": str(tenant_id),
        "workspace_slug": values["brew93_tenant_slug"],
        "username": (claims.get("email") or username).strip().lower(),
    }


@frappe.whitelist(methods=["POST"])
def setup_connector(base_url=None, workspace_slug=None, username=None, password=None) -> dict:
    """Complete the guided two-way setup without exposing ERPNext credentials."""
    _require_system_manager()
    with _preserve_frappe_session():
        linked = _link_workspace(base_url, workspace_slug, username, password)
        from brew93_connector.setup.integration_user import ensure_integration_credentials
        from brew93_connector.api import client

        credentials = ensure_integration_credentials()
        values = get_settings()
        values.update({
            "brew93_base_url": normalize_base_url(base_url),
            "brew93_tenant_id": linked["tenant_id"],
            "brew93_tenant_slug": workspace_slug.strip(),
            "request_timeout": 10,
        })
        try:
            client.register_frappe_integration(values, credentials["api_key"], credentials["api_secret"])
        except Exception:
            pass
        doc = _doc()
        doc.db_set({"enabled": 1, "sso_enabled": 1, "brew93_connection_status": "Connected"})
        return {
            "connected": True,
            "enabled": True,
            "tenant_id": linked["tenant_id"],
            "workspace_slug": linked["workspace_slug"],
            "integration_user": credentials["user"],
        }


@frappe.whitelist()
def get_setup_status() -> dict:
    """Return setup metadata only; credential material never leaves the server."""
    _require_system_manager()
    from brew93_connector.api.constants import INTEGRATION_USER
    configured = bool(_doc().get("enabled") and get_workspace_refresh_token())
    user_exists = bool(frappe.db.exists("User", INTEGRATION_USER))
    has_credentials = bool(
        user_exists
        and frappe.db.get_value("User", INTEGRATION_USER, "api_key")
        and frappe.get_doc("User", INTEGRATION_USER).get_password("api_secret", raise_exception=False)
    )
    return {
        "connected": configured,
        "status": _doc().get("brew93_connection_status") or "Disconnected",
        "tenant_id": _doc().get("brew93_tenant_id"),
        "workspace_slug": _doc().get("brew93_tenant_slug"),
        "integration_user": INTEGRATION_USER,
        "integration_ready": has_credentials,
    }


# All supported CRM DocTypes are live by default. Operators can narrow this
# allow-list in site_config; an empty value never enables an unspecified type.
DEFAULT_LIVE_DOCTYPES = ("Lead", "Opportunity", "Quotation", "Contact", "Customer")


def get_live_doctypes() -> set[str]:
    return set(frappe.conf.get("brew93_live_doctypes") or DEFAULT_LIVE_DOCTYPES)


def get_service_password() -> str | None:
    """Brew93 service-account password. site_config wins over the Password field."""
    return frappe.conf.get("brew93_service_password") or _doc().get_password(
        "service_password", raise_exception=False
    )


def get_workspace_refresh_token() -> str | None:
    return _doc().get_password("brew93_refresh_token", raise_exception=False)


def set_workspace_refresh_token(refresh_token: str) -> None:
    """Persist the linked workspace refresh token through Frappe's encrypted API."""
    if not refresh_token:
        raise ValueError("A workspace refresh token is required")
    doc = _doc()
    set_encrypted_password(SETTINGS_DOCTYPE, doc.name, refresh_token, "brew93_refresh_token")
    # Console/scheduler contexts may not auto-commit; a lost rotation write
    # leaves a server-side-revoked token and breaks all further refreshes.
    frappe.db.commit()


def get_hmac_secret() -> str | None:
    """HMAC signing secret for the events channel. site_config wins."""
    return frappe.conf.get("brew93_hmac_secret") or _doc().get_password(
        "hmac_secret", raise_exception=False
    )


def get_jwt_verification_settings() -> dict:
    """Return the out-of-band JWT trust configuration, without secrets."""
    return {
        "public_key": frappe.conf.get("brew93_jwt_public_key"),
        "issuer": frappe.conf.get("brew93_jwt_issuer"),
        "audience": frappe.conf.get("brew93_jwt_audience"),
    }


def set_user_refresh_token(user: str, refresh_token: str) -> None:
    """Persist a refresh token through Frappe's encrypted Password API."""
    if not user or not refresh_token:
        raise ValueError("A user and refresh token are required")
    if not frappe.get_meta("User").has_field("brew93_refresh_token"):
        return
    set_encrypted_password("User", user, refresh_token, "brew93_refresh_token")
    frappe.db.commit()


def get_user_connection(user: str) -> dict | None:
    """Return only connection metadata; never expose the refresh token."""
    if not user or user in ("Guest", "Administrator"):
        return None
    meta = frappe.get_meta("User")
    fields = [
        field for field in ("brew93_user_id", "brew93_tenant_id", "brew93_connection_status")
        if meta.has_field(field)
    ]
    if not fields or not meta.has_field("brew93_refresh_token"):
        return None
    data = frappe.db.get_value("User", user, fields, as_dict=True)
    if not data or not get_user_refresh_token(user):
        return None
    return data


def get_user_refresh_token(user: str) -> str | None:
    if not user or user in ("Guest", "Administrator"):
        return None
    if not frappe.get_meta("User").has_field("brew93_refresh_token"):
        return None
    return frappe.get_doc("User", user).get_password("brew93_refresh_token", raise_exception=False)


@frappe.whitelist()
def get_connection_status() -> dict:
    """Return connection state for the current user without token material."""
    user = frappe.session.user
    if user in ("Guest", "Administrator"):
        return {"connected": False, "status": "Disconnected"}
    meta = frappe.get_meta("User")
    fields = [field for field in ("brew93_tenant_id", "brew93_connection_status") if meta.has_field(field)]
    if not fields or not meta.has_field("brew93_refresh_token"):
        return {"connected": False, "status": "Disconnected"}
    data = frappe.db.get_value("User", user, fields, as_dict=True) or {}
    connected = bool(get_user_refresh_token(user)) and str(data.get("brew93_tenant_id")) == str(get_settings().get("brew93_tenant_id"))
    status = data.get("brew93_connection_status") if connected else "Disconnected"
    if status not in {"Connected", "Disconnected", "Needs Reconnect"}:
        status = "Disconnected"
    return {
        "connected": connected,
        "status": status,
        "tenant_id": data.get("brew93_tenant_id") if connected else None,
    }
