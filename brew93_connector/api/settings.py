# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Typed accessor for `Brew93 Connector Settings` with site_config precedence.

Secrets (service password, HMAC secret) are read from `site_config.json` when
present, else from the encrypted Password fields on the single DocType. They are
never returned in bulk dicts, never cached in plaintext, and never logged.
"""

from __future__ import annotations

import frappe
from frappe.utils.password import set_encrypted_password

SETTINGS_DOCTYPE = "Brew93 Connector Settings"

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
    values["brew93_base_url"] = (values.get("brew93_base_url") or "").rstrip("/")
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
    return bool(values.get("sso_enabled") and values.get("brew93_base_url") and values.get("brew93_tenant_id"))


def _require_setup_admin() -> None:
    user = frappe.session.user
    if user == "Administrator":
        return
    frappe.throw(frappe._("Only the ERPNext Administrator can link Brew93."), frappe.PermissionError)


@frappe.whitelist(methods=["POST"])
def link_workspace(base_url, tenant_id, workspace_slug, username, password) -> dict:
    """Verify and link Brew93, retaining only encrypted refresh-token material."""
    _require_setup_admin()
    if not all((base_url, tenant_id, workspace_slug, username, password)):
        frappe.throw(frappe._("All Brew93 workspace fields are required."))

    values = {
        "brew93_base_url": base_url.strip().rstrip("/"),
        "brew93_tenant_id": tenant_id.strip(),
        "brew93_tenant_slug": workspace_slug.strip(),
        "request_timeout": 10,
    }
    from brew93_connector.api import client

    try:
        auth = client.brew93_workspace_authenticate(values, username.strip(), password)
    except frappe.AuthenticationError:
        raise
    except Exception:
        frappe.throw(frappe._("Brew93 workspace verification failed. Check the URL, tenant, workspace, and credentials."))
    finally:
        password = None

    claims = auth["claims"]
    if str(claims.get("tenant_id")) != str(values["brew93_tenant_id"]):
        frappe.throw(frappe._("The Brew93 account does not belong to the configured tenant."))
    if not claims.get("sub") and not claims.get("user_id"):
        frappe.throw(frappe._("Brew93 did not return a stable user ID."))
    refresh_token = auth.get("refresh_token")
    if not refresh_token:
        frappe.throw(frappe._("Brew93 did not return a refresh token."))

    doc = _doc()
    doc.db_set({
        "brew93_base_url": values["brew93_base_url"],
        "brew93_tenant_id": values["brew93_tenant_id"],
        "brew93_tenant_slug": values["brew93_tenant_slug"],
        "brew93_connection_status": "Connected",
        "brew93_connected_user_id": claims.get("sub") or claims.get("user_id"),
        "brew93_connected_username": (claims.get("email") or username).strip().lower(),
        "sso_enabled": 1,
    })
    set_encrypted_password(SETTINGS_DOCTYPE, doc.name, refresh_token, "brew93_refresh_token")
    return {
        "connected": True,
        "tenant_id": values["brew93_tenant_id"],
        "workspace_slug": values["brew93_tenant_slug"],
        "username": (claims.get("email") or username).strip().lower(),
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
