# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Hardened Brew93 SSO for the ERPNext desk (Phase 7).

Fixes the account-takeover class in the legacy brew93_ai SSO:
- TENANT PINNED: the visitor-typed workspace is ignored; the login always uses
  the configured tenant slug, AND the returned token's tenant_id must equal the
  configured Brew93 tenant UUID, else the login is refused.
- IDENTITY BY STABLE ID: users are matched on `User.brew93_user_id` (the Brew93
  user UUID from the token's `sub`), NOT on email. Email is used only to
  BOOTSTRAP the link on first login, and only within the already-pinned tenant;
  the uuid is then stamped so later logins never rely on email.
- PRIVILEGED ACCOUNTS REFUSED: SSO can never resolve to Administrator or any
  System Manager, and never auto-creates a privileged user.
- AUTO-CREATE OFF by default.
- DISABLED by default (`sso_enabled`), and does not touch the legacy brew93_ai
  login until an operator switches over.

The password is forwarded to Brew93 once and never stored or logged.
"""

from __future__ import annotations

import hashlib

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import cint

from brew93_connector.api import client
from brew93_connector.api import settings as cfg

_PRIVILEGED_ROLES = {"System Manager", "Administrator"}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(key="email", limit=10, seconds=60, methods=["POST"])
def login(email: str, password: str, workspace: str | None = None) -> dict:
    """Sign in with Brew93 credentials and start a Frappe desk session."""
    if not cfg.sso_enabled():
        frappe.throw(_("Brew93 sign-in is not enabled on this site."), frappe.AuthenticationError)

    values = cfg.get_settings()
    email = (email or "").strip().lower()
    if not email or not password:
        frappe.throw(_("Email and password are required."), frappe.AuthenticationError)
    if not values.get("brew93_base_url") or not values.get("brew93_tenant_id"):
        frappe.throw(_("Brew93 SSO is not fully configured."), frappe.AuthenticationError)

    # Ignore any visitor-supplied workspace; always use the configured tenant.
    workspace = values.get("brew93_tenant_slug") or None

    auth = client.brew93_user_authenticate(values, email, password)
    claims = auth["claims"]
    password = None  # noqa: F841 - drop as soon as it is spent

    _assert_tenant(claims, values["brew93_tenant_id"])
    user = _resolve_user(claims, values)
    _refuse_privileged(user)
    _refuse_disabled(user)
    _refuse_ineligible(user)
    cfg.set_user_refresh_token(user, auth["refresh_token"])
    _set_user_connection_metadata(user, values["brew93_tenant_id"])

    full_name, user_type = frappe.db.get_value("User", user, ["full_name", "user_type"])
    # A Website User has no desk access; sending them to /app would bounce.
    redirect_to = "/app" if user_type == "System User" else "/me"
    # login_as() skips the enabled check that password login performs.
    frappe.local.login_manager.login_as(user)
    frappe.local.response["home_page"] = redirect_to
    frappe.local.response["full_name"] = full_name
    return {"success": True, "user": user, "redirect_to": redirect_to}


def _assert_tenant(claims: dict, expected_tenant_id: str) -> None:
    if str(claims.get("tenant_id")) != str(expected_tenant_id):
        frappe.throw(
            _("This Brew93 account is not in the workspace configured for this site."),
            frappe.AuthenticationError,
        )


def _resolve_user(claims: dict, values: dict) -> str:
    sub = claims.get("sub") or claims.get("user_id")
    email = (claims.get("email") or "").strip().lower()
    user_meta = frappe.get_meta("User")
    has_user_id_field = user_meta.has_field("brew93_user_id")

    # 1) Stable-id match (the durable path).
    if sub and has_user_id_field:
        user = frappe.db.get_value("User", {"brew93_user_id": sub}, "name")
        if user:
            return user

    # 2) Bootstrap the link once, by email, WITHIN the already-pinned tenant.
    #    If the token carries an explicit email_verified=false, refuse.
    if claims.get("email_verified") is False:
        frappe.throw(_("This Brew93 email is not verified."), frappe.AuthenticationError)

    if email:
        user = frappe.db.get_value("User", {"email": email}, "name")
        if user:
            _refuse_privileged(user)  # never link/stamp onto a privileged account
            linked = frappe.db.get_value("User", user, "brew93_user_id") if has_user_id_field else None
            if linked and linked != sub:
                # Already bound to a different Brew93 account: an email match must
                # never re-point that link (e.g. a same-email user minted by a
                # Brew93 tenant admin).
                frappe.throw(
                    _("This ERPNext user is linked to a different Brew93 account."),
                    frappe.AuthenticationError,
                )
            if sub and has_user_id_field:
                frappe.db.set_value("User", user, "brew93_user_id", sub)
            return user

    frappe.throw(
        _("No eligible ERPNext System User matches this Brew93 account. Ask an administrator to link the user."),
        frappe.AuthenticationError,
    )


def _refuse_privileged(user: str) -> None:
    if user == "Administrator":
        frappe.throw(_("This account cannot use Brew93 sign-in."), frappe.AuthenticationError)
    if _PRIVILEGED_ROLES & set(frappe.get_roles(user)):
        frappe.throw(_("Privileged accounts cannot use Brew93 sign-in."), frappe.AuthenticationError)


def _refuse_disabled(user: str) -> None:
    if not cint(frappe.db.get_value("User", user, "enabled")):
        frappe.throw(_("This user account is disabled in ERPNext."), frappe.AuthenticationError)


def _refuse_ineligible(user: str) -> None:
    user_type = frappe.db.get_value("User", user, "user_type")
    if user_type != "System User":
        frappe.throw(_("Only eligible ERPNext System Users can use Brew93 sign-in."), frappe.AuthenticationError)

    if not all(frappe.has_permission("Lead", ptype, user=user) for ptype in ("read", "create", "write")):
        frappe.throw(
            _("This user needs read, create, and write permission on Lead to use Brew93 sign-in."),
            frappe.AuthenticationError,
        )


def _set_user_connection_metadata(user: str, tenant_id: str) -> None:
    """Write optional connector fields without assuming custom fields exist."""
    meta = frappe.get_meta("User")
    values = {}
    if meta.has_field("brew93_tenant_id"):
        values["brew93_tenant_id"] = tenant_id
    if meta.has_field("brew93_connection_status"):
        values["brew93_connection_status"] = "Connected"
    if values:
        frappe.db.set_value("User", user, values)


def _create_user(claims: dict, values: dict) -> str:
    default_role = values.get("sso_default_role")
    if default_role in _PRIVILEGED_ROLES:
        frappe.throw(_("SSO default role must not be privileged."), frappe.AuthenticationError)

    email = (claims.get("email") or "").strip().lower()
    doc = frappe.new_doc("User")
    doc.update({
        "email": email,
        "username": _unique_username(email),
        "first_name": claims.get("first_name") or (email.split("@")[0] if email else "Brew93 User"),
        "last_name": claims.get("last_name") or "",
        "enabled": 1,
        "user_type": "System User",
        "send_welcome_email": 0,
    })
    if frappe.get_meta("User").has_field("brew93_user_id"):
        doc.brew93_user_id = claims.get("sub")
    if default_role and frappe.db.exists("Role", default_role):
        doc.append("roles", {"role": default_role})
    doc.flags.ignore_permissions = True
    doc.insert(ignore_permissions=True)
    frappe.db.commit()  # nosemgrep - the session below must see a committed user
    return doc.name


def _unique_username(email: str) -> str:
    """Use the stable email identity instead of Frappe's first-name default."""
    if email and not frappe.db.exists("User", {"username": email}):
        return email

    # Keep the fallback deterministic and independent of the user's display name.
    digest = hashlib.sha256(email.encode()).hexdigest()[:16]
    base = frappe.scrub(email.replace("@", " ")) or "brew93_user"
    username = f"{base}_{digest}"
    suffix = 1
    while frappe.db.exists("User", {"username": username}):
        username = f"{base}_{digest}_{suffix}"
        suffix += 1
    return username
