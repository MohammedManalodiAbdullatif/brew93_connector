"""Context for the connector-owned Brew93 sign-in page."""

import frappe

from brew93_connector.api import settings

no_cache = True


def get_context(context):
    if frappe.session.user != "Guest":
        frappe.local.flags.redirect_location = "/brew93-status"
        raise frappe.Redirect

    if not settings.sso_is_enabled_and_configured():
        frappe.local.flags.redirect_location = "/login"
        raise frappe.Redirect

    context.no_cache = 1
    context.allow_frappe_login = False
    context.title = frappe._("Sign in with Brew93")
    return context
