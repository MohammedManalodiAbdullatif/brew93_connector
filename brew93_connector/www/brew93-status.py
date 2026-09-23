"""Context for the authenticated Brew93 connection status page."""

import frappe

no_cache = True


def get_context(context):
    if frappe.session.user == "Guest":
        frappe.local.flags.redirect_location = "/brew93-login"
        raise frappe.Redirect
    context.no_cache = 1
    context.title = frappe._("Brew93 Connection")
    return context
