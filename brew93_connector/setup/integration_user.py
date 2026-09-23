# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Create the low-privilege integration identity for Brew93 -> ERPNext writes.

NOT run automatically. It creates a credentialed production account, so it is
invoked only after explicit user approval (e.g. via bench execute). It creates:
- a custom role `Brew93 Integration`,
- create/read/write DocPerms for that role on Lead/Opportunity/Customer/Contact
  (no delete, no submit, no privileged doctypes),
- read-only DocPerms on Item/UOM so Quotation line link validation works,
- a System User `brew93-integration@rag.klyonix.in` holding ONLY that role.

It does NOT generate or print API keys — that is a separate, explicit step so no
secret is ever emitted to a log or a message.
"""

import frappe

from brew93_connector.api.constants import (
    INTEGRATION_DOCTYPES,
    INTEGRATION_ROLE,
    INTEGRATION_USER,
    READ_ONLY_DOCTYPES,
)


def ensure_integration_identity():
    if not frappe.db.exists("Role", INTEGRATION_ROLE):
        role = frappe.new_doc("Role")
        role.role_name = INTEGRATION_ROLE
        role.desk_access = 1
        role.insert(ignore_permissions=True)

    for dt in INTEGRATION_DOCTYPES:
        _ensure_docperm(dt, write=True)
    for dt in READ_ONLY_DOCTYPES:
        _ensure_docperm(dt, write=False)

    if not frappe.db.exists("User", INTEGRATION_USER):
        user = frappe.new_doc("User")
        user.email = INTEGRATION_USER
        user.first_name = "Brew93"
        user.last_name = "Integration"
        user.user_type = "System User"
        user.send_welcome_email = 0
        user.append("roles", {"role": INTEGRATION_ROLE})
        user.insert(ignore_permissions=True)
    else:
        user = frappe.get_doc("User", INTEGRATION_USER)
        if INTEGRATION_ROLE not in [r.role for r in user.roles]:
            user.append("roles", {"role": INTEGRATION_ROLE})
            user.save(ignore_permissions=True)

    frappe.db.commit()
    return {"role": INTEGRATION_ROLE, "user": INTEGRATION_USER}


def _ensure_docperm(doctype, write=True):
    exists = frappe.db.exists(
        "Custom DocPerm", {"parent": doctype, "role": INTEGRATION_ROLE, "permlevel": 0}
    )
    if exists:
        if write:
            perm = frappe.get_doc("Custom DocPerm", exists)
            if not perm.write:
                perm.write = 1
                if not perm.create:
                    perm.create = 1
                perm.save(ignore_permissions=True)
                frappe.db.commit()
        return
    perm = frappe.new_doc("Custom DocPerm")
    perm.parent = doctype
    perm.parenttype = "DocType"
    perm.parentfield = "permissions"
    perm.role = INTEGRATION_ROLE
    perm.permlevel = 0
    perm.read = 1
    perm.write = 1 if write else 0
    perm.create = 1 if write else 0
    perm.delete = 0
    perm.submit = 0
    perm.insert(ignore_permissions=True)
    frappe.db.commit()
