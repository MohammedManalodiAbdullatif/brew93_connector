# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Create the low-privilege integration identity for Brew93 -> ERPNext writes.

NOT run automatically. It creates a credentialed production account, so it is
invoked only after explicit user approval (e.g. via bench execute). It creates:
- a custom role `Brew93 Integration`,
- create/read/write DocPerms for that role on Lead/Opportunity/Customer/Contact
  (no delete, no submit, no privileged doctypes),
- read-only DocPerms on Item/UOM so Quotation line link validation works,
- a System User `brew93-integration@rag.klyonix.in` holding ONLY that role.

IMPORTANT: Frappe\u0027s meta.set_custom_permissions() REPLACES meta.permissions with
Custom DocPerm rows whenever ANY Custom DocPerm exists for a DocType. Before the
first Custom DocPerm is inserted, every standard DocPerm row must be copied over,
or roles like Sales User silently lose desk permissions (breaking SSO eligibility).

It does NOT generate or print API keys \u2014 that is a separate, explicit step so no
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


def repair_custom_docperms(doctypes=None):
    """Copy any missing standard DocPerm rows into Custom DocPerm.

    Safe to re-run: only inserts (parent, role, permlevel) combos that are not
    already present in Custom DocPerm. Fixes sites where a partial Custom DocPerm
    (ours only) wiped Sales User / Desk User permissions from meta.permissions.
    """
    doctypes = list(doctypes or set(INTEGRATION_DOCTYPES) | set(READ_ONLY_DOCTYPES))
    copied = 0
    for dt in doctypes:
        std = frappe.get_all(
            "DocPerm",
            filters={"parent": dt},
            fields=["role", "permlevel", "select", "read", "write", "create", "delete",
                    "submit", "cancel", "amend", "print", "email", "report", "export",
                    "import", "share", "if_owner"],
        )
        for row in std:
            exists = frappe.db.exists(
                "Custom DocPerm",
                {"parent": dt, "role": row.role, "permlevel": row.permlevel, "if_owner": row.get("if_owner") or 0},
            )
            if exists:
                continue
            perm = frappe.new_doc("Custom DocPerm")
            perm.parent = dt
            perm.parenttype = "DocType"
            perm.parentfield = "permissions"
            perm.update(row)
            perm.insert(ignore_permissions=True)
            copied += 1
    frappe.db.commit()
    frappe.clear_cache(doctype="Lead")
    for dt in doctypes:
        frappe.clear_cache(doctype=dt)
    return {"copied": copied, "doctypes": doctypes}


def _ensure_docperm(doctype, write=True):
    # Preserve standard role permissions before/while adding ours (see module docstring).
    repair_custom_docperms([doctype])

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
