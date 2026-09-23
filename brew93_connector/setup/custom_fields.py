# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""External-ID mapping fields on the synced DocTypes (Phase 3 data model).

- `brew93_id`: the immutable Brew93 UUID. UNIQUE per DocType, indexed. This is the
  join key for synchronization — records are matched on this, NEVER on email.
- `brew93_tenant_id`: the owning Brew93 tenant UUID (tenant isolation at the row).
- `brew93_synced_at`: last successful sync timestamp (diagnostics only).

Idempotent: `create_custom_fields` upserts, so re-running install/migrate is safe.
"""

import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

SYNCED_DOCTYPES = ("Lead", "Opportunity", "Contact", "Customer", "Quotation")


def _field_defs():
    common = [
        {
            "fieldname": "brew93_section",
            "fieldtype": "Section Break",
            "label": "Brew93 Integration",
            "collapsible": 1,
            "insert_after": "modified",
        },
        {
            "fieldname": "brew93_id",
            "label": "Brew93 ID",
            "fieldtype": "Data",
            "unique": 1,
            "read_only": 1,
            "no_copy": 1,
            "search_index": 1,
            "insert_after": "brew93_section",
            "description": "Immutable Brew93 UUID. Sync matches on this, never on email.",
        },
        {
            "fieldname": "brew93_tenant_id",
            "label": "Brew93 Tenant ID",
            "fieldtype": "Data",
            "read_only": 1,
            "no_copy": 1,
            "search_index": 1,
            "insert_after": "brew93_id",
        },
        {
            "fieldname": "brew93_synced_at",
            "label": "Brew93 Last Synced",
            "fieldtype": "Datetime",
            "read_only": 1,
            "no_copy": 1,
            "insert_after": "brew93_tenant_id",
        },
    ]
    return {dt: [dict(f) for f in common] for dt in SYNCED_DOCTYPES}


def _user_link_field():
    return {
        "User": [
            {
                "fieldname": "brew93_user_id",
                "label": "Brew93 User ID",
                "fieldtype": "Data",
                "unique": 1,
                "read_only": 1,
                "no_copy": 1,
                "search_index": 1,
                "insert_after": "username",
                "description": "Stable Brew93 user UUID. SSO maps on this, never on email alone.",
            }
            ,{
                "fieldname": "brew93_tenant_id",
                "label": "Brew93 Tenant ID",
                "fieldtype": "Data",
                "read_only": 1,
                "no_copy": 1,
                "search_index": 1,
                "insert_after": "brew93_user_id",
            },
            {
                "fieldname": "brew93_refresh_token",
                "label": "Brew93 Refresh Token",
                "fieldtype": "Password",
                "read_only": 1,
                "no_copy": 1,
                "hidden": 1,
                "insert_after": "brew93_tenant_id",
            },
            {
                "fieldname": "brew93_connection_status",
                "label": "Brew93 Connection Status",
                "fieldtype": "Select",
                "options": "Connected\nDisconnected\nNeeds Reconnect",
                "read_only": 1,
                "insert_after": "brew93_refresh_token",
            },
        ]
    }


def create_external_id_fields():
    create_custom_fields(_field_defs(), ignore_validate=True)
    create_custom_fields(_user_link_field(), ignore_validate=True)
    frappe.db.commit()


def remove_external_id_fields():
    defs = {**_field_defs(), **_user_link_field()}
    for dt, fields in defs.items():
        for f in fields:
            name = f"{dt}-{f['fieldname']}"
            if frappe.db.exists("Custom Field", name):
                frappe.delete_doc("Custom Field", name, ignore_permissions=True, force=True)
    frappe.db.commit()
