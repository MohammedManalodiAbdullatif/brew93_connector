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
    fields = {dt: [dict(f) for f in common] for dt in SYNCED_DOCTYPES}
    # Lead identity is scoped by tenant; the database composite index is
    # installed by ensure_lead_external_id_index().
    fields["Lead"][1]["unique"] = 0
    return fields


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
    ensure_lead_external_id_index()
    frappe.db.commit()


def ensure_lead_external_id_index():
    """Make Lead identity unique on (tenant, Brew93 id), including old sites."""
    if not frappe.db.table_exists("Lead"):
        return

    duplicate_groups = frappe.db.sql(
        """
        SELECT brew93_tenant_id, brew93_id
        FROM `tabLead`
        WHERE brew93_tenant_id IS NOT NULL
          AND brew93_id IS NOT NULL AND brew93_id != ''
        GROUP BY brew93_tenant_id, brew93_id
        HAVING COUNT(*) > 1
        """,
        as_dict=True,
    )

    # Older installs made brew93_id globally unique. Remove only that index;
    # dropping an index cannot delete or change any Lead data. Other external-id
    # fields retain their existing uniqueness guarantees.
    indexes = frappe.db.sql(
        """
        SELECT index_name, non_unique, GROUP_CONCAT(column_name ORDER BY seq_in_index)
        FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = 'tabLead'
        GROUP BY index_name, non_unique
        """,
        as_list=True,
    )
    for index_name, non_unique, columns in indexes:
        if not non_unique and columns == "brew93_id":
            frappe.db.sql("ALTER TABLE `tabLead` DROP INDEX `{}`".format(index_name.replace("`", "``")))

    if duplicate_groups:
        conflicts = ", ".join(
            f"tenant={group.brew93_tenant_id!r}, brew93_id={group.brew93_id!r}"
            for group in duplicate_groups
        )
        frappe.logger("brew93_connector").warning(
            "Cannot create unique Lead index brew93_lead_tenant_id: "
            f"same-tenant duplicate groups exist ({conflicts}). "
            "No Leads were deleted; resolve the duplicates and rerun migration."
        )
        return

    indexes = frappe.db.sql(
        """
        SELECT index_name
        FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = 'tabLead'
          AND index_name = 'brew93_lead_tenant_id'
        """,
        as_list=True,
    )
    if not indexes:
        frappe.db.sql(
            "ALTER TABLE `tabLead` ADD UNIQUE INDEX `brew93_lead_tenant_id` "
            "(`brew93_tenant_id`, `brew93_id`)"
        )


def remove_external_id_fields():
    defs = {**_field_defs(), **_user_link_field()}
    for dt, fields in defs.items():
        for f in fields:
            name = f"{dt}-{f['fieldname']}"
            if frappe.db.exists("Custom Field", name):
                frappe.delete_doc("Custom Field", name, ignore_permissions=True, force=True)
    frappe.db.commit()
