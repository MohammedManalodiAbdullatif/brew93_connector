# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Operator-triggered initial ERPNext -> Brew93 backfill."""

from __future__ import annotations

import frappe

from brew93_connector.api import mapping
from brew93_connector.api import outbound
from brew93_connector.api import settings as cfg


@frappe.whitelist()
def enqueue_backfill(doctype: str, limit: int = 500, start: int = 0) -> dict:
    """Queue a bounded page of existing documents; delivery remains asynchronous."""
    if frappe.session.user != "Administrator" and "System Manager" not in frappe.get_roles():
        frappe.throw("Only a System Manager may start a Brew93 backfill.", frappe.PermissionError)
    if not cfg.is_enabled():
        frappe.throw("Brew93 Connector is disabled.", frappe.ValidationError)
    if doctype not in mapping.RESOURCE_BUILDERS:
        frappe.throw("This DocType is not supported for Brew93 backfill.", frappe.ValidationError)

    limit = min(max(int(limit or 0), 1), 500)
    start = max(int(start or 0), 0)
    resource, builder = mapping.RESOURCE_BUILDERS[doctype]
    source_site = cfg.get_settings().get("source_site")
    names = frappe.get_all(doctype, pluck="name", limit_start=start, limit_page_length=limit)
    queued = 0
    skipped = 0
    for name in names:
        doc = frappe.get_doc(doctype, name)
        event_id = outbound.enqueue_event(
            doctype, name, resource, f"{resource}.upserted", builder(doc.as_dict(), source_site)
        )
        if event_id:
            queued += 1
        else:
            skipped += 1
    return {"doctype": doctype, "start": start, "requested": len(names), "queued": queued, "skipped": skipped}
