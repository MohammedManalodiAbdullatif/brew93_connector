# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Inbound Pull Synchronization: Brew93 -> ERPNext.

Pulls records from Brew93 CRM endpoints (/api/v1/crm/*) and updates ERPNext in place.
Can be triggered manually from Desk or automatically on a recurring schedule.
"""

from __future__ import annotations

import frappe
from frappe.utils import get_datetime

from brew93_connector.api import client
from brew93_connector.api import settings as cfg
from brew93_connector.api.v1 import (
    _apply_contact,
    _apply_customer,
    _apply_lead,
    _apply_opportunity,
    _apply_quotation,
)


@frappe.whitelist()
def pull_all_from_brew93(is_scheduled: bool = False) -> dict:
    """Pull all recent CRM records from Brew93 into ERPNext."""
    if not cfg.is_enabled():
        return {"ok": False, "message": "Brew93 Connector is disabled."}

    settings_doc = frappe.get_single("Brew93 Connector Settings")
    if is_scheduled and hasattr(settings_doc, "auto_sync_enabled") and not settings_doc.auto_sync_enabled:
        return {"ok": False, "message": "Auto-sync is disabled in settings."}

    results = {}
    if not hasattr(settings_doc, "sync_leads") or settings_doc.sync_leads:
        results["leads"] = pull_leads()
    if not hasattr(settings_doc, "sync_deals") or settings_doc.sync_deals:
        results["deals"] = pull_deals()
    if not hasattr(settings_doc, "sync_contacts") or settings_doc.sync_contacts:
        results["contacts"] = pull_contacts()
    if not hasattr(settings_doc, "sync_customers") or settings_doc.sync_customers:
        results["customers"] = pull_customers()
    if not hasattr(settings_doc, "sync_quotations") or settings_doc.sync_quotations:
        results["quotations"] = pull_quotations()

    try:
        frappe.db.set_value(
            "Brew93 Connector Settings",
            "Brew93 Connector Settings",
            "last_synced_at",
            frappe.utils.now(),
            update_modified=False,
        )
    except Exception:
        pass

    frappe.db.commit()
    return {"ok": True, "results": results}


def _get_crm(endpoint: str) -> list[dict]:
    values = cfg.get_settings()
    token = client._get_user_crm_token(values, "Administrator") if frappe.session else client._crm_token(values)
    session = client._session()
    try:
        base = client._base_url(values)
        headers = {"Authorization": f"Bearer {token}"}
        if values.get("brew93_tenant_slug"):
            headers["x-tenant-slug"] = values["brew93_tenant_slug"]
        resp = session.get(f"{base}/crm/{endpoint}", headers=headers, timeout=(5, values.get("request_timeout", 10)))
        if resp.status_code == 200:
            body = resp.json()
            data = body.get("data") if isinstance(body, dict) else None
            if isinstance(data, dict):
                return data.get("rows") or []
            if isinstance(data, list):
                return data
        return []
    finally:
        session.close()


def _get_crm_detail(endpoint: str, resource_id: str) -> dict | None:
    values = cfg.get_settings()
    token = client._get_user_crm_token(values, "Administrator") if frappe.session else client._crm_token(values)
    session = client._session()
    try:
        base = client._base_url(values)
        headers = {"Authorization": f"Bearer {token}"}
        if values.get("brew93_tenant_slug"):
            headers["x-tenant-slug"] = values["brew93_tenant_slug"]
        resp = session.get(f"{base}/crm/{endpoint}/{resource_id}", headers=headers, timeout=(5, values.get("request_timeout", 10)))
        if resp.status_code == 200:
            body = resp.json()
            return body.get("data") if isinstance(body, dict) else None
        return None
    finally:
        session.close()


def pull_leads() -> dict:
    values = cfg.get_settings()
    tenant_id = values.get("brew93_tenant_id")
    rows = _get_crm("leads")
    created, updated, skipped = 0, 0, 0

    for r in rows:
        bid = r.get("id")
        if not bid:
            continue
        data = {
            "lead_name": r.get("name"),
            "email_id": r.get("email"),
            "mobile_no": r.get("phone"),
            "company_name": r.get("company_name"),
            "job_title": r.get("job_title"),
            "status": r.get("status"),
            "source": r.get("source"),
        }
        try:
            _, action = _apply_lead(bid, tenant_id, r.get("updated_at"), data)
            if action == "created":
                created += 1
            elif action == "updated":
                updated += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return {"created": created, "updated": updated, "skipped": skipped}


def pull_deals() -> dict:
    values = cfg.get_settings()
    tenant_id = values.get("brew93_tenant_id")
    rows = _get_crm("deals")
    created, updated, skipped = 0, 0, 0

    for r in rows:
        bid = r.get("id")
        if not bid:
            continue
        data = {
            "title": r.get("title"),
            "opportunity_amount": r.get("value"),
            "currency": r.get("currency") or "INR",
            "probability": r.get("probability"),
            "expected_closing": r.get("expected_close_date"),
        }
        try:
            _, action = _apply_opportunity(bid, tenant_id, r.get("updated_at"), data)
            if action == "created":
                created += 1
            elif action == "updated":
                updated += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return {"created": created, "updated": updated, "skipped": skipped}


def pull_contacts() -> dict:
    values = cfg.get_settings()
    tenant_id = values.get("brew93_tenant_id")
    rows = _get_crm("contacts")
    created, updated, skipped = 0, 0, 0

    for r in rows:
        bid = r.get("id")
        if not bid:
            continue
        data = {
            "first_name": r.get("first_name"),
            "last_name": r.get("last_name"),
            "email_id": r.get("email"),
            "mobile_no": r.get("mobile") or r.get("phone"),
            "designation": r.get("job_title"),
            "department": r.get("department"),
        }
        try:
            _, action = _apply_contact(bid, tenant_id, r.get("updated_at"), data)
            if action == "created":
                created += 1
            elif action == "updated":
                updated += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return {"created": created, "updated": updated, "skipped": skipped}


def pull_customers() -> dict:
    values = cfg.get_settings()
    tenant_id = values.get("brew93_tenant_id")
    rows = _get_crm("companies")
    created, updated, skipped = 0, 0, 0

    for r in rows:
        bid = r.get("id")
        if not bid:
            continue
        data = {
            "customer_name": r.get("name"),
            "industry": r.get("industry"),
            "website": r.get("website"),
            "default_currency": r.get("currency") or "INR",
        }
        try:
            _, action = _apply_customer(bid, tenant_id, r.get("updated_at"), data)
            if action == "created":
                created += 1
            elif action == "updated":
                updated += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1
    return {"created": created, "updated": updated, "skipped": skipped}


def pull_quotations() -> dict:
    values = cfg.get_settings()
    tenant_id = values.get("brew93_tenant_id")
    rows = _get_crm("quotes")
    created, updated, skipped = 0, 0, 0

    for r in rows:
        bid = r.get("id")
        if not bid:
            continue
        detail = _get_crm_detail("quotes", bid) or r
        
        # Link items
        items = []
        for li in (detail.get("line_items") or []):
            item_name = li.get("name") or "Item"
            qty = float(li.get("quantity") or 1)
            rate = float(li.get("unit_price") or 0)
            items.append({
                "item_code": item_name,
                "item_name": item_name,
                "qty": qty,
                "rate": rate,
                "amount": qty * rate,
                "discount_percentage": float(li.get("discount") or 0),
            })

        # Match existing Quotation by brew93_id OR quote_number
        existing_name = None
        if frappe.db.exists("Quotation", {"brew93_id": bid}):
            existing_name = frappe.db.get_value("Quotation", {"brew93_id": bid}, "name")
        elif detail.get("quote_number") and frappe.db.exists("Quotation", detail["quote_number"]):
            existing_name = detail["quote_number"]
            # Stamp brew93_id
            frappe.db.set_value("Quotation", existing_name, "brew93_id", bid, update_modified=False)

        if not existing_name:
            # Need a party to create a new quotation in ERPNext
            skipped += 1
            continue

        qdoc = frappe.get_doc("Quotation", existing_name)
        if qdoc.docstatus == 0:  # Draft: update fields and items
            frappe.flags.in_brew93_import = True
            try:
                if items:
                    qdoc.set("items", [])
                    for it in items:
                        # Find or create item if missing, or use item_code as is
                        if not frappe.db.exists("Item", it["item_code"]):
                            # Fallback to a default or first available item or create basic item
                            fallback_item = frappe.db.get_value("Item", {}, "name")
                            if fallback_item:
                                it["item_code"] = fallback_item
                        qdoc.append("items", it)
                if detail.get("valid_until"):
                    qdoc.valid_till = str(detail["valid_until"])[:10]
                if detail.get("notes"):
                    qdoc.remarks = detail["notes"]
                qdoc.brew93_id = bid
                qdoc.brew93_synced_at = frappe.utils.now()
                qdoc.flags.ignore_permissions = True
                qdoc.save(ignore_permissions=True)
                updated += 1
            finally:
                frappe.flags.in_brew93_import = False
        else:
            # Submitted / cancelled quote: update brew93 fields only
            frappe.db.set_value("Quotation", qdoc.name, {
                "brew93_id": bid,
                "brew93_synced_at": frappe.utils.now(),
            }, update_modified=False)
            updated += 1

    return {"created": created, "updated": updated, "skipped": skipped}
