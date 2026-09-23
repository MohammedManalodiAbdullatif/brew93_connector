# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Field/status mapping and Brew93 bulk-record builders.

Pure functions (they take plain dicts, not Frappe docs) so they are unit-testable
without a site. The builders emit the record shapes documented in the Brew93
Postman collection's `Integrations — ERPNext` folder, keyed by `external_id`
(= the ERPNext document name).

STATUS MAPPING — a deliberate, documented choice:
- On the BULK channel (ERPNext -> Brew93 push) the documented example sends the
  ERPNext status string verbatim (e.g. "Lead", "Quotation"), so the builders pass
  it through unchanged. The Brew93 receiver owns interpreting it.
- The 5<->9 two-way map below is for the INBOUND direction (Brew93 -> ERPNext) and
  for any channel that expects Brew93's own enum. It is intentionally total: every
  value maps to something, and unknowns fall back to a safe default.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

# ERPNext/Frappe store naive datetimes in the SITE's local timezone, not UTC.
# Default to IST (Asia/Kolkata, UTC+5:30, no DST) — this site's timezone — for
# the pure unit tests, which run without a connected Frappe site.
_DEFAULT_SITE_TZ = timezone(timedelta(hours=5, minutes=30))


def _site_tzinfo():
    """Resolve the ERPNext site timezone (System Settings.time_zone).

    Falls back to the default above when no Frappe site is connected, so the
    naive->UTC conversion is deterministic in isolation. Frappe is imported
    lazily to keep this module unit-testable without a site.
    """
    try:
        import frappe

        tzname = frappe.get_cached_value("System Settings", "System Settings", "time_zone")
        if tzname:
            from zoneinfo import ZoneInfo

            return ZoneInfo(tzname)
    except Exception:
        pass
    return _DEFAULT_SITE_TZ

# --- Lead status -----------------------------------------------------------
# ERPNext Lead (9) -> Brew93 lead.status (5)
LEAD_STATUS_ERP_TO_BREW93 = {
    "Lead": "new",
    "Open": "contacted",
    "Replied": "contacted",
    "Interested": "qualified",
    "Opportunity": "qualified",
    "Quotation": "qualified",
    "Converted": "converted",
    "Lost Quotation": "unqualified",
    "Do Not Contact": "unqualified",
}
# Brew93 (5) -> ERPNext (9). Chosen as the least-surprising inbound landing state.
LEAD_STATUS_BREW93_TO_ERP = {
    "new": "Lead",
    "contacted": "Open",
    "qualified": "Interested",
    "unqualified": "Do Not Contact",
    "converted": "Converted",
}
_DEFAULT_BREW93_LEAD_STATUS = "new"
_DEFAULT_ERP_LEAD_STATUS = "Lead"


def lead_status_to_brew93(erp_status: str | None) -> str:
    return LEAD_STATUS_ERP_TO_BREW93.get((erp_status or "").strip(), _DEFAULT_BREW93_LEAD_STATUS)


def lead_status_to_erpnext(brew93_status: str | None) -> str:
    return LEAD_STATUS_BREW93_TO_ERP.get((brew93_status or "").strip().lower(), _DEFAULT_ERP_LEAD_STATUS)


# --- helpers ---------------------------------------------------------------
def to_iso8601_utc(value) -> str | None:
    """Render a datetime/str as ISO-8601 UTC with a trailing Z, or None.

    A NAIVE datetime (what Frappe stores) is interpreted in the SITE timezone
    (IST here) and then converted to UTC — e.g. 11:15 IST -> 05:45Z. An
    already-aware datetime is converted from its own offset. This is for
    datetime fields only; use `to_date_str` for Date fields (no tz shift).
    """
    if value is None or value == "":
        return None
    if isinstance(value, str):
        # Frappe stores "YYYY-MM-DD HH:MM:SS(.ffffff)"; normalise to ISO-Z.
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value  # already some ISO-ish string; pass through untouched
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=_site_tzinfo())  # local site time, not UTC
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return None


def to_date_str(value) -> str | None:
    """Render a date/datetime/str as a plain YYYY-MM-DD, or None."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)[:10]


def docstatus_label(docstatus) -> str:
    return {0: "draft", 1: "submitted", 2: "cancelled"}.get(int(docstatus or 0), "draft")


def _clean(record: dict) -> dict:
    """Drop keys whose value is None-ish but keep explicit False/0/''.

    The Brew93 receiver ignores unknown fields, but we still avoid shipping a wall
    of nulls. `external_id` is always retained by the callers.
    """
    return {k: v for k, v in record.items() if v is not None}


# --- record builders (ERPNext -> Brew93 bulk shape) ------------------------
def build_lead_record(doc: dict, source_site: str) -> dict:
    """Map an ERPNext Lead dict to a Brew93 `leads/bulk` record.

    `doc` is a plain dict of Lead fields (e.g. from doc.as_dict()). `external_id`
    is the ERPNext Lead name.
    """
    record = {
        "external_id": doc["name"],
        "lead_name": doc.get("lead_name"),
        "salutation": doc.get("salutation"),
        "first_name": doc.get("first_name"),
        "middle_name": doc.get("middle_name"),
        "last_name": doc.get("last_name"),
        "email": doc.get("email_id"),
        "mobile": doc.get("mobile_no"),
        "phone": doc.get("phone"),
        "whatsapp": doc.get("whatsapp_no"),
        "company_name": doc.get("company_name"),
        "job_title": doc.get("job_title"),
        "website": doc.get("website"),
        # Documented bulk contract carries the ERPNext status string verbatim.
        "status": doc.get("status"),
        "source": doc.get("utm_source") or doc.get("source"),
        "industry": doc.get("industry"),
        "market_segment": doc.get("market_segment"),
        "territory": doc.get("territory"),
        "city": doc.get("city"),
        "state": doc.get("state"),
        "country": doc.get("country"),
        "no_of_employees": doc.get("no_of_employees"),
        "qualification_status": doc.get("qualification_status"),
        "annual_revenue": doc.get("annual_revenue"),
        "owner_email": doc.get("lead_owner") or doc.get("owner"),
        "type": doc.get("type"),
        "request_type": doc.get("request_type"),
        "disabled": bool(doc.get("disabled")),
        "unsubscribed": bool(doc.get("unsubscribed")),
        "created_at": to_iso8601_utc(doc.get("creation")),
        "updated_at": to_iso8601_utc(doc.get("modified")),
    }
    return {"external_id": record["external_id"], **_clean(record)}


def build_crm_lead_payload(doc: dict, source_site: str) -> dict:
    """Map an ERPNext Lead to Brew93's CRM API shape (POST/PUT /crm/leads), so the
    lead lands in the real CRM Leads (visible in the UI), not the staging table.
    status uses the Brew93 5-enum. `custom_fields` carries the ERPNext identity
    for traceability; the ERPNext-side brew93_id keys create-vs-update.
    """
    name = (
        doc.get("lead_name")
        or " ".join(p for p in (doc.get("first_name"), doc.get("last_name")) if p)
        or doc.get("company_name")
    )
    record = {
        "name": name,
        "email": doc.get("email_id"),
        "phone": doc.get("mobile_no") or doc.get("phone"),
        "company_name": doc.get("company_name"),
        "job_title": doc.get("job_title"),
        "source": doc.get("utm_source") or doc.get("source"),
        "status": lead_status_to_brew93(doc.get("status")),
        "custom_fields": {"erpnext_name": doc["name"], "source_site": source_site},
    }
    return _clean(record)


def build_opportunity_record(doc: dict, source_site: str) -> dict:
    """Map an ERPNext Opportunity dict to a Brew93 `deals/bulk` record.

    NOTE (OPEN): the documented example sends `status`/`sales_stage` as ERPNext
    strings, but Brew93 deal.stage is a UUID FK to pipeline_stages. We send the
    ERPNext strings as documented and rely on the receiver to map them; awaiting
    confirmation of the string->stage mapping + default.
    """
    record = {
        "external_id": doc["name"],
        "title": doc.get("title") or doc.get("customer_name") or doc.get("party_name"),
        "party_type": doc.get("opportunity_from"),
        "party_id": doc.get("party_name"),
        "customer_name": doc.get("customer_name"),
        "status": doc.get("status"),
        "opportunity_type": doc.get("opportunity_type"),
        "sales_stage": doc.get("sales_stage"),
        "owner_email": doc.get("opportunity_owner") or doc.get("owner"),
        "expected_closing": to_date_str(doc.get("expected_closing")),
        "probability": doc.get("probability"),
        "amount": doc.get("opportunity_amount"),
        "base_amount": doc.get("base_opportunity_amount"),
        "currency": doc.get("currency"),
        "total": doc.get("total"),
        "company": doc.get("company"),
        "territory": doc.get("territory"),
        "industry": doc.get("industry"),
        "city": doc.get("city"),
        "state": doc.get("state"),
        "country": doc.get("country"),
        "source": doc.get("utm_source") or doc.get("source"),
        "transaction_date": to_date_str(doc.get("transaction_date")),
        "created_at": to_iso8601_utc(doc.get("creation")),
        "updated_at": to_iso8601_utc(doc.get("modified")),
    }
    return {"external_id": record["external_id"], **_clean(record)}


def build_customer_record(doc: dict, source_site: str) -> dict:
    """Map an ERPNext Customer dict to the Brew93 `customers/bulk` schema
    (confirmed by Brew93 2026-09-16). Fields absent on the ERPNext Customer
    DocType (e.g. email/mobile, which live on the linked Contact) are simply
    omitted; the receiver ignores unknown/missing fields.
    """
    record = {
        "external_id": doc["name"],
        "customer_name": doc.get("customer_name"),
        "customer_type": doc.get("customer_type"),
        "customer_group": doc.get("customer_group"),
        "territory": doc.get("territory"),
        "industry": doc.get("industry"),
        "market_segment": doc.get("market_segment"),
        "status": doc.get("disabled") and "disabled" or doc.get("customer_status"),
        "owner_email": doc.get("owner"),
        "email": doc.get("email_id"),
        "mobile": doc.get("mobile_no"),
        "phone": doc.get("phone"),
        "whatsapp": doc.get("whatsapp_no"),
        "website": doc.get("website"),
        "city": doc.get("city"),
        "state": doc.get("state"),
        "country": doc.get("country"),
        "tax_id": doc.get("tax_id"),
        "currency": doc.get("default_currency"),
        "default_price_list": doc.get("default_price_list"),
        "payment_terms": doc.get("payment_terms"),
        "account_manager": doc.get("account_manager"),
        "lead_id": doc.get("lead_name"),
        "annual_revenue": doc.get("annual_revenue"),
        "credit_limit": doc.get("credit_limit"),
        "disabled": bool(doc.get("disabled")),
        "is_frozen": bool(doc.get("is_frozen")),
        "created_at": to_iso8601_utc(doc.get("creation")),
        "updated_at": to_iso8601_utc(doc.get("modified")),
    }
    return {"external_id": record["external_id"], **_clean(record)}


def _primary_from_children(rows, value_key, flag_keys):
    """Pick the primary value from a Contact child table (email_ids/phone_nos).

    Prefers a row flagged primary; else the first row. `rows` is a list of dicts
    from doc.as_dict(). Returns the value or None.
    """
    if not rows:
        return None
    for row in rows:
        if any(row.get(fk) for fk in flag_keys):
            return row.get(value_key)
    return rows[0].get(value_key)


def build_contact_record(doc: dict, source_site: str) -> dict:
    """Map an ERPNext Contact dict (from doc.as_dict(), incl. child tables) to a
    Brew93 `contacts` record (schema confirmed by Brew93 2026-09-16).

    ERPNext keeps emails/phones in child tables and parties in the `links` child
    table, so we flatten the primary values. Address lines/city/state/country
    live on a linked Address (not on the Contact), so they are omitted here.
    """
    email = doc.get("email_id") or _primary_from_children(doc.get("email_ids"), "email_id", ("is_primary",))
    mobile = doc.get("mobile_no") or _primary_from_children(doc.get("phone_nos"), "phone", ("is_primary_mobile_no",))
    phone = doc.get("phone") or _primary_from_children(doc.get("phone_nos"), "phone", ("is_primary_phone",))

    links = doc.get("links") or []
    party_type = links[0].get("link_doctype") if links else None
    party_name = links[0].get("link_name") if links else None

    record = {
        "external_id": doc["name"],
        "first_name": doc.get("first_name"),
        "middle_name": doc.get("middle_name"),
        "last_name": doc.get("last_name"),
        "salutation": doc.get("salutation"),
        "designation": doc.get("designation"),
        "department": doc.get("department"),
        "company_name": doc.get("company_name"),
        "email": email,
        "mobile": mobile,
        "phone": phone,
        "whatsapp": doc.get("whatsapp"),
        "gender": doc.get("gender"),
        "status": doc.get("status"),
        "owner_email": doc.get("owner"),
        "party_type": party_type,
        "party_name": party_name,
        "is_primary_contact": bool(doc.get("is_primary_contact")),
        "unsubscribed": bool(doc.get("unsubscribed")),
        "created_at": to_iso8601_utc(doc.get("creation")),
        "updated_at": to_iso8601_utc(doc.get("modified")),
    }
    return {"external_id": record["external_id"], **_clean(record)}


def build_quotation_record(doc: dict, source_site: str) -> dict:
    """Map an ERPNext Quotation (submittable, with child `items`) to a Brew93
    `quotations` record. `doc_status` reflects draft/submitted/cancelled so Brew93
    sees the lifecycle; line items are flattened from the child table.
    """
    items = []
    for idx, it in enumerate(doc.get("items") or [], start=1):
        items.append(_clean({
            "position": idx,
            "item_code": it.get("item_code"),
            "item_name": it.get("item_name"),
            "description": it.get("description"),
            "item_group": it.get("item_group"),
            "qty": it.get("qty"),
            "uom": it.get("uom"),
            "rate": it.get("rate"),
            "amount": it.get("amount"),
            "net_amount": it.get("net_amount"),
            "discount_percentage": it.get("discount_percentage"),
        }))

    record = {
        "external_id": doc["name"],
        "title": doc.get("title"),
        "party_type": doc.get("quotation_to"),
        "party_id": doc.get("party_name"),
        "customer_name": doc.get("customer_name"),
        "status": doc.get("status"),
        "order_type": doc.get("order_type"),
        "transaction_date": to_date_str(doc.get("transaction_date")),
        "valid_till": to_date_str(doc.get("valid_till")),
        "currency": doc.get("currency"),
        "conversion_rate": doc.get("conversion_rate"),
        "total_qty": doc.get("total_qty"),
        "net_total": doc.get("net_total"),
        "total": doc.get("total"),
        "total_taxes": doc.get("total_taxes_and_charges"),
        "discount_amount": doc.get("discount_amount"),
        "discount_percentage": doc.get("additional_discount_percentage"),
        "grand_total": doc.get("grand_total"),
        "rounded_total": doc.get("rounded_total"),
        "base_grand_total": doc.get("base_grand_total"),
        "company": doc.get("company"),
        "opportunity_id": doc.get("opportunity"),
        "source": doc.get("utm_source") or doc.get("source"),
        "doc_status": docstatus_label(doc.get("docstatus")),
        "created_at": to_iso8601_utc(doc.get("creation")),
        "updated_at": to_iso8601_utc(doc.get("modified")),
    }
    cleaned = {"external_id": record["external_id"], **_clean(record)}
    cleaned["items"] = items  # always include (possibly empty) the line items
    return cleaned


# Maps the ERPNext DocType -> (Brew93 resource, builder). Single source of the
# resource routing so outbound/inbound stay consistent.
RESOURCE_BUILDERS = {
    "Lead": ("leads", build_lead_record),
    "Opportunity": ("deals", build_opportunity_record),
    "Customer": ("customers", build_customer_record),
    "Contact": ("contacts", build_contact_record),
    "Quotation": ("quotations", build_quotation_record),
}

# Brew93 event_type prefix per resource (event names are singular).
EVENT_TYPE_PREFIX = {
    "leads": "lead",
    "deals": "opportunity",
    "customers": "customer",
    "contacts": "contact",
    "quotations": "quotation",
}

EVENT_SCHEMA_VERSION = 1


def event_type(resource: str, action: str) -> str:
    """('leads', 'upserted') -> 'lead.upserted'. action in {'upserted','deleted'}."""
    return f"{EVENT_TYPE_PREFIX[resource]}.{action}"


def build_event_envelope(
    resource: str,
    action: str,
    event_id: str,
    tenant_id: str,
    source_site: str,
    data: dict,
    occurred_at: str | None = None,
) -> dict:
    """Wrap a record/delete in the Brew93 events envelope (schema_version 1)."""
    return {
        "event_id": event_id,
        "event_type": event_type(resource, action),
        "schema_version": EVENT_SCHEMA_VERSION,
        "occurred_at": occurred_at,
        "tenant_id": tenant_id,
        "source": "erpnext",
        "source_site": source_site,
        "data": data,
    }
