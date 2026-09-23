# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Inbound API (Brew93 -> ERPNext), model (i): Brew93 calls these whitelisted
methods with the dedicated integration identity.

Security invariants enforced on EVERY call:
- Authorization: caller must hold the `Brew93 Integration` role and must NOT be
  Administrator/System Manager (privileged accounts are refused this path).
- Tenant isolation: body `tenant_id` must equal the pinned tenant, else 403.
- Idempotency: records are matched on `brew93_id` (custom field), NEVER on email.
  A changed email can never create a duplicate.
- Least privilege: only an allow-listed set of fields is ever written; unknown or
  privileged fields are ignored. Writes run under the caller's own permissions.
- Loop prevention: writes are tagged `frappe.flags.in_brew93_import` so the
  outbound doc_event does not echo the change back to Brew93.

Request:  { brew93_id, tenant_id, brew93_modified?, data: {ERPNext field names} }
Response: { ok: true, erpnext_name, action: created|updated|unchanged }
          | { ok: false, error: { code, message } }
HTTP: 200 ok · 403 auth/tenant · 417 validation (permanent) · 500 transient.
"""

from __future__ import annotations

import json

import frappe
from frappe import _
from frappe.utils import get_datetime

from brew93_connector.api import mapping
from brew93_connector.api import settings as cfg
from brew93_connector.api.constants import INTEGRATION_ROLE

# ERPNext Lead fields Brew93 may write. Everything else in `data` is ignored.
ALLOWED_LEAD_FIELDS = {
    "lead_name", "salutation", "first_name", "middle_name", "last_name",
    "email_id", "mobile_no", "phone", "whatsapp_no", "company_name", "job_title",
    "website", "industry", "market_segment", "territory", "city", "state",
    "country", "no_of_employees", "annual_revenue", "qualification_status",
    "type", "request_type",
}
_ERP_LEAD_STATUSES = set(mapping.LEAD_STATUS_BREW93_TO_ERP.values()) | set(
    mapping.LEAD_STATUS_ERP_TO_BREW93.keys()
)

# ERPNext Opportunity fields Brew93 may write (ERPNext names). Party, status,
# sales_stage, source, company and transaction_date are handled specially below.
ALLOWED_OPPORTUNITY_FIELDS = {
    "title", "opportunity_amount", "base_opportunity_amount", "currency",
    "conversion_rate", "probability", "expected_closing", "opportunity_type", "customer_name",
    "contact_email", "contact_mobile", "no_of_employees", "annual_revenue",
    "industry", "market_segment", "territory", "city", "state", "country",
    "order_lost_reason",
}
# Coarse Brew93 deal lifecycle -> ERPNext Opportunity status. Passthrough for a
# value already in the ERPNext set.
OPP_STATUS_MAP = {"open": "Open", "won": "Converted", "lost": "Lost"}
_ERP_OPP_STATUSES = {"Open", "Quotation", "Converted", "Lost", "Replied", "Closed"}
_VALID_PARTY_TYPES = ("Customer", "Lead", "Prospect")

# ERPNext Customer fields Brew93 may write. customer_group/territory (mandatory
# Links) are defaulted; industry/market_segment are Links set only if they exist.
ALLOWED_CUSTOMER_FIELDS = {
    "customer_name", "customer_type", "tax_id", "website", "default_currency",
    "default_price_list", "account_manager", "language", "customer_details",
    "disabled", "is_frozen",
}
_CUSTOMER_LINK_FIELDS = {"industry": "Industry Type", "market_segment": "Market Segment"}

# ERPNext Contact scalar fields Brew93 may write. Email/phone/party are handled
# via child tables below.
ALLOWED_CONTACT_FIELDS = {
    "first_name", "middle_name", "last_name", "salutation", "designation",
    "department", "company_name", "gender", "status", "is_primary_contact",
    "unsubscribed",
}

ALLOWED_QUOTATION_FIELDS = {
    "title", "quotation_to", "party_name", "customer_name", "order_type",
    "transaction_date", "valid_till", "currency", "conversion_rate",
    "total_qty", "net_total", "total", "total_taxes_and_charges",
    "discount_amount", "additional_discount_percentage", "grand_total",
    "rounded_total", "base_grand_total", "company", "opportunity",
}


class _ApiError(Exception):
    def __init__(self, code, message, http=417):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http = http


def _existing_name(doctype, brew93_id, tenant_id):
    """Resolve an external id only inside the pinned tenant.

    A duplicate id belonging to another tenant is an explicit conflict, not an
    invitation to update that row or silently create an ambiguous mapping.
    """
    rows = frappe.get_all(
        doctype,
        filters={"brew93_id": brew93_id},
        fields=["name", "brew93_tenant_id"],
        limit=2,
    )
    for row in rows:
        if str(row.brew93_tenant_id) == str(tenant_id):
            return row.name
    if rows:
        raise _ApiError("tenant_mismatch", "This Brew93 ID belongs to another tenant.", 403)
    return None


def _require_integration_identity():
    user = frappe.session.user
    if user in ("Administrator", "Guest"):
        raise _ApiError("forbidden", "This endpoint is not available to this account.", 403)
    roles = set(frappe.get_roles(user))
    if "System Manager" in roles or INTEGRATION_ROLE not in roles:
        raise _ApiError("forbidden", "Caller lacks the Brew93 Integration role.", 403)


def _validate_tenant(tenant_id):
    pinned = cfg.get_settings().get("brew93_tenant_id")
    if not pinned:
        raise _ApiError("not_configured", "Connector tenant is not configured.", 503)
    if not tenant_id or str(tenant_id) != str(pinned):
        raise _ApiError("tenant_mismatch", "tenant_id does not match the pinned tenant.", 403)


def _coerce_data(data):
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            raise _ApiError("bad_request", "data must be a JSON object.")
    if not isinstance(data, dict):
        raise _ApiError("bad_request", "data must be an object.")
    return data


def _map_lead_status(value):
    if not value:
        return None
    v = str(value).strip()
    if v in mapping.LEAD_STATUS_BREW93_TO_ERP:          # a Brew93 enum value
        return mapping.LEAD_STATUS_BREW93_TO_ERP[v]
    if v in _ERP_LEAD_STATUSES:                          # already an ERPNext value
        return v
    return None  # unknown -> leave the field untouched


def _synced_at(brew93_modified):
    """Normalize inbound ISO-8601 timestamps to a MariaDB-safe naive datetime."""
    if not brew93_modified:
        return frappe.utils.now()
    try:
        dt = get_datetime(brew93_modified)
        if getattr(dt, "tzinfo", None) is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except Exception:
        return frappe.utils.now()


def _apply_lead(brew93_id, tenant_id, brew93_modified, data):
    existing = _existing_name("Lead", brew93_id, tenant_id)
    doc = frappe.get_doc("Lead", existing) if existing else frappe.new_doc("Lead")

    # Optional last-write-wins guard: skip if our copy is already newer.
    if existing and brew93_modified and doc.get("brew93_synced_at"):
        try:
            if _synced_at(doc.get("brew93_synced_at")) >= _synced_at(brew93_modified):
                return doc.name, "unchanged"
        except Exception:
            pass

    for field in ALLOWED_LEAD_FIELDS:
        if field in data:
            doc.set(field, data[field])

    status = _map_lead_status(data.get("status"))
    if status:
        doc.status = status
    if not doc.get("status"):
        doc.status = "Lead"  # required field default for new docs

    src = data.get("source") or data.get("utm_source")
    if src and frappe.db.exists("Lead Source", src):
        doc.utm_source = src  # never auto-create master data from inbound

    doc.brew93_id = brew93_id
    doc.brew93_tenant_id = tenant_id
    doc.brew93_synced_at = _synced_at(brew93_modified)

    frappe.flags.in_brew93_import = True
    try:
        if existing:
            doc.save()
            action = "updated"
        else:
            doc.insert()
            action = "created"
    finally:
        frappe.flags.in_brew93_import = False
    return doc.name, action


def _map_opp_status(value):
    if not value:
        return None
    v = str(value).strip()
    if v.lower() in OPP_STATUS_MAP:
        return OPP_STATUS_MAP[v.lower()]
    if v in _ERP_OPP_STATUSES:
        return v
    return None


def _default_company():
    return (
        frappe.conf.get("brew93_default_company")
        or frappe.db.get_single_value("Global Defaults", "default_company")
        or frappe.db.get_value("Company", {}, "name")
    )


def _apply_opportunity(brew93_id, tenant_id, brew93_modified, data):
    existing = _existing_name("Opportunity", brew93_id, tenant_id)
    doc = frappe.get_doc("Opportunity", existing) if existing else frappe.new_doc("Opportunity")

    if existing and brew93_modified and doc.get("brew93_synced_at"):
        try:
            if _synced_at(doc.get("brew93_synced_at")) >= _synced_at(brew93_modified):
                return doc.name, "unchanged"
        except Exception:
            pass

    # Party is mandatory + immutable on ERPNext Opportunity. Brew93 must send the
    # ERPNext docname of an ALREADY-SYNCED Lead/Customer (it holds this in its
    # external_refs). We never fabricate a party from a Brew93 uuid.
    if not existing:
        party_type = data.get("party_type") or "Lead"
        party_name = data.get("party_name")
        if party_type not in _VALID_PARTY_TYPES:
            raise _ApiError("party_type_invalid", f"party_type must be one of {_VALID_PARTY_TYPES}.")
        if not party_name or not frappe.db.exists(party_type, party_name):
            raise _ApiError(
                "party_unresolved",
                "party_name must be an already-synced ERPNext record; sync the Lead/Customer first.",
            )
        doc.opportunity_from = party_type
        doc.party_name = party_name

        company = data.get("company") or _default_company()
        if not company:
            raise _ApiError("no_company", "No company configured for the Opportunity.")
        doc.company = company
        doc.transaction_date = data.get("transaction_date") or (get_datetime(brew93_modified).date() if brew93_modified else frappe.utils.today())

    for field in ALLOWED_OPPORTUNITY_FIELDS:
        if field in data:
            doc.set(field, data[field])

    status = _map_opp_status(data.get("status"))
    if status:
        doc.status = status

    ss = data.get("sales_stage")
    if ss and frappe.db.exists("Sales Stage", ss):
        doc.sales_stage = ss  # Link; no auto-create of master data

    src = data.get("source") or data.get("utm_source")
    if src and frappe.db.exists("Lead Source", src):
        doc.utm_source = src

    doc.brew93_id = brew93_id
    doc.brew93_tenant_id = tenant_id
    doc.brew93_synced_at = _synced_at(brew93_modified)

    frappe.flags.in_brew93_import = True
    try:
        if existing:
            doc.save()
            action = "updated"
        else:
            doc.insert()
            action = "created"
    finally:
        frappe.flags.in_brew93_import = False
    return doc.name, action


def _set_primary_email(doc, email):
    """Idempotently make `email` the primary; never duplicates a row."""
    found = False
    for row in doc.get("email_ids", []):
        if (row.email_id or "").lower() == email.lower():
            row.is_primary = 1
            found = True
        else:
            row.is_primary = 0
    if not found:
        doc.append("email_ids", {"email_id": email, "is_primary": 1})


def _set_primary_phone(doc, number, is_mobile):
    flag = "is_primary_mobile_no" if is_mobile else "is_primary_phone"
    for row in doc.get("phone_nos", []):
        if row.phone == number:
            row.set(flag, 1)
            return
    doc.append("phone_nos", {"phone": number, flag: 1})


def _apply_contact(brew93_id, tenant_id, brew93_modified, data):
    existing = _existing_name("Contact", brew93_id, tenant_id)
    doc = frappe.get_doc("Contact", existing) if existing else frappe.new_doc("Contact")

    if existing and brew93_modified and doc.get("brew93_synced_at"):
        try:
            if _synced_at(doc.get("brew93_synced_at")) >= _synced_at(brew93_modified):
                return doc.name, "unchanged"
        except Exception:
            pass

    for field in ALLOWED_CONTACT_FIELDS:
        if field in data:
            doc.set(field, data[field])

    # Contact requires a first_name; derive a fallback on create.
    if not doc.get("first_name"):
        email0 = data.get("email") or ""
        doc.first_name = email0.split("@")[0] if email0 else "Contact"

    if data.get("email"):
        _set_primary_email(doc, data["email"])
    if data.get("mobile"):
        _set_primary_phone(doc, data["mobile"], is_mobile=True)
    if data.get("phone"):
        _set_primary_phone(doc, data["phone"], is_mobile=False)

    # Party link is optional for a Contact; link only if it resolves, else skip.
    pt, pn = data.get("party_type"), data.get("party_name")
    if pt and pn and pt in _VALID_PARTY_TYPES and frappe.db.exists(pt, pn):
        if not any(l.link_doctype == pt and l.link_name == pn for l in doc.get("links", [])):
            doc.append("links", {"link_doctype": pt, "link_name": pn})

    doc.brew93_id = brew93_id
    doc.brew93_tenant_id = tenant_id
    doc.brew93_synced_at = _synced_at(brew93_modified)

    frappe.flags.in_brew93_import = True
    try:
        if existing:
            doc.save()
            action = "updated"
        else:
            doc.insert()
            action = "created"
    finally:
        frappe.flags.in_brew93_import = False
    return doc.name, action


def _default_customer_group():
    # Customer.customer_group must be a LEAF (non-group) node.
    return (
        frappe.conf.get("brew93_default_customer_group")
        or frappe.db.get_single_value("Selling Settings", "customer_group")
        or frappe.db.get_value("Customer Group", {"is_group": 0}, "name")
    )


def _default_territory():
    return (
        frappe.conf.get("brew93_default_territory")
        or frappe.db.get_single_value("Selling Settings", "territory")
        or frappe.db.get_value("Territory", {"is_group": 0}, "name")
    )


def _apply_customer(brew93_id, tenant_id, brew93_modified, data):
    existing = _existing_name("Customer", brew93_id, tenant_id)
    doc = frappe.get_doc("Customer", existing) if existing else frappe.new_doc("Customer")

    if existing and brew93_modified and doc.get("brew93_synced_at"):
        try:
            if _synced_at(doc.get("brew93_synced_at")) >= _synced_at(brew93_modified):
                return doc.name, "unchanged"
        except Exception:
            pass

    for field in ALLOWED_CUSTOMER_FIELDS:
        if field in data:
            doc.set(field, data[field])

    # Link fields: set only if the master value already exists (no auto-create).
    for field, link_dt in _CUSTOMER_LINK_FIELDS.items():
        val = data.get(field)
        if val and frappe.db.exists(link_dt, val):
            doc.set(field, val)

    if not doc.get("customer_name"):
        raise _ApiError("bad_request", "customer_name is required.")
    if not doc.get("customer_type"):
        doc.customer_type = "Company"

    cg = data.get("customer_group")
    if not doc.get("customer_group"):
        doc.customer_group = cg if (cg and frappe.db.exists("Customer Group", cg)) else _default_customer_group()
    terr = data.get("territory")
    if not doc.get("territory"):
        doc.territory = terr if (terr and frappe.db.exists("Territory", terr)) else _default_territory()

    ln = data.get("lead_name") or data.get("lead_id")
    if ln and frappe.db.exists("Lead", ln):
        doc.lead_name = ln

    doc.brew93_id = brew93_id
    doc.brew93_tenant_id = tenant_id
    doc.brew93_synced_at = _synced_at(brew93_modified)

    frappe.flags.in_brew93_import = True
    try:
        if existing:
            doc.save()
            action = "updated"
        else:
            doc.insert()
            action = "created"
    finally:
        frappe.flags.in_brew93_import = False
    return doc.name, action


def _apply_quotation_items(doc, items):
    """Replace Quotation Item child rows from a validated items list.

    Only allow-listed scalar keys are copied; unknown keys are ignored the same
    way top-level fields are. Totals are left to ERPNext's calculate_taxes.
    """
    if not isinstance(items, list):
        return
    allowed = {"item_code", "item_name", "description", "qty", "rate", "amount", "uom"}
    doc.set("items", [])
    for raw in items:
        if not isinstance(raw, dict):
            continue
        row = {k: raw[k] for k in allowed if k in raw}
        if not row.get("qty") and not row.get("rate") and not row.get("amount"):
            continue
        row.setdefault("qty", 1)
        doc.append("items", row)


def _apply_quotation(brew93_id, tenant_id, brew93_modified, data):
    existing = _existing_name("Quotation", brew93_id, tenant_id)
    doc = frappe.get_doc("Quotation", existing) if existing else frappe.new_doc("Quotation")

    if existing and brew93_modified and doc.get("brew93_synced_at"):
        try:
            if _synced_at(doc.get("brew93_synced_at")) >= _synced_at(brew93_modified):
                return doc.name, "unchanged"
        except Exception:
            pass

    if not existing:
        company = data.get("company") or _default_company()
        if not company:
            raise _ApiError("no_company", "No company configured for the Quotation.")
        doc.company = company
        if not data.get("quotation_to") or not data.get("party_name"):
            raise _ApiError("party_unresolved", "quotation_to and party_name are required.")
        if data["quotation_to"] not in ("Customer", "Lead", "Prospect") or not frappe.db.exists(data["quotation_to"], data["party_name"]):
            raise _ApiError("party_unresolved", "party_name must resolve to an ERPNext party.")

    for field in ALLOWED_QUOTATION_FIELDS:
        if field in data:
            doc.set(field, data[field])
    if "items" in data:
        _apply_quotation_items(doc, data["items"])
    doc.brew93_id = brew93_id
    doc.brew93_tenant_id = tenant_id
    doc.brew93_synced_at = _synced_at(brew93_modified)

    frappe.flags.in_brew93_import = True
    try:
        if existing:
            doc.save()
            action = "updated"
        else:
            doc.insert()
            action = "created"
    finally:
        frappe.flags.in_brew93_import = False
    return doc.name, action


def _handle(resource_apply, **kwargs):
    """Shared envelope: auth, validate, apply, structured response + HTTP code."""
    try:
        if not cfg.is_enabled():
            raise _ApiError("disabled", "Connector is disabled.", 503)
        _require_integration_identity()

        brew93_id = kwargs.get("brew93_id")
        tenant_id = kwargs.get("tenant_id")
        if not brew93_id:
            raise _ApiError("bad_request", "brew93_id is required.")
        _validate_tenant(tenant_id)
        data = _coerce_data(kwargs.get("data") or {})

        name, action = resource_apply(brew93_id, tenant_id, kwargs.get("brew93_modified"), data)
        return {"ok": True, "erpnext_name": name, "action": action}
    except _ApiError as e:
        frappe.local.response["http_status_code"] = e.http
        return {"ok": False, "error": {"code": e.code, "message": e.message}}
    except frappe.PermissionError:
        frappe.local.response["http_status_code"] = 403
        return {"ok": False, "error": {"code": "forbidden", "message": "Permission denied."}}
    except Exception:
        frappe.log_error(title="brew93_connector: inbound upsert failed", message=frappe.get_traceback())
        frappe.local.response["http_status_code"] = 500
        return {"ok": False, "error": {"code": "internal_error", "message": "Unexpected error."}}


@frappe.whitelist(methods=["POST"])
def upsert_lead(brew93_id=None, tenant_id=None, brew93_modified=None, data=None):
    return _handle(_apply_lead, brew93_id=brew93_id, tenant_id=tenant_id,
                   brew93_modified=brew93_modified, data=data)


@frappe.whitelist(methods=["POST"])
def upsert_opportunity(brew93_id=None, tenant_id=None, brew93_modified=None, data=None):
    return _handle(_apply_opportunity, brew93_id=brew93_id, tenant_id=tenant_id,
                   brew93_modified=brew93_modified, data=data)


@frappe.whitelist(methods=["POST"])
def upsert_contact(brew93_id=None, tenant_id=None, brew93_modified=None, data=None):
    return _handle(_apply_contact, brew93_id=brew93_id, tenant_id=tenant_id,
                   brew93_modified=brew93_modified, data=data)


@frappe.whitelist(methods=["POST"])
def upsert_customer(brew93_id=None, tenant_id=None, brew93_modified=None, data=None):
    return _handle(_apply_customer, brew93_id=brew93_id, tenant_id=tenant_id,
                   brew93_modified=brew93_modified, data=data)


@frappe.whitelist(methods=["POST"])
def upsert_quotation(brew93_id=None, tenant_id=None, brew93_modified=None, data=None):
    return _handle(_apply_quotation, brew93_id=brew93_id, tenant_id=tenant_id,
                   brew93_modified=brew93_modified, data=data)
