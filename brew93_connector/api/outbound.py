# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Outbound sync: ERPNext -> Brew93, via a durable queue with backoff.

Flow:
  doc_event (on_update/on_trash)
    -> enqueue a `Brew93 Event Queue` row (fast DB insert, idempotent)
    -> schedule an immediate background drain (after_commit)
  drain_queue() [also scheduled every 5 min as the retry safety net]
    -> deliver due rows; classify; backoff or dead-letter.

Safety properties:
- NO-OP unless Brew93 Connector Settings.enabled.
- Loop prevention: writes made BY the integration (inbound import) never enqueue.
- Idempotent enqueue: identical state (same payload_hash) is not re-queued.
- Bounded retries: after max_retries a row goes to `Dead` (no infinite loop).
- Never logs secrets; only the queue row's last_error (HTTP status / exception class).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid

import frappe
from frappe.utils import add_to_date, now_datetime

from brew93_connector.api import client
from brew93_connector.api import mapping
from brew93_connector.api import settings as cfg
from brew93_connector.api.constants import INTEGRATION_USER

QUEUE_DOCTYPE = "Brew93 Event Queue"
DRAIN_BATCH = 50


# --- loop prevention -------------------------------------------------------
def is_integration_write() -> bool:
    """True when the current write originates from the integration itself."""
    if getattr(frappe.flags, "in_brew93_import", False):
        return True
    if getattr(frappe.flags, "in_install", False) or getattr(frappe.flags, "in_migrate", False):
        return True
    return frappe.session and frappe.session.user == INTEGRATION_USER


def _payload_hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _is_uuid(value) -> bool:
    return bool(value) and bool(_UUID_RE.match(str(value)))


# --- doc events ------------------------------------------------------------
def on_document_update(doc, method=None):
    _maybe_enqueue(doc, deleted=False)


def on_document_trash(doc, method=None):
    _maybe_enqueue(doc, deleted=True)


def _maybe_enqueue(doc, deleted: bool):
    try:
        if not cfg.is_enabled() or is_integration_write():
            return
        if doc.doctype not in mapping.RESOURCE_BUILDERS or doc.doctype not in cfg.get_live_doctypes():
            return
        resource, builder = mapping.RESOURCE_BUILDERS[doc.doctype]
        if deleted:
            event_type = f"{resource}.deleted"
            # capture brew93_id now (the doc is about to be gone) so the CRM
            # delete can target the Brew93 record.
            payload = {"external_id": doc.name, "brew93_id": doc.get("brew93_id"), "owner": doc.owner}
        else:
            event_type = f"{resource}.upserted"
            payload = builder(doc.as_dict(), cfg.get_settings()["source_site"])
            payload["owner"] = doc.owner
        enqueue_event(doc.doctype, doc.name, resource, event_type, payload)
    except Exception:
        # Outbound must never break the user's ERPNext transaction.
        frappe.log_error(title="brew93_connector: enqueue failed", message=frappe.get_traceback())


def enqueue_event(ref_doctype, ref_name, resource, event_type, payload) -> str | None:
    phash = _payload_hash({"event_type": event_type, "payload": payload})

    # Idempotent: skip if the identical state is already the document's latest
    # queued/retrying/delivered event. Compared against the LATEST row only, so
    # A -> B -> A still sends A (otherwise Brew93 would be left holding B).
    latest = frappe.get_all(
        QUEUE_DOCTYPE,
        filters={"ref_doctype": ref_doctype, "ref_name": ref_name},
        fields=["payload_hash", "status"],
        order_by="creation desc",
        limit=1,
    )
    if latest and latest[0].payload_hash == phash and latest[0].status in ("Pending", "Failed", "Delivered"):
        return None

    event_id = str(uuid.uuid4())
    row = frappe.get_doc(
        {
            "doctype": QUEUE_DOCTYPE,
            "event_id": event_id,
            "direction": "Outbound",
            "event_type": event_type,
            "status": "Pending",
            "ref_doctype": ref_doctype,
            "ref_name": ref_name,
            "brew93_resource": resource,
            "external_id": payload.get("external_id"),
            "payload_hash": phash,
            "payload": json.dumps(payload, default=str),
            "initiating_user": payload.get("owner") or (frappe.session.user if frappe.session else None),
            "attempts": 0,
            "next_attempt": now_datetime(),
        }
    )
    row.flags.ignore_permissions = True
    row.insert(ignore_permissions=True)

    try:
        frappe.enqueue(
            "brew93_connector.api.outbound.deliver_one",
            queue="long",
            enqueue_after_commit=True,
            event_id=event_id,
        )
    except Exception:
        # Durable event queue row is already stored; scheduled drain will deliver it.
        pass
    return event_id


# --- delivery --------------------------------------------------------------
def deliver_one(event_id: str):
    if not cfg.is_enabled() or not cfg.events_enabled():
        return  # events transport off => hold in queue until enabled
    if not frappe.db.exists(QUEUE_DOCTYPE, event_id):
        return
    # Row lock: the immediate job and the scheduled drain can race for the same
    # row; the loser waits, then sees it is no longer Pending/Failed.
    row = frappe.get_doc(QUEUE_DOCTYPE, event_id, for_update=True)
    if row.status not in ("Pending", "Failed"):
        return
    _attempt(row)


def drain_queue():
    """Scheduled safety net: deliver all due Pending/Failed rows."""
    if not cfg.is_enabled() or not cfg.events_enabled():
        return
    due = frappe.get_all(
        QUEUE_DOCTYPE,
        filters={"status": ["in", ["Pending", "Failed"]], "next_attempt": ["<=", now_datetime()]},
        pluck="name",
        limit=DRAIN_BATCH,
        order_by="next_attempt asc",
    )
    for event_id in due:
        try:
            row = frappe.get_doc(QUEUE_DOCTYPE, event_id, for_update=True)
            if row.status not in ("Pending", "Failed"):
                frappe.db.commit()  # delivered by the immediate job meanwhile; release lock
                continue
            _attempt(row)
            frappe.db.commit()
        except Exception:
            frappe.db.rollback()
            frappe.log_error(title="brew93_connector: drain failed", message=frappe.get_traceback())


def _is_superseded(row) -> bool:
    """True when a newer event exists for the same document.

    Each event carries the full document state, so only the newest one matters.
    Without this, a retry of an older event could land after a newer one and
    leave Brew93 holding stale data.
    """
    return bool(
        frappe.db.exists(
            QUEUE_DOCTYPE,
            {"ref_doctype": row.ref_doctype, "ref_name": row.ref_name,
             "creation": [">", row.creation], "name": ["!=", row.name]},
        )
    )


CRM_RESOURCE_CONFIG = {
    "leads": ("Lead", mapping.build_crm_lead_payload, "leads"),
    "deals": ("Opportunity", mapping.build_crm_deal_payload, "deals"),
    "contacts": ("Contact", mapping.build_crm_contact_payload, "contacts"),
    "customers": ("Customer", mapping.build_crm_company_payload, "companies"),
    "quotations": ("Quotation", mapping.build_crm_quote_payload, "quotes"),
}


def _deliver_to_crm(row, action):
    """Sync a document to Brew93's CRM direct endpoints via workspace-admin bearer login.
    Stores the returned Brew93 ID on the ERPNext document so subsequent edits update in place.
    """
    config = CRM_RESOURCE_CONFIG.get(row.brew93_resource)
    if not config:
        return client.Result(False, 400, "permanent", None, f"Unsupported CRM resource: {row.brew93_resource}")

    doctype, builder, endpoint_resource = config
    payload_json = json.loads(row.payload or "{}")

    if action == "deleted":
        bid = payload_json.get("brew93_id")
        if not bid:
            return client.Result(True, 200, None, {"skipped": f"no brew93 {endpoint_resource} id"}, "ok")
        return client.crm_delete(endpoint_resource, bid, payload_json.get("owner"))

    if not frappe.db.exists(doctype, row.ref_name):
        return client.Result(True, 200, None, {"skipped": f"{doctype} removed"}, "ok")

    doc = frappe.get_doc(doctype, row.ref_name)
    values = cfg.get_settings()
    crm_payload = builder(doc.as_dict(), values["source_site"])
    bid = doc.get("brew93_id")
    if bid and not _is_uuid(bid):
        bid = None

    result = client.crm_upsert(endpoint_resource, bid, crm_payload, doc.owner)
    if result.ok and not bid and isinstance(result.body, dict):
        data = result.body.get("data") if isinstance(result.body.get("data"), dict) else result.body
        new_id = (data or {}).get("id")
        if new_id:
            frappe.flags.in_brew93_import = True  # silent write, no loop
            try:
                update_fields = {"brew93_id": new_id}
                meta = frappe.get_meta(doctype)
                if meta.has_field("brew93_tenant_id"):
                    update_fields["brew93_tenant_id"] = values.get("brew93_tenant_id")
                if meta.has_field("brew93_synced_at"):
                    update_fields["brew93_synced_at"] = frappe.utils.now()
                frappe.db.set_value(doctype, doc.name, update_fields, update_modified=False)
                frappe.db.commit()
            finally:
                frappe.flags.in_brew93_import = False
    return result


def _deliver_lead_to_crm(row, action):
    return _deliver_to_crm(row, action)


def _deliver_deal_to_crm(row, action):
    return _deliver_to_crm(row, action)


def _attempt(row):
    if _is_superseded(row):
        row.status = "Superseded"
        row.next_attempt = None
        row.last_error = "superseded by a newer event for the same document"
        row.flags.ignore_permissions = True
        row.save(ignore_permissions=True)
        return

    values = cfg.get_settings()
    payload = json.loads(row.payload or "{}")

    # One call to _attempt == one delivery try. Count it up front so config and
    # network failures also advance toward the dead-letter cap (no infinite loop).
    row.attempts = (row.attempts or 0) + 1
    row.last_attempt = now_datetime()

    action = "deleted" if row.event_type.endswith(".deleted") else "upserted"

    try:
        if row.brew93_resource == "leads":
            result = _deliver_lead_to_crm(row, action)
        elif row.brew93_resource == "deals":
            result = _deliver_deal_to_crm(row, action)
        elif row.brew93_resource in CRM_RESOURCE_CONFIG:
            result = _deliver_to_crm(row, action)
        else:
            # Other resources still use the signed /events channel (-> staging).
            occurred_at = payload.get("updated_at") or mapping.to_iso8601_utc(now_datetime())
            envelope = mapping.build_event_envelope(
                resource=row.brew93_resource, action=action, event_id=row.event_id,
                tenant_id=values.get("brew93_tenant_id"), source_site=values["source_site"],
                data=payload, occurred_at=occurred_at,
            )
            raw_body = json.dumps(envelope, default=str, separators=(",", ":"))
            result = client.post_event(raw_body, row.event_id)
    except client.Brew93ConfigError as exc:
        _mark_failed(row, values, None, f"config: {exc}", permanent=False)
        return
    except Exception as exc:
        _mark_failed(row, values, None, exc.__class__.__name__, permanent=False)
        return

    row.http_status = result.status_code or 0

    if result.ok:
        row.status = "Delivered"
        row.last_error = None
        row.next_attempt = None
        row.flags.ignore_permissions = True
        row.save(ignore_permissions=True)
        return

    _mark_failed(row, values, result.status_code, result.message, permanent=(result.failure_kind == "permanent"))


def _mark_failed(row, values, http_status, message, permanent: bool):
    row.http_status = http_status or 0
    row.last_error = (message or "")[:500]
    if permanent or (row.attempts or 0) >= values["max_retries"]:
        row.status = "Dead"
        row.next_attempt = None
    else:
        row.status = "Failed"
        delay = min(values["retry_backoff_base"] ** (row.attempts or 1), values["max_backoff_seconds"])
        row.next_attempt = add_to_date(now_datetime(), seconds=int(delay))
    row.flags.ignore_permissions = True
    row.save(ignore_permissions=True)
