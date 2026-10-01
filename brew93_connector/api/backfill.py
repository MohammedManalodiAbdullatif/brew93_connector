# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Operator-triggered initial ERPNext -> Brew93 backfill."""

from __future__ import annotations

import frappe
from frappe.utils import now_datetime

from brew93_connector.api.constants import INTEGRATION_ROLE
from brew93_connector.api import mapping
from brew93_connector.api import outbound
from brew93_connector.api import settings as cfg

JOB_DOCTYPE = "Brew93 Backfill Job"
MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100


def _require_backfill_access():
    if frappe.session.user != "Administrator" and not {"System Manager", INTEGRATION_ROLE}.intersection(
        frappe.get_roles()
    ):
        frappe.throw("Only an Administrator, System Manager, or Brew93 Integration user may run a backfill.", frappe.PermissionError)
    if not cfg.is_enabled():
        frappe.throw("Brew93 Connector is disabled.", frappe.ValidationError)


def _validate_request(doctype, page_size=DEFAULT_PAGE_SIZE):
    _require_backfill_access()
    if doctype not in mapping.RESOURCE_BUILDERS:
        frappe.throw("This DocType is not supported for Brew93 backfill.", frappe.ValidationError)
    try:
        page_size = min(max(int(page_size or 0), 1), MAX_PAGE_SIZE)
    except (TypeError, ValueError):
        frappe.throw("page_size must be a positive integer.", frappe.ValidationError)
    return page_size


def _validate_start(start):
    try:
        start = int(start or 0)
    except (TypeError, ValueError):
        frappe.throw("start must be a non-negative integer.", frappe.ValidationError)
    if start < 0:
        frappe.throw("start must be a non-negative integer.", frappe.ValidationError)
    return start


def _job_response(job):
    return {
        "job_id": job.job_id,
        "doctype": job.doctype_name,
        "status": job.status,
        "page_size": job.page_size,
        "total": job.total,
        "processed": job.processed,
        "queued": job.queued,
        "skipped": job.skipped,
        "last_name": job.last_name,
        "error": job.error,
        "cancel_requested": bool(job.cancel_requested),
        "started_at": job.started_at,
        "finished_at": job.finished_at,
    }


@frappe.whitelist(methods=["POST"])
def enqueue_backfill(doctype: str, limit: int = 500, start: int = 0) -> dict:
    """Queue a bounded page of existing documents; delivery remains asynchronous."""
    limit = _validate_request(doctype, limit)
    start = _validate_start(start)
    resource, builder = mapping.RESOURCE_BUILDERS[doctype]
    source_site = cfg.get_settings().get("source_site")
    names = frappe.get_all(doctype, pluck="name", limit_start=start, limit_page_length=limit, order_by="name asc")
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


@frappe.whitelist(methods=["POST"])
def start_backfill(doctype: str, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    """Create a durable backfill job; each record is still sent through the event queue."""
    page_size = _validate_request(doctype, page_size)
    job_id = frappe.generate_hash(length=32)
    job = frappe.get_doc({
        "doctype": JOB_DOCTYPE,
        "job_id": job_id,
        "doctype_name": doctype,
        "status": "Queued",
        "page_size": page_size,
        "total": frappe.db.count(doctype),
        "processed": 0,
        "queued": 0,
        "skipped": 0,
    })
    job.flags.ignore_permissions = True
    job.insert(ignore_permissions=True)
    frappe.enqueue(
        "brew93_connector.api.backfill.run_backfill",
        queue="long",
        timeout=1500,
        enqueue_after_commit=True,
        job_id=job_id,
        backfill_job_id=job_id,
    )
    return {"job_id": job_id, "status": "Queued"}


@frappe.whitelist(methods=["GET"])
def get_backfill_status(job_id: str) -> dict:
    _require_backfill_access()
    if not frappe.db.exists(JOB_DOCTYPE, job_id):
        frappe.throw("Backfill job not found.", frappe.DoesNotExistError)
    return _job_response(frappe.get_doc(JOB_DOCTYPE, job_id))


@frappe.whitelist(methods=["POST"])
def cancel_backfill(job_id: str) -> dict:
    _require_backfill_access()
    if not frappe.db.exists(JOB_DOCTYPE, job_id):
        frappe.throw("Backfill job not found.", frappe.DoesNotExistError)
    job = frappe.get_doc(JOB_DOCTYPE, job_id, for_update=True)
    if job.status in ("Queued", "Running"):
        job.cancel_requested = 1
        job.save(ignore_permissions=True)
        frappe.db.commit()
    return _job_response(job)


def _set_job(job_id, values):
    frappe.db.set_value(JOB_DOCTYPE, job_id, values, update_modified=False)
    frappe.db.commit()


def run_backfill(backfill_job_id: str):
    """Process a job in bounded chunks, committing progress after each chunk."""
    if not frappe.db.exists(JOB_DOCTYPE, backfill_job_id):
        return
    job = frappe.get_doc(JOB_DOCTYPE, backfill_job_id, for_update=True)
    if job.status not in ("Queued", "Running"):
        return
    if job.cancel_requested:
        _set_job(backfill_job_id, {"status": "Cancelled", "finished_at": now_datetime()})
        return
    try:
        _set_job(backfill_job_id, {"status": "Running", "started_at": job.started_at or now_datetime()})
        resource, builder = mapping.RESOURCE_BUILDERS[job.doctype_name]
        source_site = cfg.get_settings().get("source_site")
        while True:
            job = frappe.get_doc(JOB_DOCTYPE, backfill_job_id)
            if job.cancel_requested:
                _set_job(backfill_job_id, {"status": "Cancelled", "finished_at": now_datetime()})
                return
            filters = {"name": [">", job.last_name]} if job.last_name else {}
            names = frappe.get_all(job.doctype_name, filters=filters, pluck="name",
                                   limit_page_length=job.page_size, order_by="name asc")
            if not names:
                _set_job(backfill_job_id, {"status": "Completed", "finished_at": now_datetime()})
                return
            queued = skipped = 0
            for name in names:
                doc = frappe.get_doc(job.doctype_name, name)
                if outbound.enqueue_event(job.doctype_name, name, resource, f"{resource}.upserted",
                                          builder(doc.as_dict(), source_site)):
                    queued += 1
                else:
                    skipped += 1
            _set_job(backfill_job_id, {
                "processed": job.processed + len(names),
                "queued": job.queued + queued,
                "skipped": job.skipped + skipped,
                "last_name": names[-1],
            })
    except Exception as exc:
        frappe.db.rollback()
        _set_job(backfill_job_id, {"status": "Failed", "error": str(exc)[:500], "finished_at": now_datetime()})
