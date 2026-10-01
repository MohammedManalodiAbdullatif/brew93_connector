# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""DB-backed tests for the outbound queue: enqueue, idempotency, loop
prevention, delivery, backoff, and dead-lettering.

Run: bench --site <site> run-tests --module brew93_connector.tests.test_outbound
Each test runs inside a transaction that FrappeTestCase rolls back.
"""

import json
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from brew93_connector.api import client, outbound

SETTINGS = {
    "enabled": True,
    "events_enabled": True,
    "source_site": "rag.klyonix.in",
    "brew93_base_url": "https://example.invalid/api/v1",
    "events_url": "https://example.invalid/api/v1/integrations/erpnext/events",
    "brew93_tenant_id": "00000000-0000-0000-0000-000000000000",
    "request_timeout": 5,
    "max_retries": 3,
    "retry_backoff_base": 2.0,
    "max_backoff_seconds": 3600,
}


def _ok():
    return client.Result(True, 200, None, {"status": "ok"}, "ok")


def _permanent():
    return client.Result(False, 422, "permanent", {"error": "bad"}, "HTTP 422")


def _temporary():
    return client.Result(False, 503, "temporary", None, "HTTP 503")


class TestOutboundQueue(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")
        # A unique external_id per test method: this Frappe version rolls back
        # once per class, not per test, so shared names would collide on the
        # idempotency check. Unique names keep each test independent.
        self.ref = f"CRM-LEAD-{self._testMethodName}"
        self._patch = patch.multiple(
            "brew93_connector.api.outbound.cfg",
            is_enabled=lambda: True,
            events_enabled=lambda: True,
            get_settings=lambda: dict(SETTINGS),
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _enqueue_lead(self, name=None, status="Open"):
        name = name or self.ref
        payload = {"external_id": name, "status": status}
        return outbound.enqueue_event("Lead", name, "leads", "leads.upserted", payload)

    # --- enqueue + idempotency --------------------------------------------
    def test_enqueue_creates_pending_row(self):
        eid = self._enqueue_lead()
        self.assertTrue(eid)
        row = frappe.get_doc("Brew93 Event Queue", eid)
        self.assertEqual(row.status, "Pending")
        self.assertEqual(row.external_id, self.ref)
        self.assertEqual(row.direction, "Outbound")

    def test_identical_state_is_deduped(self):
        first = self._enqueue_lead()
        second = self._enqueue_lead()  # same payload_hash
        self.assertTrue(first)
        self.assertIsNone(second)  # no duplicate created
        count = frappe.db.count("Brew93 Event Queue", {"ref_name": self.ref})
        self.assertEqual(count, 1)

    def test_changed_state_enqueues_again(self):
        self._enqueue_lead(status="Open")
        self._enqueue_lead(status="Converted")  # different hash
        count = frappe.db.count("Brew93 Event Queue", {"ref_name": self.ref})
        self.assertEqual(count, 2)

    def test_identical_state_while_failed_is_deduped(self):
        eid = self._enqueue_lead()
        frappe.db.set_value("Brew93 Event Queue", eid, "status", "Failed")  # retrying
        self.assertIsNone(self._enqueue_lead())
        self.assertEqual(frappe.db.count("Brew93 Event Queue", {"ref_name": self.ref}), 1)

    def test_state_reverted_to_earlier_value_is_sent_again(self):
        # A (delivered) -> B -> A: A is no longer the latest state, so it must go out.
        a = self._enqueue_lead(status="Open")
        frappe.db.set_value("Brew93 Event Queue", a, "status", "Delivered")
        self._enqueue_lead(status="Converted")
        self.assertTrue(self._enqueue_lead(status="Open"))
        self.assertEqual(frappe.db.count("Brew93 Event Queue", {"ref_name": self.ref}), 3)

    def test_older_event_is_superseded_by_newer(self):
        older = self._enqueue_lead(status="Open")
        newer = self._enqueue_lead(status="Converted")
        with patch.object(outbound, "_deliver_lead_to_crm", return_value=_ok()) as post_mock:
            outbound.deliver_one(older)
            post_mock.assert_not_called()
            outbound.deliver_one(newer)
            post_mock.assert_called_once()
        self.assertEqual(frappe.db.get_value("Brew93 Event Queue", older, "status"), "Superseded")
        self.assertEqual(frappe.db.get_value("Brew93 Event Queue", newer, "status"), "Delivered")

    def test_already_delivered_row_is_not_sent_twice(self):
        eid = self._enqueue_lead()
        with patch.object(outbound, "_deliver_lead_to_crm", return_value=_ok()) as post_mock:
            outbound.deliver_one(eid)
            outbound.deliver_one(eid)  # e.g. the drain racing the immediate job
            post_mock.assert_called_once()

    # --- loop prevention ---------------------------------------------------
    def test_import_flag_blocks_enqueue(self):
        frappe.flags.in_brew93_import = True
        try:
            self.assertTrue(outbound.is_integration_write())
        finally:
            frappe.flags.in_brew93_import = False

    def test_integration_user_is_a_loop_write(self):
        # simulated: the integration user's writes must never emit events
        original = frappe.session.user
        frappe.set_user("Administrator")
        try:
            frappe.session.user = outbound.INTEGRATION_USER
            self.assertTrue(outbound.is_integration_write())
        finally:
            frappe.set_user(original)

    # --- delivery (signed /events channel) ---------------------------------
    def test_delivery_success_marks_delivered(self):
        eid = self._enqueue_lead()
        with patch.object(outbound, "_deliver_lead_to_crm", return_value=_ok()):
            outbound.deliver_one(eid)
        row = frappe.get_doc("Brew93 Event Queue", eid)
        self.assertEqual(row.status, "Delivered")
        self.assertEqual(row.attempts, 1)
        self.assertIsNone(row.next_attempt)

    def test_generic_event_posts_valid_envelope(self):
        # unmapped/generic resources still go through the signed /events channel
        name = f"ITEM-ENV-{self._testMethodName}"
        eid = outbound.enqueue_event("Item", name, "items", "items.upserted",
                                     {"external_id": name, "item_name": "Env Co"})
        captured = {}

        def _capture(raw_body, event_id):
            captured["raw_body"] = raw_body
            captured["event_id"] = event_id
            return _ok()

        with patch.object(client, "post_event", side_effect=_capture):
            outbound.deliver_one(eid)
        body = json.loads(captured["raw_body"])
        self.assertEqual(captured["event_id"], eid)
        self.assertEqual(body["event_id"], eid)          # header == body event_id
        self.assertEqual(body["event_type"], "item.upserted")
        self.assertEqual(body["schema_version"], 1)
        self.assertEqual(body["source"], "erpnext")
        self.assertEqual(body["tenant_id"], SETTINGS["brew93_tenant_id"])
        self.assertEqual(body["data"]["external_id"], name)

    def test_lead_delivers_via_crm_not_events(self):
        # leads sync to the real Brew93 CRM (crm path), NOT the /events channel
        eid = self._enqueue_lead(status="Open")
        with patch.object(outbound, "_deliver_lead_to_crm", return_value=_ok()) as crm_mock, \
             patch.object(client, "post_event") as ev_mock:
            outbound.deliver_one(eid)
        crm_mock.assert_called_once()
        ev_mock.assert_not_called()
        self.assertEqual(frappe.get_doc("Brew93 Event Queue", eid).status, "Delivered")

    def test_permanent_failure_dead_letters_immediately(self):
        eid = self._enqueue_lead()
        with patch.object(outbound, "_deliver_lead_to_crm", return_value=_permanent()):
            outbound.deliver_one(eid)
        row = frappe.get_doc("Brew93 Event Queue", eid)
        self.assertEqual(row.status, "Dead")   # 4xx => no retry
        self.assertEqual(row.attempts, 1)
        self.assertEqual(row.http_status, 422)

    def test_temporary_failures_backoff_then_dead(self):
        eid = self._enqueue_lead()
        with patch.object(outbound, "_deliver_lead_to_crm", return_value=_temporary()):
            # attempt 1 -> Failed (retryable), 2 -> Failed, 3 -> Dead (== max_retries)
            outbound.deliver_one(eid)
            row = frappe.get_doc("Brew93 Event Queue", eid)
            self.assertEqual(row.status, "Failed")
            self.assertEqual(row.attempts, 1)
            self.assertIsNotNone(row.next_attempt)

            row.status = "Pending"  # simulate drain re-picking it
            outbound._attempt(row)
            self.assertEqual(row.status, "Failed")
            self.assertEqual(row.attempts, 2)

            outbound._attempt(row)
            self.assertEqual(row.status, "Dead")
            self.assertEqual(row.attempts, 3)
            self.assertIsNone(row.next_attempt)

    def test_generic_delete_posts_delete_envelope(self):
        name = f"ITEM-DEL-{self._testMethodName}"
        eid = outbound.enqueue_event("Item", name, "items", "items.deleted",
                                     {"external_id": name})
        captured = {}
        with patch.object(client, "post_event", side_effect=lambda rb, ev: captured.update(raw_body=rb) or _ok()):
            outbound.deliver_one(eid)
        body = json.loads(captured["raw_body"])
        self.assertEqual(body["event_type"], "item.deleted")
        self.assertEqual(body["data"], {"external_id": name})
        self.assertEqual(frappe.get_doc("Brew93 Event Queue", eid).status, "Delivered")

    def test_disabled_connector_skips_delivery(self):
        eid = self._enqueue_lead()
        with patch("brew93_connector.api.outbound.cfg.is_enabled", return_value=False), \
             patch.object(outbound, "_deliver_lead_to_crm", return_value=_ok()) as post_mock:
            outbound.deliver_one(eid)
            post_mock.assert_not_called()
        self.assertEqual(frappe.get_doc("Brew93 Event Queue", eid).status, "Pending")

    def test_events_disabled_holds_in_queue(self):
        eid = self._enqueue_lead()
        with patch("brew93_connector.api.outbound.cfg.events_enabled", return_value=False), \
             patch.object(outbound, "_deliver_lead_to_crm", return_value=_ok()) as post_mock:
            outbound.deliver_one(eid)
            post_mock.assert_not_called()
        self.assertEqual(frappe.get_doc("Brew93 Event Queue", eid).status, "Pending")
