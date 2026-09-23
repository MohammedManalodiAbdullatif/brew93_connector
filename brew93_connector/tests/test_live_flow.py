# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Local end-to-end test of the live sync, with no Brew93 involved.

Two outbound channels are exercised against a local 127.0.0.1 receiver:
  * Leads  -> Brew93's REAL CRM Leads (Bearer, admin login). The queue capture
    and loop-prevention tests below drive Lead insert/save -> doc_event ->
    Brew93 Event Queue row and assert on the QUEUE, never delivering (delivery
    would need a live CRM; that path is covered by test_outbound with mocks).
  * Everything else -> the signed /events transport. The delivery / backoff /
    supersede / dead-letter tests drive that transport with a `customers` event
    (enqueued directly) -> deliver_one -> client.post_event -> signed HTTP POST
    -> a local receiver that verifies the HMAC exactly as Brew93 must.

Settings are patched in memory only; the site's connector stays disabled.
Records get explicit names, so no naming series is touched, and everything is
rolled back by FrappeTestCase.

Run: bench --site <site> run-tests --module brew93_connector.tests.test_live_flow
"""

import http.server
import json
import threading
import uuid
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase
from frappe.utils import add_to_date, now_datetime

from brew93_connector.api import outbound, signing, v1

SECRET = "local-e2e-" + uuid.uuid4().hex
TENANT = "00000000-0000-0000-0000-000000000000"
QUEUE = "Brew93 Event Queue"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        ok, reason = signing.verify_signature(
            self.server.secret, raw,
            self.headers.get(signing.HEADER_TIMESTAMP), self.headers.get(signing.HEADER_SIGNATURE),
        )
        self.server.received.append({
            "sig_ok": ok, "reason": reason, "body": json.loads(raw),
            "event_id_header": self.headers.get(signing.HEADER_EVENT_ID),
            "content_type": self.headers.get("Content-Type"),
        })
        code = 401 if not ok else self.server.status
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": code == 200}).encode())

    def log_message(self, *args):
        pass


class TestLiveLeadFlow(FrappeTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.secret = SECRET
        cls.server.status = 200
        cls.server.received = []
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.events_url = f"http://127.0.0.1:{cls.server.server_address[1]}/api/v1/integrations/erpnext/events"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        super().tearDownClass()

    def setUp(self):
        frappe.set_user("Administrator")
        frappe.flags.in_brew93_import = False
        self.server.received.clear()
        self.server.status = 200
        self.server.secret = SECRET
        self.settings = {
            "enabled": True, "events_enabled": True, "source_site": "rag.klyonix.in",
            "brew93_base_url": "http://127.0.0.1/api/v1", "events_url": self.events_url,
            "brew93_tenant_id": TENANT, "request_timeout": 5, "max_retries": 3,
            "retry_backoff_base": 2.0, "max_backoff_seconds": 3600, "replay_window_seconds": 300,
        }
        self.enabled = True
        p = patch.multiple(
            "brew93_connector.api.settings",
            is_enabled=lambda: self.enabled,
            events_enabled=lambda: self.enabled,
            get_settings=lambda: dict(self.settings),
            get_hmac_secret=lambda: SECRET,
        )
        p.start()
        self.addCleanup(p.stop)
        # Capture the after-commit job instead of pushing it to the real Redis queue.
        ep = patch("brew93_connector.api.outbound.frappe.enqueue")
        self.enqueue = ep.start()
        self.addCleanup(ep.stop)

    # --- helpers -----------------------------------------------------------
    def _new_lead(self, **fields):
        name = f"BREW93-E2E-{uuid.uuid4().hex[:10]}"
        doc = frappe.get_doc({
            "doctype": "Lead", "first_name": "E2E", "last_name": "Live Sync",
            "email_id": f"e2e-{uuid.uuid4().hex[:8]}@example.com", "company_name": "E2E Co",
            "status": "Lead", **fields,
        })
        doc.insert(ignore_permissions=True, set_name=name)
        return doc

    def _rows(self, name):
        return frappe.get_all(QUEUE, filters={"ref_doctype": "Lead", "ref_name": name},
                              fields=["name", "status", "event_type", "attempts", "http_status", "next_attempt"],
                              order_by="creation asc")

    def _enqueue_customer(self, name=None, **data):
        # Leads now sync to Brew93's CRM; the signed /events transport carries the
        # OTHER resources. Exercise that transport (HMAC/backoff/supersede) here.
        name = name or f"CUST-E2E-{uuid.uuid4().hex[:8]}"
        payload = {"external_id": name, "customer_name": data.pop("customer_name", "E2E Cust"), **data}
        return name, outbound.enqueue_event("Customer", name, "customers", "customers.upserted", payload)

    # --- capture: local detection, no blocking HTTP ------------------------
    def test_create_lead_enqueues_one_event_and_sends_nothing_inline(self):
        with patch("brew93_connector.api.client.requests.Session.post") as http_post:
            lead = self._new_lead()
            http_post.assert_not_called()  # the save never waits on Brew93
        rows = self._rows(lead.name)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "Pending")
        self.assertEqual(rows[0].event_type, "leads.upserted")
        # Lead insert also enqueues unrelated framework jobs; look at ours only.
        ours = [c for c in self.enqueue.call_args_list if c.args and c.args[0] == "brew93_connector.api.outbound.deliver_one"]
        self.assertEqual(len(ours), 1)
        args, kwargs = ours[0]
        self.assertEqual(kwargs["queue"], "long")
        self.assertTrue(kwargs["enqueue_after_commit"])
        self.assertEqual(kwargs["event_id"], rows[0].name)

    def test_supported_crm_doctypes_are_live_by_default(self):
        contact = frappe.get_doc({"doctype": "Contact", "first_name": "E2E Contact"})
        contact.insert(ignore_permissions=True)
        self.assertEqual(len(frappe.get_all(QUEUE, filters={"ref_doctype": "Contact", "ref_name": contact.name})), 1)

    def test_disabled_connector_captures_nothing(self):
        self.enabled = False
        lead = self._new_lead()
        self.assertEqual(self._rows(lead.name), [])
        self.assertFalse(any(c.args and c.args[0].endswith("deliver_one") for c in self.enqueue.call_args_list))

    # --- delivery: signed /events event to the local receiver --------------
    # (leads now go to the CRM; the /events transport carries the rest, so the
    #  transport-level guarantees are exercised here with a `customers` event.)
    def test_create_delivers_signed_event(self):
        name, eid = self._enqueue_customer(customer_name="Buyer Co")
        outbound.deliver_one(eid)

        self.assertEqual(len(self.server.received), 1)
        got = self.server.received[0]
        self.assertTrue(got["sig_ok"], got["reason"])
        self.assertEqual(got["content_type"], "application/json")
        body = got["body"]
        self.assertEqual(got["event_id_header"], eid)
        self.assertEqual(body["event_id"], eid)
        self.assertEqual(body["event_type"], "customer.upserted")
        self.assertEqual(body["tenant_id"], TENANT)
        self.assertEqual(body["source_site"], "rag.klyonix.in")
        self.assertEqual(body["data"]["external_id"], name)
        self.assertEqual(body["data"]["customer_name"], "Buyer Co")

        row = frappe.get_doc(QUEUE, eid)
        self.assertEqual((row.status, row.attempts, row.http_status), ("Delivered", 1, 200))

    def test_edit_sends_new_event_for_same_external_id(self):
        name, first_eid = self._enqueue_customer(customer_name="Buyer Co")
        outbound.deliver_one(first_eid)

        _, second_eid = self._enqueue_customer(name=name, customer_name="Head Buyer Co")
        self.assertNotEqual(first_eid, second_eid)  # changed state => new event
        outbound.deliver_one(second_eid)

        first, second = (r["body"] for r in self.server.received)
        self.assertNotEqual(first["event_id"], second["event_id"])
        self.assertEqual(first["data"]["external_id"], second["data"]["external_id"])
        self.assertEqual(second["data"]["customer_name"], "Head Buyer Co")
        for delivered in (first_eid, second_eid):
            self.assertEqual(frappe.db.get_value(QUEUE, delivered, "status"), "Delivered")

    def test_stale_retry_is_superseded_not_sent(self):
        name, older = self._enqueue_customer(customer_name="Old")
        _, newer = self._enqueue_customer(name=name, customer_name="New")

        outbound.deliver_one(newer)
        outbound.deliver_one(older)  # e.g. a late retry of the first event

        self.assertEqual(len(self.server.received), 1)
        self.assertEqual(self.server.received[0]["body"]["data"]["customer_name"], "New")
        self.assertEqual(frappe.db.get_value(QUEUE, older, "status"), "Superseded")

    # --- failures: backoff, dead letter, recovery via the drain -------------
    def test_receiver_unavailable_backs_off_then_drain_delivers(self):
        _, eid = self._enqueue_customer()
        self.server.status = 503
        outbound.deliver_one(eid)
        row = frappe.get_doc(QUEUE, eid)
        self.assertEqual((row.status, row.http_status, row.attempts), ("Failed", 503, 1))
        self.assertGreater(row.next_attempt, now_datetime())

        # Brew93 recovers; the scheduled drain picks the row once it is due.
        self.server.status = 200
        frappe.db.set_value(QUEUE, eid, "next_attempt", add_to_date(now_datetime(), seconds=-1))
        with patch.object(frappe.db, "commit"), patch.object(frappe.db, "rollback"):
            outbound.drain_queue()
        row = frappe.get_doc(QUEUE, eid)
        self.assertEqual((row.status, row.attempts), ("Delivered", 2))

    def test_wrong_secret_is_rejected_and_retried_until_dead(self):
        self.server.secret = "a-different-secret"
        _, eid = self._enqueue_customer()
        for _ in range(3):  # max_retries = 3
            row = frappe.get_doc(QUEUE, eid)
            outbound._attempt(row)
        row = frappe.get_doc(QUEUE, eid)
        self.assertFalse(self.server.received[0]["sig_ok"])
        self.assertEqual((row.status, row.http_status), ("Dead", 401))

    def test_drain_leaves_not_yet_due_rows_alone(self):
        _, eid = self._enqueue_customer()
        frappe.db.set_value(QUEUE, eid, {"status": "Failed", "next_attempt": add_to_date(now_datetime(), hours=1)})
        with patch.object(frappe.db, "commit"), patch.object(frappe.db, "rollback"):
            outbound.drain_queue()  # may deliver OTHER due rows left by earlier tests in this class
        self.assertNotIn(eid, [r["event_id_header"] for r in self.server.received])
        self.assertEqual(frappe.db.get_value(QUEUE, eid, "status"), "Failed")

    # --- loop prevention ---------------------------------------------------
    def test_brew93_originated_lead_is_not_echoed_back(self):
        name, action = v1._apply_lead(str(uuid.uuid4()), TENANT, None,
                                      {"lead_name": "From Brew93", "email_id": f"in-{uuid.uuid4().hex[:8]}@example.com"})
        self.assertEqual(action, "created")
        self.assertEqual(self._rows(name), [])
        self.assertFalse(frappe.flags.in_brew93_import)

    def test_integration_user_write_is_not_echoed_back(self):
        with patch("brew93_connector.api.outbound.frappe.session", frappe._dict(user=outbound.INTEGRATION_USER)):
            lead = self._new_lead(lead_owner="Administrator")
        self.assertEqual(self._rows(lead.name), [])
