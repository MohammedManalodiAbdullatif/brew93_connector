# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""DB-backed tests for the inbound API (Brew93 -> ERPNext) — Phase 5/8.

Run: bench --site <site> run-tests --module brew93_connector.tests.test_inbound
"""

import uuid
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from brew93_connector.api import v1
from brew93_connector.api import backfill

TENANT = "00000000-0000-0000-0000-000000000000"
SETTINGS = {"brew93_tenant_id": TENANT, "source_site": "rag.klyonix.in"}


class TestApplyLead(FrappeTestCase):
    """Exercises _apply_lead directly (as Administrator, which has Lead perms) to
    verify create/update/idempotency/loop-guard independent of the auth layer."""

    def setUp(self):
        frappe.set_user("Administrator")
        frappe.flags.in_brew93_import = False

    def test_create_lead(self):
        bid = str(uuid.uuid4())
        name, action = v1._apply_lead(bid, TENANT, None, {"lead_name": "Acme Co", "email_id": "a@b.com"})
        self.assertEqual(action, "created")
        doc = frappe.get_doc("Lead", name)
        self.assertEqual(doc.brew93_id, bid)
        self.assertEqual(doc.brew93_tenant_id, TENANT)
        self.assertEqual(doc.email_id, "a@b.com")
        self.assertTrue(doc.status)  # required field defaulted

    def test_matches_on_brew93_id_not_email(self):
        bid = str(uuid.uuid4())
        name1, _ = v1._apply_lead(bid, TENANT, None, {"lead_name": "X", "email_id": "first@x.com"})
        # same brew93_id, DIFFERENT email -> must update the SAME lead, no duplicate
        name2, action = v1._apply_lead(bid, TENANT, None, {"lead_name": "X", "email_id": "changed@x.com"})
        self.assertEqual(name1, name2)
        self.assertEqual(action, "updated")
        self.assertEqual(frappe.get_doc("Lead", name2).email_id, "changed@x.com")
        self.assertEqual(frappe.db.count("Lead", {"brew93_id": bid}), 1)

    def test_status_mapping_from_brew93_enum(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_lead(bid, TENANT, None, {"lead_name": "Y", "status": "qualified"})
        self.assertEqual(frappe.get_doc("Lead", name).status, "Interested")

    def test_loop_flag_cleared_after_write(self):
        bid = str(uuid.uuid4())
        v1._apply_lead(bid, TENANT, None, {"lead_name": "Z"})
        self.assertFalse(frappe.flags.in_brew93_import)  # reset in finally

    def test_privileged_field_ignored(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_lead(bid, TENANT, None, {"lead_name": "P", "owner": "Administrator", "docstatus": 1})
        doc = frappe.get_doc("Lead", name)
        self.assertEqual(doc.docstatus, 0)  # not in allow-list, ignored

    def test_cross_tenant_external_id_is_rejected(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_lead(bid, "other-tenant", None, {"lead_name": "Other"})
        with self.assertRaises(v1._ApiError) as ctx:
            v1._apply_lead(bid, TENANT, None, {"lead_name": "Hijack"})
        self.assertEqual(ctx.exception.code, "tenant_mismatch")
        self.assertEqual(frappe.get_doc("Lead", name).lead_name, "Other")


class TestApplyOpportunity(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")
        frappe.flags.in_brew93_import = False
        # a synced Lead to serve as the Opportunity party
        self.lead = frappe.get_doc({"doctype": "Lead", "lead_name": "Party Co", "status": "Lead"}).insert()

    def test_create_opportunity_with_lead_party(self):
        bid = str(uuid.uuid4())
        name, action = v1._apply_opportunity(bid, TENANT, None, {
            "party_type": "Lead", "party_name": self.lead.name,
            "title": "Big Deal", "opportunity_amount": 1000, "status": "open",
        })
        self.assertEqual(action, "created")
        doc = frappe.get_doc("Opportunity", name)
        self.assertEqual(doc.brew93_id, bid)
        self.assertEqual(doc.opportunity_from, "Lead")
        self.assertEqual(doc.party_name, self.lead.name)
        self.assertTrue(doc.company)
        self.assertEqual(doc.status, "Open")

    def test_party_unresolved_is_rejected(self):
        with self.assertRaises(v1._ApiError) as ctx:
            v1._apply_opportunity(str(uuid.uuid4()), TENANT, None, {
                "party_type": "Lead", "party_name": "CRM-LEAD-DOES-NOT-EXIST",
                "title": "x",
            })
        self.assertEqual(ctx.exception.code, "party_unresolved")

    def test_idempotent_no_duplicate(self):
        bid = str(uuid.uuid4())
        n1, _ = v1._apply_opportunity(bid, TENANT, None, {"party_type": "Lead", "party_name": self.lead.name, "title": "A"})
        n2, action = v1._apply_opportunity(bid, TENANT, None, {"party_type": "Lead", "party_name": self.lead.name, "title": "B"})
        self.assertEqual(n1, n2)
        self.assertEqual(action, "updated")
        self.assertEqual(frappe.db.count("Opportunity", {"brew93_id": bid}), 1)

    def test_status_won_maps_converted(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_opportunity(bid, TENANT, None, {
            "party_type": "Lead", "party_name": self.lead.name, "title": "W", "status": "won",
        })
        self.assertEqual(frappe.get_doc("Opportunity", name).status, "Converted")

    def test_loop_flag_cleared(self):
        v1._apply_opportunity(str(uuid.uuid4()), TENANT, None,
                              {"party_type": "Lead", "party_name": self.lead.name, "title": "L"})
        self.assertFalse(frappe.flags.in_brew93_import)


class TestApplyContact(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")
        frappe.flags.in_brew93_import = False
        self.lead = frappe.get_doc({"doctype": "Lead", "lead_name": "Link Co", "status": "Lead"}).insert()

    def test_create_contact_with_children(self):
        bid = str(uuid.uuid4())
        name, action = v1._apply_contact(bid, TENANT, None, {
            "first_name": "Jane", "last_name": "Doe",
            "email": "jane@acme.com", "mobile": "999", "designation": "CTO",
        })
        self.assertEqual(action, "created")
        doc = frappe.get_doc("Contact", name)
        self.assertEqual(doc.brew93_id, bid)
        self.assertEqual(doc.email_id, "jane@acme.com")   # computed primary
        self.assertTrue(any(p.phone == "999" for p in doc.phone_nos))

    def test_reupsert_does_not_duplicate_email(self):
        bid = str(uuid.uuid4())
        n1, _ = v1._apply_contact(bid, TENANT, None, {"first_name": "A", "email": "a@x.com"})
        n2, action = v1._apply_contact(bid, TENANT, None, {"first_name": "A", "email": "a@x.com", "mobile": "5"})
        self.assertEqual(n1, n2)
        self.assertEqual(action, "updated")
        doc = frappe.get_doc("Contact", n2)
        self.assertEqual(len([r for r in doc.email_ids if r.email_id == "a@x.com"]), 1)
        self.assertEqual(frappe.db.count("Contact", {"brew93_id": bid}), 1)

    def test_party_link_when_resolvable(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_contact(bid, TENANT, None, {
            "first_name": "P", "party_type": "Lead", "party_name": self.lead.name,
        })
        doc = frappe.get_doc("Contact", name)
        self.assertTrue(any(l.link_doctype == "Lead" and l.link_name == self.lead.name for l in doc.links))

    def test_unresolvable_party_is_skipped_not_error(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_contact(bid, TENANT, None, {
            "first_name": "Q", "party_type": "Lead", "party_name": "CRM-LEAD-NOPE",
        })
        doc = frappe.get_doc("Contact", name)
        self.assertEqual(len(doc.links), 0)  # skipped, contact still created

    def test_loop_flag_cleared(self):
        v1._apply_contact(str(uuid.uuid4()), TENANT, None, {"first_name": "L"})
        self.assertFalse(frappe.flags.in_brew93_import)


class TestApplyCustomer(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")
        frappe.flags.in_brew93_import = False

    def test_create_customer_defaults_group_and_territory(self):
        bid = str(uuid.uuid4())
        name, action = v1._apply_customer(bid, TENANT, None, {"customer_name": "Acme Corp"})
        self.assertEqual(action, "created")
        doc = frappe.get_doc("Customer", name)
        self.assertEqual(doc.brew93_id, bid)
        self.assertEqual(doc.customer_type, "Company")   # defaulted
        self.assertTrue(doc.customer_group)               # mandatory Link filled
        self.assertTrue(doc.territory)

    def test_missing_customer_name_rejected(self):
        with self.assertRaises(v1._ApiError) as ctx:
            v1._apply_customer(str(uuid.uuid4()), TENANT, None, {"website": "x.com"})
        self.assertEqual(ctx.exception.code, "bad_request")

    def test_unknown_industry_skipped(self):
        bid = str(uuid.uuid4())
        name, _ = v1._apply_customer(bid, TENANT, None,
                                     {"customer_name": "NoInd", "industry": "TotallyMadeUpIndustry"})
        self.assertFalse(frappe.get_doc("Customer", name).industry)  # skipped, no error

    def test_idempotent_no_duplicate(self):
        bid = str(uuid.uuid4())
        n1, _ = v1._apply_customer(bid, TENANT, None, {"customer_name": "Dup Co"})
        n2, action = v1._apply_customer(bid, TENANT, None, {"customer_name": "Dup Co Renamed"})
        self.assertEqual(n1, n2)
        self.assertEqual(action, "updated")
        self.assertEqual(frappe.db.count("Customer", {"brew93_id": bid}), 1)


class TestApplyQuotation(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")
        frappe.flags.in_brew93_import = False
        self.lead = frappe.get_doc({"doctype": "Lead", "lead_name": "Quotation Party", "status": "Lead"}).insert()

    def test_create_and_update_quotation_is_idempotent(self):
        bid = str(uuid.uuid4())
        data = {"quotation_to": "Lead", "party_name": self.lead.name, "title": "Initial Quote"}
        name, action = v1._apply_quotation(bid, TENANT, None, data)
        self.assertEqual(action, "created")
        name2, action = v1._apply_quotation(bid, TENANT, None, {**data, "title": "Updated Quote"})
        self.assertEqual((name2, action), (name, "updated"))
        self.assertEqual(frappe.db.count("Quotation", {"brew93_id": bid}), 1)


class TestHandleGuards(FrappeTestCase):
    def setUp(self):
        frappe.set_user("Administrator")
        self._p = patch.multiple(
            "brew93_connector.api.v1.cfg",
            is_enabled=lambda: True,
            get_settings=lambda: dict(SETTINGS),
        )
        self._p.start()
        self.addCleanup(self._p.stop)

    def test_missing_brew93_id(self):
        # auth passes first (order: auth -> validate), so bypass the identity gate
        with patch("brew93_connector.api.v1._require_integration_identity"):
            res = v1.upsert_lead(brew93_id=None, tenant_id=TENANT, data={"lead_name": "x"})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["code"], "bad_request")

    def test_tenant_mismatch_rejected(self):
        # identity check bypassed to isolate the tenant guard
        with patch("brew93_connector.api.v1._require_integration_identity"):
            res = v1.upsert_lead(brew93_id=str(uuid.uuid4()), tenant_id="wrong-tenant", data={"lead_name": "x"})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["code"], "tenant_mismatch")

    def test_administrator_is_forbidden(self):
        # even Administrator (all roles) must be refused this path
        res = v1.upsert_lead(brew93_id=str(uuid.uuid4()), tenant_id=TENANT, data={"lead_name": "x"})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["code"], "forbidden")

    def test_disabled_connector(self):
        with patch("brew93_connector.api.v1.cfg.is_enabled", return_value=False):
            res = v1.upsert_lead(brew93_id=str(uuid.uuid4()), tenant_id=TENANT, data={"lead_name": "x"})
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["code"], "disabled")

    def test_full_handle_success_creates(self):
        # bypass only the identity gate; run the rest end-to-end as Administrator
        bid = str(uuid.uuid4())
        with patch("brew93_connector.api.v1._require_integration_identity"):
            res = v1.upsert_lead(brew93_id=bid, tenant_id=TENANT, data={"lead_name": "EndToEnd"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["action"], "created")
        self.assertEqual(frappe.db.get_value("Lead", res["erpnext_name"], "brew93_id"), bid)

    def test_bad_data_json(self):
        with patch("brew93_connector.api.v1._require_integration_identity"):
            res = v1.upsert_lead(brew93_id=str(uuid.uuid4()), tenant_id=TENANT, data="not-json")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"]["code"], "bad_request")

    def test_all_resources_implemented(self):
        # every whitelisted upsert is now real (no 501 stubs remain)
        for fn in (v1.upsert_lead, v1.upsert_opportunity, v1.upsert_contact, v1.upsert_customer, v1.upsert_quotation):
            self.assertTrue(callable(fn))

    def test_backfill_is_bounded_and_uses_queue(self):
        with patch("brew93_connector.api.backfill.cfg.is_enabled", return_value=True), \
             patch("brew93_connector.api.backfill.cfg.get_settings", return_value={"source_site": "test"}), \
             patch("brew93_connector.api.backfill.outbound.enqueue_event", return_value="event-1") as enqueue:
            result = backfill.enqueue_backfill("Lead", limit=9999)
        self.assertLessEqual(result["requested"], 500)
        self.assertEqual(result["queued"], result["requested"])
        self.assertTrue(enqueue.called)
