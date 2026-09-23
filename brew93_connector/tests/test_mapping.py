# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Unit tests for field/status mapping and record builders. Pure — no site."""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from brew93_connector.api import mapping  # noqa: E402


class TestStatusMapping(unittest.TestCase):
    def test_erp_to_brew93_total(self):
        self.assertEqual(mapping.lead_status_to_brew93("Lead"), "new")
        self.assertEqual(mapping.lead_status_to_brew93("Converted"), "converted")
        self.assertEqual(mapping.lead_status_to_brew93("Do Not Contact"), "unqualified")
        self.assertEqual(mapping.lead_status_to_brew93("Interested"), "qualified")

    def test_erp_to_brew93_unknown_defaults(self):
        self.assertEqual(mapping.lead_status_to_brew93("Whatever"), "new")
        self.assertEqual(mapping.lead_status_to_brew93(None), "new")

    def test_brew93_to_erp_total(self):
        self.assertEqual(mapping.lead_status_to_erpnext("new"), "Lead")
        self.assertEqual(mapping.lead_status_to_erpnext("converted"), "Converted")
        self.assertEqual(mapping.lead_status_to_erpnext("QUALIFIED"), "Interested")
        self.assertEqual(mapping.lead_status_to_erpnext("bogus"), "Lead")


class TestIso(unittest.TestCase):
    # ERPNext stores naive timestamps in the site timezone (IST, UTC+5:30 here).
    # to_iso8601_utc must interpret them as IST and convert to UTC.
    def test_naive_ist_1115_becomes_0545z(self):
        # the reported bug: 11:15 IST must become 05:45Z, not 11:15Z
        self.assertEqual(
            mapping.to_iso8601_utc(datetime(2026, 9, 17, 11, 15, 0)), "2026-09-17T05:45:00Z"
        )

    def test_naive_datetime_shifts_back_530(self):
        self.assertEqual(
            mapping.to_iso8601_utc(datetime(2026, 8, 31, 6, 50, 35)), "2026-08-31T01:20:35Z"
        )

    def test_naive_crosses_date_boundary(self):
        # early-morning IST rolls back to the previous UTC day
        self.assertEqual(
            mapping.to_iso8601_utc(datetime(2026, 1, 1, 2, 0, 0)), "2025-12-31T20:30:00Z"
        )

    def test_frappe_string_datetime_is_ist(self):
        self.assertEqual(mapping.to_iso8601_utc("2026-09-17 11:15:00"), "2026-09-17T05:45:00Z")

    def test_aware_datetime_unchanged(self):
        # already tz-aware => converted from its own offset, no IST assumption
        self.assertEqual(
            mapping.to_iso8601_utc(datetime(2026, 8, 31, 6, 50, 35, tzinfo=timezone.utc)),
            "2026-08-31T06:50:35Z",
        )

    def test_aware_non_utc_converts(self):
        from datetime import timedelta
        ist = timezone(timedelta(hours=5, minutes=30))
        self.assertEqual(
            mapping.to_iso8601_utc(datetime(2026, 9, 17, 11, 15, 0, tzinfo=ist)),
            "2026-09-17T05:45:00Z",
        )

    def test_none_and_empty(self):
        self.assertIsNone(mapping.to_iso8601_utc(None))
        self.assertIsNone(mapping.to_iso8601_utc(""))


class TestDateFieldsNoTzShift(unittest.TestCase):
    """Date fields (transaction_date, valid_till, expected_closing) must stay a
    plain YYYY-MM-DD — never routed through the datetime->UTC conversion, which
    would shift them across the date boundary."""

    def test_to_date_str_no_shift(self):
        self.assertEqual(mapping.to_date_str("2026-08-25"), "2026-08-25")
        self.assertEqual(mapping.to_date_str(datetime(2026, 8, 25, 2, 0, 0)), "2026-08-25")

    def test_opportunity_dates_are_plain(self):
        doc = {
            "name": "CRM-OPP-2026-00009",
            "opportunity_from": "Lead", "party_name": "CRM-LEAD-1",
            "transaction_date": "2026-08-25", "expected_closing": "2026-09-10",
            "creation": "2026-08-25 11:15:00", "modified": "2026-08-25 11:15:00",
        }
        r = mapping.build_opportunity_record(doc, "rag.klyonix.in")
        self.assertEqual(r["transaction_date"], "2026-08-25")   # no shift
        self.assertEqual(r["expected_closing"], "2026-09-10")   # no shift
        self.assertEqual(r["created_at"], "2026-08-25T05:45:00Z")  # datetime IST->UTC
        self.assertEqual(r["updated_at"], "2026-08-25T05:45:00Z")


class TestLeadRecord(unittest.TestCase):
    def _doc(self):
        return {
            "name": "CRM-LEAD-2026-05015",
            "lead_name": "hii",
            "first_name": "hii",
            "email_id": "a@b.com",
            "mobile_no": "123",
            "whatsapp_no": "456",
            "status": "Lead",
            "utm_source": "Website",
            "country": "India",
            "no_of_employees": "1-10",
            "qualification_status": "Unqualified",
            "annual_revenue": 0.0,
            "lead_owner": "Administrator",
            "disabled": 0,
            "unsubscribed": 0,
            "creation": "2026-08-31 06:50:35",
            "modified": "2026-08-31 06:50:35",
        }

    def test_external_id_and_key_fields(self):
        r = mapping.build_lead_record(self._doc(), "rag.klyonix.in")
        self.assertEqual(r["external_id"], "CRM-LEAD-2026-05015")
        self.assertEqual(r["email"], "a@b.com")       # email_id -> email
        self.assertEqual(r["mobile"], "123")          # mobile_no -> mobile
        self.assertEqual(r["whatsapp"], "456")        # whatsapp_no -> whatsapp
        self.assertEqual(r["source"], "Website")      # utm_source -> source
        self.assertEqual(r["owner_email"], "Administrator")

    def test_status_passthrough_on_bulk(self):
        # Documented bulk contract carries the ERPNext status string verbatim.
        r = mapping.build_lead_record(self._doc(), "rag.klyonix.in")
        self.assertEqual(r["status"], "Lead")

    def test_dates_are_iso_z(self):
        # 06:50:35 IST -> 01:20:35Z (naive stored value interpreted as site tz)
        r = mapping.build_lead_record(self._doc(), "rag.klyonix.in")
        self.assertEqual(r["created_at"], "2026-08-31T01:20:35Z")
        self.assertEqual(r["updated_at"], "2026-08-31T01:20:35Z")

    def test_nulls_dropped_but_external_id_kept(self):
        doc = {"name": "CRM-LEAD-1", "status": "Open"}
        r = mapping.build_lead_record(doc, "rag.klyonix.in")
        self.assertEqual(r["external_id"], "CRM-LEAD-1")
        self.assertNotIn("email", r)  # None-valued keys removed
        self.assertIn("disabled", r)  # explicit False retained


class TestResourceRouting(unittest.TestCase):
    def test_routing_table(self):
        self.assertEqual(mapping.RESOURCE_BUILDERS["Lead"][0], "leads")
        self.assertEqual(mapping.RESOURCE_BUILDERS["Opportunity"][0], "deals")
        self.assertEqual(mapping.RESOURCE_BUILDERS["Customer"][0], "customers")
        self.assertEqual(mapping.RESOURCE_BUILDERS["Contact"][0], "contacts")

    def test_contact_event_type(self):
        self.assertEqual(mapping.event_type("contacts", "upserted"), "contact.upserted")


class TestContactRecord(unittest.TestCase):
    def test_flattens_children_and_party(self):
        doc = {
            "name": "CONT-0001",
            "first_name": "Jane",
            "last_name": "Doe",
            "designation": "CTO",
            "email_id": "jane@acme.com",
            "mobile_no": "999",
            "is_primary_contact": 1,
            "email_ids": [{"email_id": "jane@acme.com", "is_primary": 1}],
            "phone_nos": [{"phone": "111", "is_primary_phone": 1}],
            "links": [{"link_doctype": "Customer", "link_name": "Acme"}],
            "creation": "2026-08-25 06:00:00",
            "modified": "2026-08-25 06:00:00",
        }
        r = mapping.build_contact_record(doc, "rag.klyonix.in")
        self.assertEqual(r["external_id"], "CONT-0001")
        self.assertEqual(r["email"], "jane@acme.com")
        self.assertEqual(r["mobile"], "999")
        self.assertEqual(r["phone"], "111")          # from phone_nos primary
        self.assertEqual(r["party_type"], "Customer")
        self.assertEqual(r["party_name"], "Acme")
        self.assertIn("is_primary_contact", r)

    def test_no_links_no_party(self):
        r = mapping.build_contact_record({"name": "CONT-2", "first_name": "X"}, "s")
        self.assertEqual(r["external_id"], "CONT-2")
        self.assertNotIn("party_type", r)  # cleaned out when None


class TestCustomerRecord(unittest.TestCase):
    def test_customer_schema_fields(self):
        doc = {
            "name": "CUST-0001",
            "customer_name": "Acme",
            "customer_type": "Company",
            "customer_group": "Commercial",
            "territory": "India",
            "default_currency": "INR",
            "disabled": 0,
            "is_frozen": 0,
            "creation": "2026-08-25 06:00:00",
            "modified": "2026-08-25 06:00:00",
        }
        r = mapping.build_customer_record(doc, "rag.klyonix.in")
        self.assertEqual(r["external_id"], "CUST-0001")
        self.assertEqual(r["customer_name"], "Acme")
        self.assertEqual(r["customer_type"], "Company")
        self.assertEqual(r["currency"], "INR")   # default_currency -> currency
        self.assertIn("disabled", r)
        self.assertIn("is_frozen", r)


class TestQuotationRecord(unittest.TestCase):
    def _doc(self):
        return {
            "name": "SAL-QTN-2026-00001",
            "quotation_to": "Customer",
            "party_name": "mohammed",
            "customer_name": "mohammed",
            "status": "Open",
            "order_type": "Sales",
            "transaction_date": "2026-08-25",
            "valid_till": "2026-09-25",
            "currency": "INR",
            "conversion_rate": 1.0,
            "grand_total": 323.0,
            "docstatus": 1,
            "creation": "2026-08-25 06:55:57",
            "modified": "2026-08-25 06:56:07",
            "items": [
                {"item_code": "IPHONE", "item_name": "IPHONE", "qty": 1.0, "uom": "Nos",
                 "rate": 323.0, "amount": 323.0, "item_group": "Consumable"},
            ],
        }

    def test_maps_header_and_docstatus(self):
        r = mapping.build_quotation_record(self._doc(), "rag.klyonix.in")
        self.assertEqual(r["external_id"], "SAL-QTN-2026-00001")
        self.assertEqual(r["party_type"], "Customer")     # quotation_to -> party_type
        self.assertEqual(r["party_id"], "mohammed")       # party_name -> party_id
        self.assertEqual(r["doc_status"], "submitted")     # docstatus 1
        self.assertEqual(r["transaction_date"], "2026-08-25")  # plain date, not Z

    def test_line_items(self):
        r = mapping.build_quotation_record(self._doc(), "rag.klyonix.in")
        self.assertEqual(len(r["items"]), 1)
        item = r["items"][0]
        self.assertEqual(item["position"], 1)
        self.assertEqual(item["item_code"], "IPHONE")
        self.assertEqual(item["qty"], 1.0)

    def test_docstatus_labels(self):
        self.assertEqual(mapping.docstatus_label(0), "draft")
        self.assertEqual(mapping.docstatus_label(2), "cancelled")

    def test_routing_and_event_type(self):
        self.assertEqual(mapping.RESOURCE_BUILDERS["Quotation"][0], "quotations")
        self.assertEqual(mapping.event_type("quotations", "upserted"), "quotation.upserted")


class TestCrmLeadPayload(unittest.TestCase):
    def test_maps_to_brew93_crm_shape(self):
        doc = {"name": "CRM-LEAD-2026-05015", "lead_name": "Amit Walker",
               "email_id": "a@b.com", "mobile_no": "999", "company_name": "Acme",
               "job_title": "CTO", "utm_source": "Website", "status": "Interested"}
        p = mapping.build_crm_lead_payload(doc, "rag.klyonix.in")
        self.assertEqual(p["name"], "Amit Walker")
        self.assertEqual(p["email"], "a@b.com")
        self.assertEqual(p["phone"], "999")
        self.assertEqual(p["status"], "qualified")   # ERPNext Interested -> Brew93 enum
        self.assertEqual(p["custom_fields"]["erpnext_name"], "CRM-LEAD-2026-05015")
        self.assertEqual(p["custom_fields"]["source_site"], "rag.klyonix.in")


class TestEvents(unittest.TestCase):
    def test_event_type_names(self):
        self.assertEqual(mapping.event_type("leads", "upserted"), "lead.upserted")
        self.assertEqual(mapping.event_type("deals", "deleted"), "opportunity.deleted")
        self.assertEqual(mapping.event_type("customers", "upserted"), "customer.upserted")
        self.assertEqual(mapping.event_type("quotations", "deleted"), "quotation.deleted")

    def test_envelope_shape(self):
        env = mapping.build_event_envelope(
            resource="leads", action="upserted", event_id="evt-1",
            tenant_id="ten-1", source_site="rag.klyonix.in",
            data={"external_id": "CRM-LEAD-1", "status": "Open"},
            occurred_at="2026-08-31T06:50:35Z",
        )
        self.assertEqual(env["event_id"], "evt-1")
        self.assertEqual(env["event_type"], "lead.upserted")
        self.assertEqual(env["schema_version"], 1)
        self.assertEqual(env["source"], "erpnext")
        self.assertEqual(env["source_site"], "rag.klyonix.in")
        self.assertEqual(env["tenant_id"], "ten-1")
        self.assertEqual(env["data"]["external_id"], "CRM-LEAD-1")

    def test_delete_envelope_data(self):
        env = mapping.build_event_envelope(
            resource="deals", action="deleted", event_id="evt-2",
            tenant_id="ten-1", source_site="s", data={"external_id": "CRM-OPP-1"},
        )
        self.assertEqual(env["event_type"], "opportunity.deleted")
        self.assertEqual(env["data"], {"external_id": "CRM-OPP-1"})


if __name__ == "__main__":
    unittest.main()
