# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
import frappe
from frappe.model.document import Document


class Brew93ConnectorSettings(Document):
    def validate(self):
        self.sso_auto_create = 0
        for field in ("brew93_base_url", "events_url"):
            if self.get(field):
                self.set(field, (self.get(field) or "").strip().rstrip("/"))
        if self.enabled and not self.brew93_base_url:
            frappe.throw("Set the Brew93 Base URL before enabling the connector.")
        if self.enabled and not self.brew93_tenant_id:
            frappe.throw("Set the Brew93 Tenant ID before enabling the connector (tenant pinning is mandatory).")
        if self.events_enabled and not self.events_url:
            frappe.throw("Set the Events Receiver URL before enabling signed events.")
