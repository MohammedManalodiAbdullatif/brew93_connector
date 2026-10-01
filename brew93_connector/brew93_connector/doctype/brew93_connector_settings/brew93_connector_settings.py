# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
import frappe
from frappe.model.document import Document
from brew93_connector.api.settings import normalize_base_url


class Brew93ConnectorSettings(Document):
    def validate(self):
        if self.get("brew93_base_url") or self.enabled:
            try:
                self.brew93_base_url = normalize_base_url(self.get("brew93_base_url"))
            except ValueError:
                frappe.throw("Brew93 API URL must be a valid HTTP(S) URL.")
        if self.get("events_url"):
            self.events_url = (self.events_url or "").strip().rstrip("/")
        if self.enabled and not self.brew93_tenant_id:
            frappe.throw("Set the Brew93 Tenant ID before enabling the connector (tenant pinning is mandatory).")
        if self.enabled and not self.brew93_tenant_slug:
            frappe.throw("Set the Brew93 Workspace Slug before enabling the connector.")
        if self.events_enabled and not self.events_url:
            frappe.throw("Set the Events Receiver URL before enabling signed events.")
