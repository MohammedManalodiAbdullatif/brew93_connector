# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""Shared identity constants for the connector.

The integration user is the ONLY identity Brew93→ERPNext writes run as. It has
the minimal custom role below and is never System Manager/Administrator. Its
writes are tagged (loop prevention) so they never emit an outbound event back.
"""

INTEGRATION_USER = "brew93-integration@rag.klyonix.in"
INTEGRATION_ROLE = "Brew93 Integration"

# DocTypes the integration role may touch (create/read/write only; no delete,
# no submit, no privileged doctypes).
INTEGRATION_DOCTYPES = ("Lead", "Opportunity", "Customer", "Contact", "Quotation")
