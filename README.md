# Brew93 Connector

Isolated Frappe app implementing the bidirectional Brew93 CRM ↔ ERPNext integration.

- **Owns:** external-ID mapping fields, the outbound event queue (ERPNext → Brew93),
  the signed inbound receiver (Brew93 → ERPNext), the HTTP client to Brew93, and the
  hardened SSO user-mapping helpers.
- **Does not** contain Brew93 business logic. All Brew93 endpoints are treated as the
  contract in `docs/INTEGRATION_CONTRACT.md`; endpoints not present in the Brew93
  Postman collection are marked **NEW** there.
- **Secrets** (HMAC secret and the Brew93 workspace refresh token) are stored as
  encrypted `Password` fields or read from `site_config`, never hard-coded and never
  logged. Legacy service-account fields remain backend-compatible but are hidden and
  are not part of production setup.

## Production setup

The ERPNext Administrator must use `/desk/brew93-integration` and select **Link
Workspace**. Enter the Brew93 Base URL, Tenant ID, Workspace Slug, Brew93 Username,
and Brew93 Password. The password is used only for verification; the connector stores
only the encrypted Brew93 workspace refresh token. `/app/brew93-integration` remains
available as a compatibility route and redirects to the Administrator setup page.

Everything is inert until `Brew93 Connector Settings.enabled` (and `events_enabled`) is
turned on. Installed only on the ERPNext site (`rag.klyonix.in`).

See `docs/INTEGRATION_CONTRACT.md` for the full contract.
