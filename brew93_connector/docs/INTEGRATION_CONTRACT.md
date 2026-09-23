# Brew93 ↔ ERPNext Integration Contract (v0.1 — DRAFT, pending both-agent + user review)

Source of truth = the Brew93 Postman collection (`brew93-backend/docs/brew93-postman-collection.json`).
Endpoints **not** in that collection are marked **NEW** and require Brew93-side work + collection update before the Frappe side builds against them.

Legend: **[EXISTING]** documented in the collection · **[NEW]** must be created · **[OPEN]** needs a decision/answer.

| # | Area | Decision |
|---|------|----------|
| 1 | **Authentication** | Two channels. (a) Bulk sync: **[EXISTING]** service login `POST {base}/integrations/erpnext/auth/login` → JWT, sent as `Authorization: Bearer`. (b) Events: **[NEW]** HMAC-SHA256, no bearer. |
| 2 | **Tenant identification** | Every record carries the Brew93 tenant UUID. ERPNext pins one tenant in `Brew93 Connector Settings.brew93_tenant_id`. |
| 3 | **Tenant isolation** | Client rejects any service token whose `tenant_id` ≠ the pinned tenant (`client._assert_tenant`). Inbound (Phase 5) will reject payloads for any other tenant. `source_site` scopes ownership on the Brew93 side. |
| 4 | **ERPNext integration user** | **[NEW]** dedicated user `brew93-integration@erpnext.local`, minimal custom role, API key/secret. Used for all inbound writes; never System Manager. (Not created yet — needs approval.) |
| 5 | **Brew93 user mapping (SSO)** | Map on an explicit **Brew93-user-UUID ↔ ERPNext User** link, **never email**. See Phase 7. |
| 6 | **Lead sync** | `Lead` ↔ Brew93 `leads`. external_id = ERPNext Lead name. Builder: `mapping.build_lead_record`. |
| 7 | **Deal/Opportunity sync** | `Opportunity` ↔ Brew93 `deals`. **[RESOLVED]** send ERPNext `status`/`sales_stage` strings verbatim; receiver stages them as plain text (no `pipeline_stages` mapping, no default-stage risk). String→stage mapping is a future staging→CRM concern, not the receiver's. |
| 8 | **Contact sync** | `Contact` ↔ Brew93 `contacts` is enabled by default when the receiver resource is deployed; disable it with `brew93_live_doctypes` until then. |
| 9 | **Company/Customer sync** | `Customer` ↔ Brew93 `customers` **[EXISTING/RESOLVED]**. Schema confirmed (customer_name, customer_type, group, territory, tax_id, currency, credit_limit, disabled, is_frozen, …). Semantics differ from Brew93 `companies`; ERPNext contact fields (email/mobile) live on linked Contact so are omitted. |
| 10 | **External IDs** | ERPNext→Brew93 key = `external_id` (ERPNext docname) + `source_site`. Brew93→ERPNext key = `brew93_id` (UUID) custom field. Never match on email. Fields added on Lead/Opportunity/Contact/Customer, `brew93_id` unique + indexed. |
| 11 | **Field ownership** | Brew93 owns lead capture, qualification, score, assignment **while unconverted** (score = Brew93 AI; `assigned_to` = Brew93 user UUIDs, stored **opaque**, never an ERPNext Link). ERPNext owns commercialization (customer, quotation, amounts, opportunity/sales stage, deal owner post-conversion). |
| 12 | **Create/update behaviour** | Upsert. Bulk receiver `ON CONFLICT (tenant_id, source_site, external_id)`. Repeated events with identical state are de-duped in the outbound queue by `payload_hash`. |
| 13 | **Delete/archive** | `DELETE {base}/integrations/erpnext/{resource}/{external_id}?source_site=…` **[EXISTING]**. **[OPEN]** confirm soft vs hard delete. ERPNext `on_trash` → `*.deleted` event. |
| 14 | **Webhooks/events** | **[NEW]** `POST {events_url}` = `…/integrations/erpnext/events`, gateway PUBLIC block (HMAC, not bearer). |
| 15 | **HMAC signatures** | HMAC-SHA256 over `"{timestamp}.{raw_body}"`; headers `X-Brew93-Timestamp`, `X-Brew93-Signature: v1=<hex>`, `X-Brew93-Event-Id`; `Content-Type: application/json`. Sender signs the exact bytes it transmits. Implemented + unit-tested (`api/signing.py`). |
| 16 | **Replay protection** | Reject timestamps older than `replay_window_seconds` (default 300) + dedupe on `event_id`. Sender **re-signs with a fresh timestamp on every retry**. |
| 17 | **Idempotency** | Outbound: `payload_hash` de-dupe + at-least-once delivery, receiver idempotent on external_id. Events: idempotent on `event_id`. Inbound: idempotent on `brew93_id`. |
| 18 | **Retry behaviour** | Durable `Brew93 Event Queue`; exponential backoff (`base^attempt`, capped `max_backoff_seconds`); dead-letter after `max_retries`. No infinite loops. |
| 19 | **Error handling** | 4xx (except 408/425/429) = permanent → dead-letter. 5xx/timeout/network = temporary → backoff. A whole bulk batch aborts on any 4xx, so records are pre-validated + chunked ≤500 client-side. |
| 20 | **Conflict handling** | Field-level ownership (§11); within a side, last-write-wins by `updated_at`. Writes by the integration user emit no outbound events (loop prevention). |
| 21 | **Rate limits** | Bulk ≤500 records/request. Outbound drains in batches of 50 every 5 min + immediate per-event job. **[OPEN]** confirm Brew93 gateway rate limits so backoff respects 429. |
| 22 | **Logging** | Structured; queue rows keep `last_error`/`http_status`. **No secrets, tokens, passwords, signatures, or HMAC material ever logged.** |
| 23 | **MCP** | **[NEW]**, Phase 14, last. Thin adapter over the same REST + integration user; no business logic, no direct DB, respects tenant/auth/idempotency. |
| 24 | **Workspace-admin connect** | **[EXISTING]** A Brew93 workspace admin starts the connection in Brew93. Brew93 calls `POST /api/v1/crm/integrations/frappe` with the ERPNext `base_url`, `api_key`, and `api_secret`, probes the credentials, and stores them encrypted per tenant. ERPNext does not receive a Brew93 password or authorization code. |

## Transport model (resolved)
- **Real-time outbound = signed `/events`** (HMAC, idempotent on `event_id`). This is the durable-queue path wired to `doc_events`.
- **Bulk endpoints = approved backfill/reconcile only** (a separate, explicitly-approved operation — Phase 8), not wired to live doc events.
- Both land in the same Brew93 staging tables keyed by `(tenant_id, source_site, external_id)`.

## Endpoints now in the Brew93 Postman collection (built + tested by Brew93, not enabled)
- `POST /integrations/erpnext/events` (signed events receiver) — was NEW, now documented.

## Resolved (Brew93 answers, 2026-09-16)
1. No `brew93_id` echo — receiver writes staging keyed by `external_id`+`source_site`; no CRM UUID minted. Correlate on the ERPNext docname. `brew93_id` field reserved for future staging→CRM promotion + inbound/SSO.
2. Deals: strings verbatim (§7).
3. `customers` schema confirmed; `contacts` not a resource (§8/§9).
4. Events envelope/vocabulary/responses specified and implemented (§14/§15/§16).

## Still gated on the USER
- **Reverse direction (Phase 5): pick (i) Brew93 calls ERPNext whitelisted methods (dedicated integration user + API key) — Brew93's recommendation — or (ii) ERPNext pulls Brew93's CRM API.** Build held until chosen.
- Production `kly` tenant UUID — verify against the prod Brew93 DB before pinning (local value ≠ prod).
- HMAC secret + service credentials — provided out of band; enablement of `enabled`/`events_enabled`; SSO hardening (Phase 7); creating the integration user; fixing `brew93_api_url`.

## Workspace-admin connection contract [EXISTING]

The workspace admin connects from Brew93. There is no ERPNext-side connect,
disconnect, authorization-code, or Brew93-password form. Brew93 owns the
connection lifecycle and stores the ERPNext credentials encrypted for the
selected tenant.

### Brew93-side provisioning request

`POST {brew93_base_url}/api/v1/crm/integrations/frappe`

The request is made by Brew93 with the ERPNext credentials being provisioned:

```json
{
  "base_url": "https://erpnext.example.com",
  "api_key": "<erpnext-api-key>",
  "api_secret": "<erpnext-api-secret>"
}
```

Brew93 probes the URL using the supplied credentials, then stores them
encrypted per tenant. The exact response and authentication for this
provisioning request are owned by Brew93; Frappe must not invent an OAuth or
authorization-code exchange for it.

### ERPNext-side configuration

`Brew93 Connector Settings` remains for the Frappe-owned integration runtime:
the signed outbound-events receiver configuration and optional hardened Brew93
SSO. It does not store Brew93 connection access or refresh tokens. Live
outbound authentication uses the documented service-login/cache path and never
reads a legacy `connection_access_token`.

For inbound API calls, create a least-privilege ERPNext integration user and
provide its API key/secret to Brew93 through the Brew93 connection flow. Do not
put those credentials in the Frappe connector page or in logs.

## Prerequisites owned by the user (not actioned peer-to-peer)
Block SSO→System Manager/Administrator, disable auto-create, pin tenant, close public :8000, tighten CORS, rotate tokens in git remotes, supervise workers, HMAC secret generation (out of band), JWT rotation on Brew93.

## JWT trust configuration

The connector never treats TLS or JWT payload decoding as signature verification.
All SSO and CRM tokens are validated against Brew93's mandatory, fail-closed
`GET /auth/me` response. Asymmetric JWT signature verification is optional when
that Brew93 validation is available. If desired, configure the Brew93 signing
public key in the site's `site_config.json` as `brew93_jwt_public_key` (PEM);
the optional `brew93_jwt_issuer` and `brew93_jwt_audience` values pin those
claims. Missing trust material, signature failures, or claim verification
failures fail closed before tenant validation or token use. These values are not
exposed by diagnostics or the status page.
