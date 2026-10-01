# Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
"""HTTP client for the Brew93 ERPNext-integration endpoints.

Endpoints used (all documented in the Brew93 Postman collection except the
events receiver, which is marked NEW in the contract):

  POST   {base}/auth/login                                (workspace login -> JWT)
  POST   {events_url}                                     (NEW: HMAC-signed events)

The client performs a SINGLE attempt and classifies the outcome; retry/backoff
is owned by the queue drainer (`outbound.drain_queue`) so there is exactly one
place that decides when to retry. No token, password, secret, or signature is
ever written to a log.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import requests

import frappe

from brew93_connector.api import settings as cfg
from brew93_connector.api import signing

_CRM_TOKEN_CACHE_KEY = "brew93_connector:crm_token"


@dataclass
class Result:
    ok: bool
    status_code: int | None
    # "permanent" => a 4xx contract/validation error; do not retry.
    # "temporary" => network error / timeout / 5xx; safe to retry.
    # None        => success.
    failure_kind: str | None
    body: dict | None
    message: str = ""

class Brew93ConfigError(Exception):
    pass


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"Accept": "application/json", "User-Agent": "Brew93-Connector/0.0.1"})
    return s


def _require_https(base_url: str | None) -> None:
    if not (base_url or "").lower().startswith("https://"):
        raise Brew93ConfigError("Brew93 authentication requires an HTTPS base URL")


def _base_url(values: dict) -> str:
    try:
        base = cfg.normalize_base_url(values.get("brew93_base_url"))
    except ValueError as exc:
        raise Brew93ConfigError(str(exc)) from exc
    _require_https(base)
    return base


def _jwt_ttl(claims: dict, default: int = 600) -> int:
    """Seconds until expiry from claims already verified by PyJWT."""
    try:
        import time

        remaining = int(claims["exp"]) - int(time.time())
        return max(0, min(default, remaining - 30))
    except Exception:
        return 0


def _assert_tenant(claims: dict, expected_tenant_id: str | None) -> None:
    """Refuse to use a token whose tenant_id != the pinned tenant."""
    if not expected_tenant_id:
        return
    if str(claims.get("tenant_id")) != str(expected_tenant_id):
        raise Brew93ConfigError("Brew93 token tenant_id does not match the pinned tenant; refusing")


def _classify(resp: requests.Response) -> Result:
    body = None
    try:
        body = resp.json()
    except ValueError:
        body = None
    if resp.status_code < 300:
        return Result(True, resp.status_code, None, body, "ok")
    if 400 <= resp.status_code < 500 and resp.status_code not in (408, 425, 429):
        return Result(False, resp.status_code, "permanent", body, f"HTTP {resp.status_code}")
    return Result(False, resp.status_code, "temporary", body, f"HTTP {resp.status_code}")


# --- public operations -----------------------------------------------------
def brew93_user_authenticate(values: dict, email: str, password: str) -> dict:
    """Return verified claims and the refresh token for immediate encrypted storage."""
    result = _user_login(values, email, password)
    return {"claims": result["claims"], "identity": result["identity"],
            "refresh_token": result["data"]["refresh_token"]}


def brew93_workspace_authenticate(values: dict, username: str, password: str) -> dict:
    """Authenticate a Brew93 workspace user without retaining credentials."""
    result = _user_login(values, username, password)
    return {"claims": result["claims"], "identity": result["identity"],
            "refresh_token": result["data"]["refresh_token"]}


def _classify_event(resp: requests.Response) -> Result:
    """Events receiver contract classification.

    200 => ok (processed|duplicate). 400 => permanent (bad json/envelope/event-id
    mismatch/unsupported type). 404 => permanent. 401 => temporary: an expired
    timestamp is fixed by re-signing on the next attempt, and a genuinely wrong
    secret is bounded by the retry cap rather than looping forever. 503/5xx/
    network => temporary.
    """
    body = None
    try:
        body = resp.json()
    except ValueError:
        body = None
    if resp.status_code < 300:
        return Result(True, resp.status_code, None, body, "ok")
    if resp.status_code in (400, 404, 422):
        return Result(False, resp.status_code, "permanent", body, f"HTTP {resp.status_code}")
    return Result(False, resp.status_code, "temporary", body, f"HTTP {resp.status_code}")


def post_event(raw_body: str, event_id: str) -> Result:
    """POST a signed event to the events receiver. Signs the exact bytes sent,
    with a fresh timestamp per call (so retries re-sign)."""
    values = cfg.get_settings()
    secret = cfg.get_hmac_secret()
    if not values.get("events_url") or not secret:
        raise Brew93ConfigError("Events URL or HMAC secret is not configured")
    headers = signing.build_signed_headers(secret, raw_body, event_id)
    session = _session()
    try:
        try:
            resp = session.post(
                values["events_url"],
                data=raw_body.encode("utf-8"),  # exact signed bytes
                headers=headers,
                timeout=(5, values["request_timeout"]),
            )
        except requests.exceptions.RequestException as exc:
            return Result(False, None, "temporary", None, exc.__class__.__name__)
        return _classify_event(resp)
    finally:
        session.close()


# --- Brew93 CRM API (admin-login + bearer -> real CRM Leads, UI-visible) -----
def _user_token_cache_key(user: str) -> str:
    return f"brew93_connector:user_token:{user}"


def _scoped_cache_key(prefix: str, values: dict, identity: str | None = None) -> str:
    """Keep bearer-token caches isolated by site, tenant, and optional identity."""
    site = (values.get("source_site") or getattr(frappe.local, "site", "") or "").strip()
    tenant = str(values.get("brew93_tenant_id") or "").strip()
    suffix = f":{site}:{tenant}"
    return f"{prefix}:{identity}{suffix}" if identity else f"{prefix}{suffix}"


def _token_data(body: dict) -> dict:
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    if not isinstance(data, dict) or not data.get("access_token"):
        raise Brew93ConfigError("Brew93 authentication returned no access token")
    if data.get("token_type", "").lower() != "bearer":
        raise Brew93ConfigError("Brew93 authentication returned an unsupported token_type")
    try:
        if int(data["expires_in"]) <= 0:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise Brew93ConfigError("Brew93 authentication returned an invalid expires_in") from exc
    return data


def _jwt_claims_without_verification(token: str) -> dict:
    """Read claims for comparison with Brew93's authoritative /auth/me reply."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError
        encoded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        claims = json.loads(base64.urlsafe_b64decode(encoded.encode()).decode())
        if not isinstance(claims, dict):
            raise ValueError
        return claims
    except Exception as exc:
        raise Brew93ConfigError("Brew93 returned an invalid JWT") from exc


def _validate_remote_identity(session: requests.Session, values: dict, access_token: str,
                              token_claims: dict | None = None) -> dict:
    """Use Brew93's server-side validation as the source of truth for a token."""
    base = _base_url(values)
    claims = token_claims or _jwt_claims_without_verification(access_token)
    slug = values.get("brew93_tenant_slug")
    headers = {"Authorization": f"Bearer {access_token}"}
    if slug:
        headers["x-tenant-slug"] = slug
    try:
        resp = session.get(base + "/auth/me", headers=headers,
                           timeout=(5, values.get("request_timeout", 10)))
    except requests.exceptions.RequestException as exc:
        raise Brew93ConfigError("Brew93 token validation is unavailable") from exc
    if resp.status_code >= 300:
        raise Brew93ConfigError("Brew93 token validation failed")
    try:
        body = resp.json() or {}
        identity = body.get("data") if isinstance(body.get("data"), dict) else body
        if isinstance(identity, dict) and isinstance(identity.get("user"), dict):
            identity = identity["user"]
    except (ValueError, AttributeError) as exc:
        raise Brew93ConfigError("Brew93 token validation returned invalid identity") from exc
    if not isinstance(identity, dict):
        raise Brew93ConfigError("Brew93 token validation returned no identity")

    returned_sub = identity.get("sub") or identity.get("user_id") or identity.get("id")
    token_sub = claims.get("sub") or claims.get("user_id")
    if not returned_sub or not token_sub or str(returned_sub) != str(token_sub):
        raise Brew93ConfigError("Brew93 validated user does not match the access token")
    returned_email = identity.get("email")
    token_email = claims.get("email")
    if returned_email and token_email and returned_email.strip().lower() != token_email.strip().lower():
        raise Brew93ConfigError("Brew93 validated email does not match the access token")
    workspace = identity.get("workspace") if isinstance(identity.get("workspace"), dict) else {}
    returned_tenant = (identity.get("tenant_id") or identity.get("tenantId") or
                       workspace.get("tenant_id") or workspace.get("tenantId"))
    token_tenant = claims.get("tenant_id") or claims.get("tenantId")
    expected_tenant = values.get("brew93_tenant_id")
    if not returned_tenant or not token_tenant or str(returned_tenant) != str(token_tenant):
        raise Brew93ConfigError("Brew93 validated tenant does not match the access token")
    if expected_tenant and str(returned_tenant) != str(expected_tenant):
        raise Brew93ConfigError("Brew93 validated tenant does not match the pinned tenant")
    requested_slug = (values.get("brew93_tenant_slug") or "").strip()
    returned_slug = (identity.get("workspace_slug") or identity.get("tenant_slug") or
                     identity.get("slug") or workspace.get("slug"))
    if requested_slug and returned_slug and str(returned_slug).strip().lower() != requested_slug.lower():
        raise Brew93ConfigError("Brew93 validated workspace does not match the requested slug")
    if identity.get("email_verified") is False:
        raise Brew93ConfigError("Brew93 email is not verified")
    return identity


def _user_login(values: dict, email: str, password: str) -> dict:
    base = _base_url(values)
    payload = {"email": email, "password": password}
    slug = values.get("brew93_tenant_slug")
    headers = {"x-tenant-slug": slug} if slug else {}
    if slug:
        payload.update(tenant_slug=slug, workspace_slug=slug)
    session = _session()
    try:
        try:
            resp = session.post(base + "/auth/login", json=payload,
                                headers=headers, timeout=(5, values["request_timeout"]))
        except requests.exceptions.RequestException as exc:
            raise Brew93ConfigError("Brew93 login is unavailable") from exc
        if resp.status_code in (400, 401, 403):
            frappe.throw(frappe._("Invalid Brew93 email or password."), frappe.AuthenticationError)
        if resp.status_code >= 300:
            raise Brew93ConfigError(f"Brew93 login failed (HTTP {resp.status_code})")
        data = _token_data(resp.json() or {})
        access = data["access_token"]
        claims = _verified_claims(access)
        _assert_tenant(claims, values.get("brew93_tenant_id"))
        identity = _validate_remote_identity(session, values, access, claims)
        if claims.get("email_verified") is False:
            raise Brew93ConfigError("Brew93 email is not verified")
        if not data.get("refresh_token"):
            raise Brew93ConfigError("Brew93 login returned no refresh token")
        return {"data": data, "claims": claims, "identity": identity}
    finally:
        payload.clear()
        session.close()


def _verified_claims(token: str) -> dict:
    """Local-verify when asymmetric trust is configured; otherwise decode
    unverified claims. /auth/me remains the mandatory authoritative check."""
    try:
        import jwt

        trust = cfg.get_jwt_verification_settings()
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        if trust.get("public_key") and algorithm in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}:
            kwargs = {
                "algorithms": [algorithm],
                "options": {"require": ["exp", "sub", "tenant_id"]},
            }
            if trust.get("issuer"):
                kwargs["issuer"] = trust["issuer"]
            if trust.get("audience"):
                kwargs["audience"] = trust["audience"]
            return jwt.decode(token, trust["public_key"], **kwargs)
        return jwt.decode(
            token,
            options={"verify_signature": False, "require": ["exp", "sub", "tenant_id"]},
        )
    except Exception as exc:
        raise Brew93ConfigError("Invalid Brew93 JWT") from exc


def crm_login(values: dict) -> str:
    """Log into Brew93 as the configured workspace admin (service_email +
    service_password) and return the access token. Password is spent once and
    never logged. Contract: POST {base}/auth/login {email,password,tenant_slug}."""
    email = values.get("service_email")
    base = _base_url(values)
    password = cfg.get_service_password()
    slug = values.get("brew93_tenant_slug")
    if not base or not email or not password:
        raise Brew93ConfigError("Brew93 admin credentials (service_email/password) are not configured")
    payload = {"email": email, "password": password}
    headers = {}
    if slug:
        payload["tenant_slug"] = slug
        payload["workspace_slug"] = slug
        headers["x-tenant-slug"] = slug
    session = _session()
    try:
        resp = session.post(base + "/auth/login", json=payload, headers=headers,
                            timeout=(5, values["request_timeout"]))
        payload.clear()
        if resp.status_code in (400, 401, 403):
            raise Brew93ConfigError("Brew93 admin login rejected (check service_email/password/tenant)")
        if resp.status_code >= 300:
            raise Brew93ConfigError(f"Brew93 admin login failed (HTTP {resp.status_code})")
        data = _token_data(resp.json() or {})
        token = data["access_token"]
        claims = _verified_claims(token)
        _assert_tenant(claims, values.get("brew93_tenant_id"))
        _validate_remote_identity(session, values, token, claims)
        return token
    finally:
        session.close()


def _crm_token(values: dict, force: bool = False) -> str:
    key = _scoped_cache_key(_CRM_TOKEN_CACHE_KEY, values)
    if not force:
        cached = frappe.cache().get_value(key)
        if cached:
            return cached
    token = crm_login(values)
    claims = _verified_claims(token)
    ttl = _jwt_ttl(claims)
    if ttl:
        frappe.cache().set_value(key, token, expires_in_sec=ttl)
    return token


def crm_upsert(resource: str, brew93_id: str | None, payload: dict, user: str | None = None) -> Result:
    """Create or update any Brew93 CRM resource (leads, deals, contacts, companies, quotes)."""
    return _crm_request(resource, "upsert", brew93_id, payload, user)


def crm_delete(resource: str, brew93_id: str, user: str | None = None) -> Result:
    """Delete any Brew93 CRM resource."""
    return _crm_request(resource, "delete", brew93_id, user=user)


def crm_upsert_lead(brew93_id: str | None, payload: dict, user: str | None = None) -> Result:
    """Create (POST /crm/leads) when there is no brew93_id, else update
    (PUT /crm/leads/:id). On a 201/200 the Brew93 lead id is in result.body.data.id."""
    return _crm_request("leads", "upsert", brew93_id, payload, user)


def crm_delete_lead(brew93_id: str, user: str | None = None) -> Result:
    """DELETE /crm/leads/:id as the workspace admin."""
    return _crm_request("leads", "delete", brew93_id, user=user)


def crm_upsert_deal(brew93_id: str | None, payload: dict, user: str | None = None) -> Result:
    """Create (POST /crm/deals) when there is no brew93_id, else update
    (PUT /crm/deals/:id). On a 201/200 the Brew93 deal id is in result.body.data.id."""
    return _crm_request("deals", "upsert", brew93_id, payload, user)


def crm_delete_deal(brew93_id: str, user: str | None = None) -> Result:
    """DELETE /crm/deals/:id as the workspace admin."""
    return _crm_request("deals", "delete", brew93_id, user=user)


def _crm_request(resource: str, operation: str, brew93_id: str | None, payload: dict | None = None,
                 user: str | None = None) -> Result:
    values = cfg.get_settings()
    session = _session()

    def _send(token):
        hdr = {"Authorization": f"Bearer {token}"}
        if values.get("brew93_tenant_slug"):
            hdr["x-tenant-slug"] = values["brew93_tenant_slug"]
        base = _base_url(values)
        to = (5, values["request_timeout"])
        if operation == "delete":
            return session.delete(f"{base}/crm/{resource}/{brew93_id}", headers=hdr, timeout=to)
        if brew93_id:
            return session.put(f"{base}/crm/{resource}/{brew93_id}", json=payload, headers=hdr, timeout=to)
        return session.post(f"{base}/crm/{resource}", json=payload, headers=hdr, timeout=to)

    try:
        token = _get_user_crm_token(values, user) if user else _crm_token(values)
        try:
            resp = _send(token)
        except requests.exceptions.RequestException as exc:
            return Result(False, None, "temporary", None, exc.__class__.__name__)
        if resp.status_code in (401, 403):
            resp = _send((_get_user_crm_token(values, user, force=True) if user else _crm_token(values, force=True)))
        return _classify(resp)
    finally:
        session.close()


def register_frappe_integration(values: dict, api_key: str, api_secret: str) -> Result:
    """Register ERPNext credentials with Brew93 using the workspace bearer token."""
    if not api_key or not api_secret:
        raise Brew93ConfigError("ERPNext integration credentials are incomplete")
    base = _base_url(values)
    token = _get_user_crm_token(values, "Administrator")
    headers = {"Authorization": f"Bearer {token}"}
    if values.get("brew93_tenant_slug"):
        headers["x-tenant-slug"] = values["brew93_tenant_slug"]
    payload = {"base_url": frappe.utils.get_url(), "api_key": api_key, "api_secret": api_secret}
    session = _session()
    try:
        try:
            response = session.put(
                f"{base}/crm/integrations/frappe", json=payload, headers=headers,
                timeout=(5, values.get("request_timeout", 10)),
            )
        except requests.exceptions.RequestException as exc:
            raise Brew93ConfigError("Brew93 ERPNext integration registration is unavailable") from exc
        result = _classify(response)
        if not result.ok:
            raise Brew93ConfigError("Brew93 rejected the ERPNext integration configuration")
        return result
    finally:
        payload.clear()
        session.close()


def _read_refresh_token(token_owner: str, user: str | None) -> str | None:
    if token_owner == "workspace":
        return cfg.get_workspace_refresh_token()
    return cfg.get_user_refresh_token(user or token_owner)


def _store_refresh_token(token_owner: str, user: str | None, refresh_token: str) -> None:
    if token_owner == "workspace":
        cfg.set_workspace_refresh_token(refresh_token)
    else:
        cfg.set_user_refresh_token(user or token_owner, refresh_token)


def _do_refresh(session, values, token_owner, user, refresh_token):
    slug = values.get("brew93_tenant_slug")
    body = {"refresh_token": refresh_token}
    if slug:
        body.update(tenant_slug=slug, workspace_slug=slug)
    headers = {"x-tenant-slug": slug} if slug else {}
    try:
        resp = session.post(_base_url(values) + "/auth/refresh", json=body,
                            headers=headers, timeout=(5, values["request_timeout"]))
    finally:
        body = None
    if resp.status_code >= 300:
        return None
    data = _token_data(resp.json() or {})
    if data.get("refresh_token") and data["refresh_token"] != refresh_token:
        _store_refresh_token(token_owner, user, data["refresh_token"])
    return data


def _get_user_crm_token(values: dict, user: str | None, force: bool = False) -> str:
    _base_url(values)
    refresh = cfg.get_user_refresh_token(user) if user else None
    token_owner = user if refresh else "workspace"
    if not refresh:
        refresh = cfg.get_workspace_refresh_token()
    if not refresh:
        if user and not values.get("allow_service_fallback"):
            raise Brew93ConfigError("Brew93 user or workspace connection is not available")
        return _crm_token(values, force=force)
    key = _scoped_cache_key(_user_token_cache_key(token_owner), values)
    if not force and (cached := frappe.cache().get_value(key)):
        return cached
    lock_key = f"brew93:refresh-lock:{token_owner}"
    got_lock = frappe.cache().get_value(lock_key)
    if got_lock:
        # Another worker is rotating; re-read and use its result if fresh.
        import time
        for _ in range(20):
            time.sleep(0.25)
            current = _read_refresh_token(token_owner, user)
            cached = frappe.cache().get_value(key)
            if cached:
                return cached
            if current and current != refresh:
                refresh = current
                break
        else:
            current = _read_refresh_token(token_owner, user)
            if current:
                refresh = current
    frappe.cache().set_value(lock_key, 1, expires_in_sec=30)
    session = _session()
    try:
        data = _do_refresh(session, values, token_owner, user, refresh)
        if data is None:
            # Concurrent worker may have rotated; re-read once before failing.
            current = _read_refresh_token(token_owner, user)
            if current and current != refresh:
                refresh = current
                data = _do_refresh(session, values, token_owner, user, refresh)
        if data is None:
            # Stale user token: fall back to workspace before giving up.
            if token_owner != "workspace":
                ws = cfg.get_workspace_refresh_token()
                if ws:
                    token_owner = "workspace"
                    refresh = ws
                    key = _scoped_cache_key(_user_token_cache_key(token_owner), values)
                    data = _do_refresh(session, values, token_owner, user, refresh)
        if data is None:
            # Stale/revoked refresh: drop it so the next call can use service
            # login instead of looping on a dead token forever.
            try:
                from frappe.utils.password import remove_encrypted_password
                if token_owner == "workspace":
                    remove_encrypted_password(
                        "Brew93 Connector Settings", "Brew93 Connector Settings",
                        "brew93_refresh_token",
                    )
                elif user:
                    remove_encrypted_password("User", user, "brew93_refresh_token")
                frappe.db.commit()
            except Exception:
                pass
            if values.get("allow_service_fallback") or not user or user in ("Administrator", "Guest"):
                return _crm_token(values, force=True)
            raise Brew93ConfigError("Brew93 session refresh failed")
        access_token = data["access_token"]
        claims = _verified_claims(access_token)
        _assert_tenant(claims, values.get("brew93_tenant_id"))
        _validate_remote_identity(session, values, access_token, claims)
        ttl = _jwt_ttl(claims)
        if ttl:
            frappe.cache().set_value(key, data["access_token"], expires_in_sec=ttl)
        return data["access_token"]
    finally:
        frappe.cache().delete_value(lock_key)
        session.close()
