app_name = "brew93_connector"
app_title = "Brew93 Connector"
app_publisher = "KlyONIX Tech Consulting Private Limited"
app_description = "Brew93 CRM <-> ERPNext bidirectional integration (isolated connector app)"
app_email = "hello@klyonix.com"
app_license = "mit"

# Adds the connector-owned Brew93 link to the standard /login page.
web_include_js = ["/assets/brew93_connector/js/brew93_login_link.js"]

# Keep the legacy API name reachable during the ownership migration without
# delegating authentication back to brew93_ai.
override_whitelisted_methods = {
    "brew93_ai.brew93_sso.auth.login": "brew93_connector.api.sso.login",
}

# ---------------------------------------------------------------------------
# Installation: create external-ID mapping fields and integration identity.
# ---------------------------------------------------------------------------
after_install = "brew93_connector.setup.install.after_install"
after_migrate = "brew93_connector.setup.install.after_migrate"
before_uninstall = "brew93_connector.setup.custom_fields.remove_external_id_fields"

# ---------------------------------------------------------------------------
# Outbound (ERPNext -> Brew93). Every handler is a NO-OP unless
# `Brew93 Connector Settings.enabled` is on, and skips writes made BY the
# integration itself (loop prevention). Nothing here fires until the app is
# installed AND explicitly enabled.
# ---------------------------------------------------------------------------
doc_events = {
    "Lead": {
        "on_update": "brew93_connector.api.outbound.on_document_update",
        "on_trash": "brew93_connector.api.outbound.on_document_trash",
    },
    "Opportunity": {
        "on_update": "brew93_connector.api.outbound.on_document_update",
        "on_trash": "brew93_connector.api.outbound.on_document_trash",
    },
    "Contact": {
        "on_update": "brew93_connector.api.outbound.on_document_update",
        "on_trash": "brew93_connector.api.outbound.on_document_trash",
    },
    "Customer": {
        "on_update": "brew93_connector.api.outbound.on_document_update",
        "on_trash": "brew93_connector.api.outbound.on_document_trash",
    },
    # Quotation is submittable: capture draft edits, submit and cancel (all as
    # upserts carrying doc_status), plus delete. Duplicate enqueues from
    # overlapping events are collapsed by the payload_hash de-dupe.
    "Quotation": {
        "on_update": "brew93_connector.api.outbound.on_document_update",
        "on_submit": "brew93_connector.api.outbound.on_document_update",
        "on_cancel": "brew93_connector.api.outbound.on_document_update",
        "on_trash": "brew93_connector.api.outbound.on_document_trash",
    },
}

# Drain the outbound queue and pull recent updates from Brew93.
# Handlers exit immediately when the integration is disabled.
scheduler_events = {
    "cron": {
        "*/5 * * * *": [
            "brew93_connector.api.outbound.drain_queue",
            "brew93_connector.api.sync.pull_all_from_brew93",
        ],
    },
}
