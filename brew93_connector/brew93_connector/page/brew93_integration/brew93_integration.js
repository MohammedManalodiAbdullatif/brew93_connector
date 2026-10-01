// Connector-owned, privileged guided setup page. Secrets are sent only to the
// server action and are cleared from the form immediately after the request.
frappe.pages["brew93-integration"].on_page_load = function (wrapper) {
    const page = frappe.ui.make_app_page({ parent: wrapper, title: __("Brew93 Integration"), single_column: true });
    if (!frappe.user.has_role("System Manager") && frappe.session.user !== "Administrator") {
        page.main.html(`<div class="alert alert-danger">${__("Only a System Manager can configure Brew93.")}</div>`);
        return;
    }
    page.main.append(`<div class="mb-4"><p class="text-muted">${__("Connect one Brew93 workspace and register the secure ERPNext integration for two-way sync.")}</p><p><strong>${__("Brew93 API")}</strong>: <code>https://mcp.brew93.com/api/v1</code></p><div class="brew93-setup-status"></div></div>`);
    const form = new frappe.ui.FieldGroup({
        fields: [
            { fieldname: "workspace_slug", fieldtype: "Data", label: __("Brew93 Workspace Slug"), reqd: 1 },
            { fieldname: "username", fieldtype: "Data", label: __("Brew93 Login"), reqd: 1 },
            { fieldname: "password", fieldtype: "Password", label: __("Brew93 Password"), reqd: 1, description: __("Used once to establish the encrypted workspace connection.") }
        ], body: page.main,
    });
    form.make();
    const status = page.main.find(".brew93-setup-status");
    const render_status = (data) => status.html(`<div class="alert ${data.connected && data.integration_ready ? "alert-success" : "alert-warning"}"><strong>${__("Status")}: ${__(data.status || "Disconnected")}</strong><br>${data.connected && data.integration_ready ? __("Two-way sync is configured.") : __("Complete setup below to enable two-way sync.")}</div>`);
    frappe.call({ method: "brew93_connector.api.settings.get_setup_status" }).then(r => render_status(r.message || {})).catch(() => render_status({}));
    page.set_primary_action(__("Connect and Enable"), () => {
        const values = form.get_values();
        if (!values) return;
        frappe.call({ method: "brew93_connector.api.settings.setup_connector", type: "POST", args: values })
            .then(r => { render_status(r.message || {}); frappe.show_alert({ message: __("Brew93 two-way integration is connected."), indicator: "green" }); })
            .catch(() => frappe.msgprint(__("Setup failed. Check the URL, workspace slug, credentials, and Brew93 access.")))
            .finally(() => form.set_value("password", ""));
    });
    page.set_secondary_action(__("Sync from Brew93"), () => {
        frappe.show_alert({ message: __("Pulling updates from Brew93..."), indicator: "blue" });
        frappe.call({ method: "brew93_connector.api.sync.pull_all_from_brew93", type: "POST" })
            .then(r => {
                const res = (r.message || {}).results || {};
                frappe.show_alert({
                    message: __("Sync complete! Quotes: {0} updated, Leads: {1} created, Contacts: {2} created", [
                        (res.quotations || {}).updated || 0,
                        (res.leads || {}).created || 0,
                        (res.contacts || {}).created || 0
                    ]),
                    indicator: "green"
                });
            })
            .catch(() => frappe.msgprint(__("Sync failed. Ensure the Brew93 connector is enabled.")));
    });
};
