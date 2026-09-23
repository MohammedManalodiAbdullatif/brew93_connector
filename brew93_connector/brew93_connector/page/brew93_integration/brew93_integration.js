// Connector-owned, privileged workspace-linking page.
frappe.pages["brew93-integration"].on_page_load = function (wrapper) {
    if (window.location.pathname === "/app/brew93-integration" || window.location.pathname === "/app/brew93-integration/") {
        window.location.replace("/desk/brew93-integration");
        return;
    }
    const page = frappe.ui.make_app_page({ parent: wrapper, title: __("Brew93 Integration"), single_column: true });
    if (frappe.session.user !== "Administrator") {
        page.main.html(`<div class="alert alert-danger">${__("Only the ERPNext Administrator can link Brew93.")}</div>`);
        return;
    }
    const form = new frappe.ui.FieldGroup({
        fields: [
            { fieldname: "base_url", fieldtype: "Data", label: __("Brew93 Base URL"), reqd: 1 },
            { fieldname: "tenant_id", fieldtype: "Data", label: __("Brew93 Tenant ID"), reqd: 1 },
            { fieldname: "workspace_slug", fieldtype: "Data", label: __("Brew93 Workspace Slug"), reqd: 1 },
            { fieldname: "username", fieldtype: "Data", label: __("Brew93 Username"), reqd: 1 },
            { fieldname: "password", fieldtype: "Password", label: __("Brew93 Password"), reqd: 1 }
        ], body: page.main,
    });
    form.make();
    page.set_primary_action(__("Link Workspace"), () => {
        const values = form.get_values();
        if (!values) return;
        frappe.call({ method: "brew93_connector.api.settings.link_workspace", type: "POST", args: values })
            .then(() => frappe.msgprint(__("Brew93 workspace linked successfully.")))
            .then(() => form.set_value("password", ""))
            .catch(() => form.set_value("password", ""));
    });
};
