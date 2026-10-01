// Copyright (c) 2026, KlyONIX Tech Consulting Private Limited
frappe.ui.form.on("Brew93 Connector Settings", {
    refresh: function (frm) {
        frm.add_custom_button(__("Sync Now from Brew93"), function () {
            frappe.show_alert({ message: __("Pulling updates from Brew93..."), indicator: "blue" });
            frappe.call({
                method: "brew93_connector.api.sync.pull_all_from_brew93",
                type: "POST",
                freeze: true,
                freeze_message: __("Syncing from Brew93..."),
                callback: function (r) {
                    if (r.message && r.message.ok) {
                        const res = r.message.results || {};
                        frappe.msgprint({
                            title: __("Sync Complete"),
                            indicator: "green",
                            message: `
                                <table class="table table-bordered table-sm">
                                    <thead><tr><th>Resource</th><th>Created</th><th>Updated</th><th>Skipped</th></tr></thead>
                                    <tbody>
                                        <tr><td>Leads</td><td>${(res.leads || {}).created || 0}</td><td>${(res.leads || {}).updated || 0}</td><td>${(res.leads || {}).skipped || 0}</td></tr>
                                        <tr><td>Deals</td><td>${(res.deals || {}).created || 0}</td><td>${(res.deals || {}).updated || 0}</td><td>${(res.deals || {}).skipped || 0}</td></tr>
                                        <tr><td>Contacts</td><td>${(res.contacts || {}).created || 0}</td><td>${(res.contacts || {}).updated || 0}</td><td>${(res.contacts || {}).skipped || 0}</td></tr>
                                        <tr><td>Customers</td><td>${(res.customers || {}).created || 0}</td><td>${(res.customers || {}).updated || 0}</td><td>${(res.customers || {}).skipped || 0}</td></tr>
                                        <tr><td>Quotations</td><td>${(res.quotations || {}).created || 0}</td><td>${(res.quotations || {}).updated || 0}</td><td>${(res.quotations || {}).skipped || 0}</td></tr>
                                    </tbody>
                                </table>
                            `
                        });
                        frm.reload_doc();
                    } else {
                        frappe.msgprint({
                            title: __("Sync Failed"),
                            indicator: "red",
                            message: r.message ? r.message.message : __("Unknown error occurred.")
                        });
                    }
                }
            });
        }).addClass("btn-primary");
    }
});
