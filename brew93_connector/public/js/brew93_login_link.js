// Adds the connector-owned Brew93 link to the standard Frappe login page.
frappe.ready(function () {
    if (window.location.pathname !== "/login") return;
    frappe.xcall("brew93_connector.api.settings.sso_is_enabled_and_configured").then(function (enabled) {
        if (enabled !== true) return;
        const card = document.querySelector(".page-card-body") || document.querySelector(".page-card");
        if (!card || card.querySelector(".brew93-login-link")) return;
        const wrapper = document.createElement("div");
        wrapper.className = "text-center brew93-login-link";
        wrapper.style.cssText = "margin-top: 16px; font-size: 13px;";
        const link = document.createElement("a");
        link.href = "/brew93-login";
        link.textContent = __("Sign in with Brew93");
        wrapper.appendChild(link);
        card.appendChild(wrapper);
    });
});
