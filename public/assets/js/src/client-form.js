(function () {
    'use strict';

    // Handle enabling and disabling input for 'allowed origins', based on client type radio input.
    function toggleAllowedOrigins() {
        if (radioOptionPublic.checked) {
            inputAllowedOrigin.disabled = false; // Enable the input field
        } else if (radioOptionConfidential.checked) {
            inputAllowedOrigin.disabled = true; // Disable the input field
        }
    }

    // Get references to the radio buttons and the input field
    const radioOptionPublic = document.getElementById("radio-option-public");
    const radioOptionConfidential = document.getElementById("radio-option-confidential");
    const inputAllowedOrigin = document.getElementById("frm-allowed_origin");

    radioOptionPublic.addEventListener("change", toggleAllowedOrigins);
    radioOptionConfidential.addEventListener("change", toggleAllowedOrigins);

    toggleAllowedOrigins();

    // Live-enforce the OIDC DCR response_type <-> grant_type correspondence: selecting a response type
    // auto-selects the grant types it requires. The map is provided by the server (single source of truth); the
    // server also normalizes on save, so this is a UX aid, not the authority. Fields remain editable.
    function readCorrespondenceMap() {
        const el = document.getElementById("oidc-response-type-grant-type-map");
        if (!el) {
            return {};
        }
        try {
            return JSON.parse(el.textContent) || {};
        } catch (e) {
            return {};
        }
    }

    const responseTypesSelect = document.getElementById("frm-response_types");
    const grantTypesSelect = document.getElementById("frm-grant_types");
    const correspondenceMap = readCorrespondenceMap();

    function syncRequiredGrantTypes() {
        if (!responseTypesSelect || !grantTypesSelect) {
            return;
        }
        const required = new Set();
        Array.from(responseTypesSelect.selectedOptions).forEach(function (option) {
            (correspondenceMap[option.value] || []).forEach(function (grantType) {
                required.add(grantType);
            });
        });
        Array.from(grantTypesSelect.options).forEach(function (option) {
            if (required.has(option.value)) {
                option.selected = true;
            }
        });
    }

    if (responseTypesSelect && grantTypesSelect) {
        responseTypesSelect.addEventListener("change", syncRequiredGrantTypes);
        syncRequiredGrantTypes();
    }

    // Keep the confidential/public type in lockstep with the metadata, using the same precedence as the server
    // (and DCR): token_endpoint_auth_method decides when selected (`none` => public, any real method =>
    // confidential); otherwise application_type `native` => public; otherwise the explicit choice stands.
    const tokenEndpointAuthMethodSelect = document.getElementById("frm-token_endpoint_auth_method");
    const applicationTypeSelect = document.getElementById("frm-application_type");

    function syncClientType() {
        const method = tokenEndpointAuthMethodSelect ? tokenEndpointAuthMethodSelect.value : "";
        if (method !== "") {
            if (method === "none") {
                radioOptionPublic.checked = true;
            } else {
                radioOptionConfidential.checked = true;
            }
            toggleAllowedOrigins();
            return;
        }
        // No auth method selected: a native application type indicates a public client.
        if (applicationTypeSelect && applicationTypeSelect.value === "native") {
            radioOptionPublic.checked = true;
            toggleAllowedOrigins();
        }
        // Otherwise leave the explicit confidential/public choice as-is.
    }

    if (tokenEndpointAuthMethodSelect) {
        tokenEndpointAuthMethodSelect.addEventListener("change", syncClientType);
    }
    if (applicationTypeSelect) {
        applicationTypeSelect.addEventListener("change", syncClientType);
    }
    if (tokenEndpointAuthMethodSelect || applicationTypeSelect) {
        syncClientType();
    }
})();
