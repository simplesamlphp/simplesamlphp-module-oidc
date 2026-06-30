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

    // Keep the confidential/public type in lockstep with token_endpoint_auth_method (the primary signal):
    // `none` => public, any real authentication method => confidential. When the auth method is left unset ("-"),
    // the admin's explicit confidential/public choice stands. The server normalizes the same way on save.
    const tokenEndpointAuthMethodSelect = document.getElementById("frm-token_endpoint_auth_method");

    function syncClientTypeFromAuthMethod() {
        if (!tokenEndpointAuthMethodSelect) {
            return;
        }
        const method = tokenEndpointAuthMethodSelect.value;
        if (method === "") {
            return; // Unset: leave the explicit type choice as-is.
        }
        if (method === "none") {
            radioOptionPublic.checked = true;
        } else {
            radioOptionConfidential.checked = true;
        }
        toggleAllowedOrigins(); // Keep the allowed-origins field enabled/disabled in sync with the type.
    }

    if (tokenEndpointAuthMethodSelect) {
        tokenEndpointAuthMethodSelect.addEventListener("change", syncClientTypeFromAuthMethod);
        syncClientTypeFromAuthMethod();
    }
})();
