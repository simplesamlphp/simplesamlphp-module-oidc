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
})();
