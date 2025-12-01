(function () {
    'use strict';

    // Handle option changes based on Grant Type
    function togglePreAuthorizedCodeOptions() {
        if (grantTypeSelect.value === "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
            useTxCodeCheckbox.disabled = false;
            usersEmailAttributeNameInput.disabled = false;
        } else {
            useTxCodeCheckbox.disabled = true;
            useTxCodeCheckbox.checked = false;
            usersEmailAttributeNameInput.disabled = true;
        }
    }

    const grantTypeSelect = document.getElementById("grantType");

    // Get references to options
    const useTxCodeCheckbox = document.getElementById("useTxCode");
    const usersEmailAttributeNameInput = document.getElementById("usersEmailAttributeName");

    grantTypeSelect.addEventListener("change", togglePreAuthorizedCodeOptions);

    togglePreAuthorizedCodeOptions();
})();