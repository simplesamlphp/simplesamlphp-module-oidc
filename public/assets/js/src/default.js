(function() {

    // Attach `confirm-action` click event to all elements with the `confirm-action` class.
    document.querySelectorAll('.confirm-action').forEach(button => {
        button.addEventListener('click', function (event) {
            // Get custom confirmation text
            const confirmText = this.getAttribute('data-confirm-text') ?? 'Are you sure?';
            // Optional: Retrieve additional data
            const itemId = this.getAttribute('data-confirm-id') ?? 'N/A';

            if (!confirm(confirmText)) {
                // Prevent the default action if the user cancels
                event.preventDefault();
            } else {
                // Optional: Handle confirmed action
                console.log(
                    `Confirmed action "${confirmText}" for item with ID "${itemId}"`);
            }
        });
    });

    // Handle forms with loading state
    document.querySelectorAll('form.form-with-loading-state').forEach(form => {
        form.addEventListener('submit', function (event) {
            const submitter = event.submitter || this.querySelector('button[type="submit"]');
            if (submitter) {
                const loadingText = submitter.getAttribute('data-loading-text') || 'Processing...';
                submitter.disabled = true;
                submitter.classList.add('loading');
                submitter.innerHTML = `<span class="form-loading-spinner"></span> ${loadingText}`;
            }
        });
    });
})();
