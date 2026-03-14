// app.js — global utilities loaded with defer in <head>.
// Because this script lives in <head> (outside <body>), it is never
// re-processed during htmx hx-boost body swaps, which means the event
// listeners registered here persist across page navigations.

function showToast(message, level) {
    level = level || 'success';
    var container = document.getElementById('toast-container');
    var wrapper = document.createElement('div');
    wrapper.className = 'toast align-items-center text-bg-' + level + ' border-0 show';
    wrapper.setAttribute('role', 'alert');
    wrapper.setAttribute('aria-atomic', 'true');
    wrapper.innerHTML =
        '<div class="d-flex">' +
            '<div class="toast-body">' + message + '</div>' +
            '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
        '</div>';
    container.appendChild(wrapper);
    setTimeout(function() { wrapper.remove(); }, 5000);
}

// For HTMX error responses, extract and apply OOB swaps (toasts) without
// touching the main target. We parse the response HTML, find elements with
// hx-swap-oob, and swap them in manually via htmx.process().
document.body.addEventListener('htmx:beforeSwap', function(evt) {
    if (evt.detail.xhr.status >= 400) {
        evt.detail.shouldSwap = false;
        evt.detail.isError = false;
        var responseText = evt.detail.xhr.responseText;
        if (responseText) {
            var doc = new DOMParser().parseFromString(responseText, 'text/html');
            var oobElements = doc.querySelectorAll('[hx-swap-oob]');
            oobElements.forEach(function(el) {
                var targetId = el.getAttribute('id');
                if (targetId) {
                    var existing = document.getElementById(targetId);
                    if (existing) {
                        existing.replaceWith(el);
                        htmx.process(el);
                    }
                }
            });
        }
    }
});

// Read flash cookie on page load
(function() {
    var raw = document.cookie.split('; ').find(function(c) { return c.startsWith('flash_message='); });
    if (!raw) return;
    var value = decodeURIComponent(raw.split('=').slice(1).join('='));
    document.cookie = 'flash_message=; Max-Age=0; path=/';
    try {
        var flash = JSON.parse(value);
        if (flash && flash.message) showToast(flash.message, flash.level);
    } catch(e) {}
})();

// Global handler: when a server response includes HX-Trigger: modalDismiss,
// clean up any Bootstrap modal backdrop left behind by OOB swaps that
// replaced the modal element before afterRequest could call .hide().
document.body.addEventListener('modalDismiss', function() {
    document.querySelectorAll('.modal-backdrop').forEach(function(el) { el.remove(); });
    document.body.classList.remove('modal-open');
    document.body.style.removeProperty('overflow');
    document.body.style.removeProperty('padding-right');
});
