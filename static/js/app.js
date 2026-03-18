// app.js — global utilities loaded with defer in <head>.
// Because this script lives in <head> (outside <body>), it is never
// re-processed during htmx hx-boost body swaps, which means the event
// listeners registered here persist across page navigations.

// Configure HTMX to process response bodies on error status codes so that
// OOB-swapped toasts are applied.  swapOverride:'none' ensures the main
// target is left untouched while OOB elements are still processed.
document.body.addEventListener('htmx:configRequest', function() {
    if (!htmx.config.responseHandling.find(function(r) { return r.code === '400'; })) {
        htmx.config.responseHandling = [
            { code: '204', swap: false },
            { code: '[23]..', swap: true },
            { code: '[45]..', swap: true, error: false, swapOverride: 'none' },
        ];
    }
}, { once: true });


// Global handler: when a server response includes HX-Trigger: modalDismiss,
// clean up any Bootstrap modal backdrop left behind by OOB swaps that
// replaced the modal element before afterRequest could call .hide().
document.body.addEventListener('modalDismiss', function() {
    document.querySelectorAll('.modal-backdrop').forEach(function(el) { el.remove(); });
    document.body.classList.remove('modal-open');
    document.body.style.removeProperty('overflow');
    document.body.style.removeProperty('padding-right');
});
