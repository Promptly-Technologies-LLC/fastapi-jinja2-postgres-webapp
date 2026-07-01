// app.js — global htmx wiring loaded with defer in <head>.
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


// When a modal closes, reset any create-* form it contains so reopening it
// starts blank. ui.js dispatches 'hidden.bs.modal' when a modal is hidden.
document.body.addEventListener('hidden.bs.modal', function(event) {
    var modal = event.target;
    if (modal.id && modal.id.startsWith('create')) {
        var form = modal.querySelector('form');
        if (form) { form.reset(); }
    }
});

// Server responses can include HX-Trigger: modalDismiss to close a modal after
// an OOB swap has already replaced the modal element (so afterRequest can no
// longer hide it). Clean up any open modal and leftover backdrop.
document.body.addEventListener('modalDismiss', function() {
    if (window.UI) {
        window.UI.hideAllModals();
    }
});
