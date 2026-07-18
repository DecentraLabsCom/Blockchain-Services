// Add the server-bound CSRF header to same-origin administrative mutations.
(function () {
    'use strict';

    const originalFetch = window.fetch.bind(window);
    const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

    function csrfToken() {
        const item = document.cookie.split('; ').find((entry) => entry.startsWith('dlabs_csrf='));
        return item ? decodeURIComponent(item.slice('dlabs_csrf='.length)) : '';
    }

    window.fetch = function (input, init = {}) {
        const requestUrl = new URL(typeof input === 'string' ? input : input.url, window.location.href);
        const method = String(init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
        if (requestUrl.origin !== window.location.origin || !mutatingMethods.has(method)) {
            return originalFetch(input, init);
        }

        const headers = new Headers(input instanceof Request ? input.headers : undefined);
        new Headers(init.headers || {}).forEach((value, key) => headers.set(key, value));
        const token = csrfToken();
        if (token) {
            headers.set('X-CSRF-Token', token);
        }
        return originalFetch(input, { ...init, credentials: 'same-origin', headers });
    };
}());
