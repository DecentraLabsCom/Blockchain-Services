(function () {
    'use strict';

    const challengeField = document.getElementById('pairingChallenge');
    const offerButton = document.getElementById('offerPairingBtn');
    const offerButtonText = document.getElementById('offerBtnText');
    const completeButton = document.getElementById('completePairingBtn');
    const pairingDetails = document.getElementById('pairingDetails');
    const marketplaceApprovalLink = document.getElementById('marketplaceApprovalLink');
    const pairingProgress = document.getElementById('pairingProgress');
    const pairingProgressMessage = document.getElementById('pairingProgressMessage');
    const pairingProgressSpinner = document.getElementById('pairing-progress-spinner');
    let currentPairing = null;

    function setPairingProgress(message, { active = false, tone = 'info' } = {}) {
        if (!pairingProgress || !pairingProgressMessage) return;
        pairingProgressMessage.textContent = message || '';
        pairingProgress.classList.toggle('is-hidden', !message);
        pairingProgress.classList.toggle('is-active', Boolean(message) && active);
        pairingProgress.classList.toggle('is-success', tone === 'success');
        pairingProgress.classList.toggle('is-error', tone === 'error');
        pairingProgress.setAttribute('aria-busy', active ? 'true' : 'false');
        pairingProgressSpinner?.classList.toggle('is-hidden', !active);
    }

    function hideAlerts() {
        ['successAlert', 'errorAlert', 'infoAlert'].forEach((id) => {
            const element = document.getElementById(id);
            if (element) element.classList.remove('is-visible');
        });
    }

    function show(id, message) {
        const element = document.getElementById(id);
        if (!element) return;
        element.textContent = message;
        element.classList.add('is-visible');
    }

    function showError(message) {
        hideAlerts();
        setPairingProgress('', { tone: 'info' });
        show('errorAlert', message);
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>'"]/g, (character) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
        })[character]);
    }

    function updateSteps(currentStep) {
        document.querySelectorAll('#pairingSteps [data-step]').forEach((step) => {
            const stepNumber = Number(step.dataset.step);
            step.classList.toggle('is-complete', stepNumber < currentStep);
            step.classList.toggle('is-current', stepNumber === currentStep);
        });
    }

    function setMarketplaceApprovalLink(url) {
        if (!marketplaceApprovalLink || typeof url !== 'string' || !url.trim()) return;
        try {
            const parsed = new URL(url.trim(), window.location.origin);
            const isLocalHttp = parsed.protocol === 'http:'
                && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
            if (parsed.protocol !== 'https:' && !isLocalHttp) return;
            marketplaceApprovalLink.href = parsed.origin;
            marketplaceApprovalLink.classList.remove('is-hidden');
        } catch (_error) {
            // Keep the link hidden when the server does not expose a valid origin.
        }
    }

    function renderDetails(data) {
        currentPairing = data;
        pairingDetails.innerHTML = `
            <div class="readonly-value"><strong>Institution</strong><br>${escapeHtml(data.institutionId || '-')}</div>
            <div class="readonly-value"><strong>Pairing role</strong><br>${escapeHtml(data.registrationType || '-')}</div>
            <div class="readonly-value"><strong>Institutional wallet</strong><br><code>${escapeHtml(data.walletAddress || '-')}</code></div>
            <div class="readonly-value"><strong>Canonical backend origin</strong><br><code>${escapeHtml(data.canonicalBackendOrigin || '-')}</code></div>
            <div class="readonly-value"><strong>Pairing status</strong><br>${escapeHtml(data.status || '-')}</div>
        `;
        pairingDetails.classList.remove('is-hidden');
        completeButton.disabled = !data.challenge || data.status === 'EXPIRED';
        document.getElementById('statusBadge').innerHTML =
            `<div class="status-badge not-registered">Pairing ${escapeHtml(data.status || 'unknown')}</div>`;

        if (data.status === 'AWAITING_APPROVAL') {
            updateSteps(3);
            setPairingProgress('Backend offer created. Waiting for Marketplace approval.', { tone: 'info' });
            show('infoAlert', 'Review and approve the read-only wallet and origin values in the Marketplace, then return here to complete pairing.');
        } else if (data.status === 'APPROVED') {
            updateSteps(4);
            setPairingProgress('Marketplace approval received. Complete pairing here.', { tone: 'info' });
        } else if (data.status === 'EXPIRED') {
            setPairingProgress('This pairing challenge has expired. Generate a new challenge in the Marketplace.', { tone: 'error' });
        } else {
            updateSteps(2);
            setPairingProgress('Backend offer created. Continue with Marketplace approval.', { tone: 'info' });
        }
    }

    async function loadStatus() {
        setPairingProgress('Loading backend pairing status...', { active: true });
        try {
            const response = await fetch('/institution-config/status');
            const data = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(data.error || 'Failed to load backend status.');
            const configuredOrigin = typeof data.publicBaseUrl === 'string' ? data.publicBaseUrl.trim() : '';
            setMarketplaceApprovalLink(data.marketplaceBaseUrl);
            if (data.isRegistered) {
                document.getElementById('statusBadge').innerHTML = '<div class="status-badge registered">Paired</div>';
                completeButton.disabled = true;
                updateSteps(5);
                setPairingProgress('Pairing complete. This backend is ready for institutional use.', { tone: 'success' });
            } else if (!configuredOrigin) {
                showError('Pairing cannot start: configured public backend origin is required. Set PUBLIC_BASE_URL in blockchain-services/.env and reload this page.');
                updateSteps(1);
            } else {
                setPairingProgress('Ready to offer this backend for pairing.', { tone: 'info' });
            }
            if (data.operatingMode === 'consumer-only') {
                show('infoAlert', 'Consumer-only deployment: use a consumer pairing challenge from the Marketplace.');
            }
        } catch (_error) {
            showError(_error.message || 'Failed to load backend status.');
        }
    }

    document.getElementById('pairingForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        hideAlerts();
        const challenge = challengeField.value.trim();
        if (!/^0x[0-9a-fA-F]{64}$/.test(challenge)) {
            showError('Paste the complete 32-byte pairing challenge from the Marketplace (0x followed by 64 hexadecimal characters).');
            updateSteps(1);
            return;
        }

        offerButton.disabled = true;
        completeButton.disabled = true;
        offerButton.setAttribute('aria-busy', 'true');
        offerButtonText.textContent = 'Offering backend identity...';
        setPairingProgress('Offering backend identity and signing the backend wallet proof...', { active: true });
        try {
            const response = await fetch('/institution-config/apply-pairing-challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ challenge })
            });
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success) throw new Error(data.error || 'Pairing offer failed');
            renderDetails({ ...data, challenge });
            show('successAlert', 'Backend offer created. Approve the read-only values in the Marketplace, then complete pairing here.');
        } catch (error) {
            showError(error.message || 'Pairing offer failed.');
        } finally {
            offerButton.disabled = false;
            offerButton.setAttribute('aria-busy', 'false');
            offerButtonText.textContent = 'Offer backend identity';
        }
    });

    completeButton.addEventListener('click', async () => {
        if (!currentPairing?.challenge) return;
        hideAlerts();
        completeButton.disabled = true;
        offerButton.disabled = true;
        completeButton.setAttribute('aria-busy', 'true');
        setPairingProgress('Completing pairing with approved server-side credentials, saving the backend registration, and submitting the on-chain spending-period initialization. This can take a moment; keep this page open...', { active: true });
        try {
            const response = await fetch('/institution-config/complete-pairing', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ challenge: currentPairing.challenge })
            });
            const data = await response.json().catch(() => ({}));
            if (response.status === 206) {
                throw new Error('Marketplace approval is not complete yet. Approve the pairing, then retry.');
            }
            if (!response.ok || !data.success || data.registered !== true) {
                throw new Error(data.error || 'Pairing is not ready. Approve the pairing first.');
            }
            setPairingProgress('Pairing completed. This backend is now connected to the institution.', { tone: 'success' });
            show('successAlert', 'Institution pairing completed successfully.');
            document.getElementById('statusBadge').innerHTML = '<div class="status-badge registered">Paired</div>';
            updateSteps(5);
        } catch (error) {
            showError(error.message || 'Pairing is not ready. Approve the pairing first.');
            completeButton.disabled = false;
        } finally {
            offerButton.disabled = false;
            completeButton.setAttribute('aria-busy', 'false');
        }
    });

    loadStatus();
}());
