/**
 * Billing Admin Dashboard - Main Logic
 * Handles UI interactions, data loading, and automatic refresh
 */

// State management
const DashboardState = {
    autoRefreshInterval: null,
    autoRefreshEnabled: true,
    refreshIntervalMs: 300000, // 5 minutes
    lastUpdate: null,
    walletAddress: null,
    contractAddress: null,
    isInstitution: false,
    isProvider: false,
    isOperator: false,
    welcomeModalDismissed: false,
    inviteTokenApplied: false,  // Track if invite token has been applied
    invitePromptedWallet: null,  // Track which wallet has been prompted this session
    collectLabs: [],
    collectLabNames: {},
    selectedCollectLabId: null,
    collectCanExecute: false,
    collectLoadingStatus: false,
    collectSubmitting: false,
    collectMaxBatch: 50,
    collectLabsRetryTimeout: null,
    collectLabsRetryAttempts: 0,
    transactionsLimit: 10
};

const INVITE_TOKEN_STORAGE_PREFIX = 'dlabs_invite_token_applied:';
const COLLECT_LAB_NAME_CACHE_PREFIX = 'dlabs_collect_lab_names:';
const COLLECT_LABS_RETRY_DELAYS_MS = [1500, 3500, 7000];
const RECEIVABLE_TRANSITION_PRESETS = {
    '2:3': { from: 2, to: 3, label: 'Queue to invoiced' },
    '3:4': { from: 3, to: 4, label: 'Invoice approved' },
    '4:5': { from: 4, to: 5, label: 'Approval to paid' },
    '2:7': { from: 2, to: 7, label: 'Queue disputed' },
    '3:7': { from: 3, to: 7, label: 'Invoice disputed' },
    '4:7': { from: 4, to: 7, label: 'Approval disputed' },
    '7:3': { from: 7, to: 3, label: 'Dispute back to invoiced' },
    '7:4': { from: 7, to: 4, label: 'Dispute resolved as approved' },
    '2:6': { from: 2, to: 6, label: 'Queue reversed' },
    '3:6': { from: 3, to: 6, label: 'Invoice reversed' },
    '4:6': { from: 4, to: 6, label: 'Approval reversed' },
    '7:6': { from: 7, to: 6, label: 'Dispute reversed' }
};

function updateRoleBasedSections() {
    const hasWallet = Boolean(DashboardState.walletAddress);
    const showInstitutionControls = hasWallet && DashboardState.isInstitution;
    const showProviderControls = hasWallet && DashboardState.isProvider;
    const showOperatorControls = hasWallet && DashboardState.isOperator;

    const settlementSection = document.getElementById('settlementOperationsSection');
    const settlementTitle = document.getElementById('settlementOperationsTitle');
    const providerSettlementControls = document.getElementById('providerSettlementControls');
    const providerPayoutActions = document.getElementById('providerPayoutActions');
    const providerSettlementTransitionForm = document.getElementById('providerSettlementTransitionForm');
    const operatorCreditPolicySection = document.getElementById('operatorCreditPolicySection');
    const creditPolicyTitle = document.getElementById('creditPolicyTitle');
    const institutionPeriodBox = document.getElementById('institutionPeriodBox');
    const institutionLimitCard = document.getElementById('institutionLimitCard');
    const institutionPeriodCard = document.getElementById('institutionPeriodCard');
    const institutionResetCard = document.getElementById('institutionResetCard');
    const institutionTopSpendersSection = document.getElementById('institutionTopSpendersSection');
    const operatorIssueCreditsCard = document.getElementById('operatorIssueCreditsCard');
    const operatorAdjustCreditsCard = document.getElementById('operatorAdjustCreditsCard');
    const collectLifecycleSummary = document.getElementById('collectLifecycleSummary');
    const collectLabSelectLabel = document.getElementById('collectLabSelectLabel');

    if (settlementSection) {
        settlementSection.classList.toggle('hidden', !showProviderControls && !showOperatorControls);
    }
    if (providerSettlementControls) {
        providerSettlementControls.classList.toggle('hidden', !showProviderControls && !showOperatorControls);
    }
    if (providerPayoutActions) {
        providerPayoutActions.classList.toggle(
            'hidden',
            !showProviderControls || !(Array.isArray(DashboardState.collectLabs) && DashboardState.collectLabs.length > 0 && DashboardState.selectedCollectLabId)
        );
    }
    if (providerSettlementTransitionForm) {
        providerSettlementTransitionForm.classList.toggle('hidden', !showOperatorControls);
    }
    if (operatorCreditPolicySection) {
        operatorCreditPolicySection.classList.toggle('hidden', !showInstitutionControls && !showOperatorControls);
    }
    if (institutionPeriodBox) {
        institutionPeriodBox.classList.toggle('hidden', !showInstitutionControls);
    }
    if (institutionLimitCard) {
        institutionLimitCard.classList.toggle('hidden', !showInstitutionControls);
    }
    if (institutionPeriodCard) {
        institutionPeriodCard.classList.toggle('hidden', !showInstitutionControls);
    }
    if (institutionResetCard) {
        institutionResetCard.classList.toggle('hidden', !showInstitutionControls);
    }
    if (institutionTopSpendersSection) {
        institutionTopSpendersSection.classList.toggle('hidden', !showInstitutionControls);
    }
    if (operatorIssueCreditsCard) {
        operatorIssueCreditsCard.classList.toggle('hidden', !showOperatorControls);
    }
    if (operatorAdjustCreditsCard) {
        operatorAdjustCreditsCard.classList.toggle('hidden', !showOperatorControls);
    }
    if (collectLifecycleSummary) {
        collectLifecycleSummary.classList.toggle('hidden', !showProviderControls && !showOperatorControls);
    }

    if (settlementTitle) {
        if (showProviderControls && showOperatorControls) {
            settlementTitle.textContent = 'Provider Settlement and Operator Review';
        } else if (showOperatorControls) {
            settlementTitle.textContent = 'Operator Settlement Review';
        } else if (showProviderControls) {
            settlementTitle.textContent = 'Provider Settlement';
        } else {
            settlementTitle.textContent = 'Settlement Operations';
        }
    }

    if (creditPolicyTitle) {
        if (showInstitutionControls && showOperatorControls) {
            creditPolicyTitle.textContent = 'Institution Policy and Operator Controls';
        } else if (showInstitutionControls) {
            creditPolicyTitle.textContent = 'Institution Policy';
        } else if (showOperatorControls) {
            creditPolicyTitle.textContent = 'Operator Controls';
        } else {
            creditPolicyTitle.textContent = 'Administration';
        }
    }

    if (collectLabSelectLabel) {
        if (showProviderControls && !showOperatorControls) {
            collectLabSelectLabel.textContent = 'Select one of your labs';
        } else if (showOperatorControls) {
            collectLabSelectLabel.textContent = 'Select lab for settlement review';
        } else {
            collectLabSelectLabel.textContent = 'Select lab';
        }
    }

    if (collectLifecycleSummary && !collectLifecycleSummary.textContent.trim()) {
        collectLifecycleSummary.classList.add('hidden');
    }
}

function updateCollectDetailVisibility() {
    const metricsEl = document.getElementById('collectStatusMetrics');
    const actionsEl = document.getElementById('providerPayoutActions');
    const hasSelectedLab = Boolean(DashboardState.selectedCollectLabId);
    const hasLabs = Array.isArray(DashboardState.collectLabs) && DashboardState.collectLabs.length > 0;
    const showDetails = hasLabs && hasSelectedLab;

    if (metricsEl) {
        metricsEl.classList.toggle('hidden', !showDetails);
    }
    if (actionsEl) {
        actionsEl.classList.toggle('hidden', !DashboardState.isProvider || !showDetails);
    }
}

function getInviteTokenStorageKey(address) {
    return `${INVITE_TOKEN_STORAGE_PREFIX}${(address || '').toLowerCase()}`;
}

function normalizeStoredContractAddress(contractAddress) {
    return (contractAddress || '').trim().toLowerCase();
}

function loadInviteTokenState(address, contractAddress = null) {
    if (!address) {
        return false;
    }
    try {
        const storageKey = getInviteTokenStorageKey(address);
        const raw = localStorage.getItem(storageKey);
        if (!raw) {
            return false;
        }

        const expectedContract = normalizeStoredContractAddress(contractAddress);
        if (raw === 'true') {
            if (!expectedContract) {
                return true;
            }
            localStorage.removeItem(storageKey);
            return false;
        }

        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (parseError) {
            localStorage.removeItem(storageKey);
            return false;
        }

        if (!parsed || parsed.applied !== true) {
            return false;
        }

        const storedContract = normalizeStoredContractAddress(parsed.contractAddress);
        if (expectedContract && storedContract !== expectedContract) {
            localStorage.removeItem(storageKey);
            return false;
        }

        return true;
    } catch (error) {
        console.warn('Unable to read invite token state from storage', error);
        return false;
    }
}

function persistInviteTokenState(address, applied, contractAddress = null) {
    if (!address) {
        return;
    }
    try {
        const storageKey = getInviteTokenStorageKey(address);
        if (applied) {
            localStorage.setItem(storageKey, JSON.stringify({
                applied: true,
                contractAddress: normalizeStoredContractAddress(contractAddress)
            }));
        } else {
            localStorage.removeItem(storageKey);
        }
    } catch (error) {
        console.warn('Unable to persist invite token state', error);
    }
}

function maybePromptInviteToken(force = false) {
    const wallet = DashboardState.walletAddress;
    if (!wallet || DashboardState.inviteTokenApplied) {
        return;
    }
    if (!force && !DashboardState.welcomeModalDismissed) {
        return;
    }
    if (!force && DashboardState.invitePromptedWallet === wallet) {
        return;
    }
    showProvisioningTokenModal();
}

// Utility: Format wei to ETH
// show up to 12 decimal places in the dashboard (was 14 previously)
// this affects all ETH-formatting but the original request only
// targeted the "ETH Balance" display.
const MAX_ETH_DECIMALS = 12;
const CREDIT_DECIMALS = 5;
const CREDIT_RAW_BASE = 10n ** BigInt(CREDIT_DECIMALS);

// Converts a raw or formatted value to a human-readable ETH/credit amount.
//
// Parameters:
//   value        - input (string/number) already in ETH or credit units (not wei)
//   maxDecimals  - optional override of decimal precision; defaults to
//                  the global MAX_ETH_DECIMALS (12). callers can request
//                  fewer decimals for special displays (billing/bonded).
function formatEthDisplay(value, maxDecimals = MAX_ETH_DECIMALS) {
    if (value === null || value === undefined) return '0';

    let text = String(value).trim().replace(/,/g, '');
    if (!text) return '0';

    let sign = '';
    if (text.startsWith('-')) {
        sign = '-';
        text = text.slice(1);
    }

    if (!/^\d+(\.\d+)?$/.test(text)) {
        const numeric = Number(sign + text);
        if (!Number.isFinite(numeric)) {
            return '0';
        }
        text = Math.abs(numeric).toFixed(maxDecimals);
    }

    let [whole, fraction = ''] = text.split('.');
    whole = whole.replace(/^0+(?=\d)/, '') || '0';
    fraction = fraction.slice(0, maxDecimals).replace(/0+$/, '');

    return sign + (fraction ? `${whole}.${fraction}` : whole);
}

function weiToEth(weiString) {
    if (!weiString) return '0';
    try {
        const wei = BigInt(weiString);
        const negative = wei < 0n;
        const absWei = negative ? -wei : wei;
        const base = 1000000000000000000n;
        const whole = absWei / base;
        const fractionRaw = (absWei % base).toString().padStart(18, '0');
        const raw = negative ? `-${whole}.${fractionRaw}` : `${whole}.${fractionRaw}`;
        return formatEthDisplay(raw);
    } catch (error) {
        const fallback = Number(weiString);
        if (!Number.isFinite(fallback)) {
            return '0';
        }
        return formatEthDisplay(fallback / 1e18);
    }
}

// Utility: Format address
function formatAddress(address) {
    if (!address || address.length < 10) return address;
    return `${address.substring(0, 6)}...${address.substring(address.length - 4)}`;
}

// Utility: Format timestamp
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function formatLabTokenRaw(rawValue) {
    if (rawValue === null || rawValue === undefined || rawValue === '') {
        return '0';
    }
    try {
        const value = BigInt(rawValue.toString());
        const whole = value / CREDIT_RAW_BASE;
        const fraction = value % CREDIT_RAW_BASE;
        if (fraction === 0n) {
            return whole.toString();
        }
        const fractionText = fraction.toString().padStart(CREDIT_DECIMALS, '0').replace(/0+$/, '');
        return `${whole.toString()}.${fractionText}`;
    } catch (error) {
        const fallback = Number(rawValue);
        if (!Number.isFinite(fallback)) {
            return '0';
        }
        return (fallback / Number(CREDIT_RAW_BASE)).toFixed(CREDIT_DECIMALS).replace(/\.?0+$/, '');
    }
}

function decimalToRawUnits(value, decimals = CREDIT_DECIMALS) {
    const text = String(value ?? '').trim();
    if (!text) {
        throw new Error('Amount is required');
    }

    const match = text.match(/^([+-]?)(\d+)(?:\.(\d+))?$/);
    if (!match) {
        throw new Error('Please enter a valid numeric amount');
    }

    const [, sign, wholePart, fractionPart = ''] = match;
    const fraction = fractionPart.padEnd(decimals, '0').slice(0, decimals);
    const raw = `${sign}${wholePart}${fraction}`.replace(/^(-?)0+(?=\d)/, '$1');
    return raw === '-0' ? '0' : raw;
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getCollectLabNameCacheKey() {
    const contractAddress = (DashboardState.contractAddress || 'unknown').trim().toLowerCase();
    const walletAddress = (DashboardState.walletAddress || 'unknown').trim().toLowerCase();
    return `${COLLECT_LAB_NAME_CACHE_PREFIX}${contractAddress}:${walletAddress}`;
}

function loadCollectLabNameCache() {
    try {
        const raw = localStorage.getItem(getCollectLabNameCacheKey());
        const parsed = raw ? JSON.parse(raw) : {};
        DashboardState.collectLabNames = parsed && typeof parsed === 'object' ? parsed : {};
    } catch (error) {
        DashboardState.collectLabNames = {};
    }
}

function persistCollectLabNameCache() {
    try {
        localStorage.setItem(getCollectLabNameCacheKey(), JSON.stringify(DashboardState.collectLabNames || {}));
    } catch (error) {
        // Ignore storage failures; UI can still operate with in-memory state.
    }
}

function isFallbackLabLabel(value, labId) {
    const text = String(value || '').trim();
    if (!text) {
        return true;
    }
    return text.toLowerCase() === `lab #${String(labId).trim()}`.toLowerCase();
}

function enrichCollectLabsWithCachedNames(labs) {
    if (!Array.isArray(labs)) {
        return [];
    }

    const cache = DashboardState.collectLabNames || {};
    let cacheUpdated = false;
    const enriched = labs.map(lab => {
        const labId = String(lab.labId || '').trim();
        if (!labId) {
            return lab;
        }

        const currentName = String(lab.name || lab.label || '').trim();
        const cachedName = String(cache[labId] || '').trim();
        const effectiveName = !isFallbackLabLabel(currentName, labId)
            ? currentName
            : (cachedName || currentName);

        if (effectiveName && !isFallbackLabLabel(effectiveName, labId) && cache[labId] !== effectiveName) {
            cache[labId] = effectiveName;
            cacheUpdated = true;
        }

        return {
            ...lab,
            name: effectiveName || currentName || `Lab #${labId}`,
            label: effectiveName || currentName || `Lab #${labId}`
        };
    });

    DashboardState.collectLabNames = cache;
    if (cacheUpdated) {
        persistCollectLabNameCache();
    }

    return enriched;
}

function getCollectTargetLabel(lab = getSelectedCollectLab()) {
    if (!lab) {
        return DashboardState.selectedCollectLabId ? `Lab #${DashboardState.selectedCollectLabId}` : 'selected lab';
    }

    const name = String(lab.name || lab.label || '').trim();
    return name || `Lab #${lab.labId || DashboardState.selectedCollectLabId}`;
}

async function waitForAdminTransactionConfirmation(txHash, options = {}) {
    const intervalMs = options.intervalMs || 2000;
    const timeoutMs = options.timeoutMs || 120000;
    const startedAt = Date.now();

    while ((Date.now() - startedAt) < timeoutMs) {
        const txStatus = await API.getAdminTransactionStatus(txHash);
        if (txStatus.confirmed === true) {
            return txStatus;
        }
        await new Promise(resolve => setTimeout(resolve, intervalMs));
    }

    throw new Error('Transaction confirmation timed out');
}

// Toast notification
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 5000);
}

// Custom Modal Input (replaces prompt())
function showInputModal(title, message, type = 'password') {
    return new Promise((resolve) => {
        const modal = document.getElementById('inputModal');
        const titleEl = document.getElementById('inputModalTitle');
        const messageEl = document.getElementById('inputModalMessage');
        const inputField = document.getElementById('inputModalField');
        const confirmBtn = document.getElementById('inputModalConfirm');
        const cancelBtn = document.getElementById('inputModalCancel');
        const closeBtn = document.getElementById('closeInputModal');
        
        // Set modal content
        titleEl.innerHTML = `<i class="fas fa-keyboard"></i> ${title}`;
        messageEl.textContent = message;
        inputField.type = type;
        inputField.value = '';
        inputField.placeholder = type === 'password' ? 'Enter password...' : 'Enter value...';
        
        // Show modal
        modal.classList.add('show');
        inputField.focus();
        
        // Handle confirmation
        const handleConfirm = () => {
            const value = inputField.value.trim();
            cleanup();
            resolve(value || null);
        };
        
        // Handle cancellation
        const handleCancel = () => {
            cleanup();
            resolve(null);
        };
        
        // Cleanup function
        const cleanup = () => {
            modal.classList.remove('show');
            confirmBtn.removeEventListener('click', handleConfirm);
            cancelBtn.removeEventListener('click', handleCancel);
            closeBtn.removeEventListener('click', handleCancel);
            inputField.removeEventListener('keypress', handleKeyPress);
        };
        
        // Handle Enter key
        const handleKeyPress = (e) => {
            if (e.key === 'Enter') {
                handleConfirm();
            } else if (e.key === 'Escape') {
                handleCancel();
            }
        };
        
        // Attach event listeners
        confirmBtn.addEventListener('click', handleConfirm);
        cancelBtn.addEventListener('click', handleCancel);
        closeBtn.addEventListener('click', handleCancel);
        inputField.addEventListener('keypress', handleKeyPress);
    });
}

// Custom Info Modal (replaces alert())
function showInfoModal(title, content, isSuccess = true) {
    return new Promise((resolve) => {
        const modal = document.getElementById('infoModal');
        const titleEl = document.getElementById('infoModalTitle');
        const contentEl = document.getElementById('infoModalContent');
        const closeBtn = document.getElementById('infoModalClose');
        const closeIconBtn = document.getElementById('closeInfoModal');
        
        // Set modal content
        const icon = isSuccess ? 'check-circle' : 'info-circle';
        titleEl.innerHTML = `<i class="fas fa-${icon}"></i> ${title}`;
        
        // Format content (can be HTML)
        if (typeof content === 'string') {
            contentEl.innerHTML = content;
        } else {
            contentEl.innerHTML = '';
            contentEl.appendChild(content);
        }
        
        // Show modal
        modal.classList.add('show');
        
        // Handle close
        const handleClose = () => {
            modal.classList.remove('show');
            closeBtn.removeEventListener('click', handleClose);
            closeIconBtn.removeEventListener('click', handleClose);
            resolve();
        };
        
        // Attach event listeners
        closeBtn.addEventListener('click', handleClose);
        closeIconBtn.addEventListener('click', handleClose);
    });
}

function showConfirmModal(title, message, options = {}) {
    const {
        icon = 'question-circle',
        confirmText = 'Confirm',
        cancelText = 'Cancel',
        confirmButtonClass = 'btn-primary'
    } = options;

    return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        const titleEl = document.getElementById('confirmModalTitle');
        const messageEl = document.getElementById('confirmModalMessage');
        const confirmBtn = document.getElementById('confirmModalConfirm');
        const cancelBtn = document.getElementById('confirmModalCancel');
        const closeBtn = document.getElementById('closeConfirmModal');

        if (!modal || !titleEl || !messageEl || !confirmBtn || !cancelBtn || !closeBtn) {
            resolve(window.confirm(message || title || 'Confirm action?'));
            return;
        }

        titleEl.innerHTML = `<i class="fas fa-${icon}"></i> ${title}`;
        messageEl.textContent = message;
        confirmBtn.className = `btn ${confirmButtonClass}`;
        confirmBtn.innerHTML = `<i class="fas fa-check"></i> ${confirmText}`;
        cancelBtn.innerHTML = `<i class="fas fa-times"></i> ${cancelText}`;

        const cleanup = () => {
            modal.classList.remove('show');
            confirmBtn.removeEventListener('click', handleConfirm);
            cancelBtn.removeEventListener('click', handleCancel);
            closeBtn.removeEventListener('click', handleCancel);
            modal.removeEventListener('click', handleBackdropClick);
            document.removeEventListener('keydown', handleKeyDown);
        };

        const handleConfirm = () => {
            cleanup();
            resolve(true);
        };

        const handleCancel = () => {
            cleanup();
            resolve(false);
        };

        const handleBackdropClick = (event) => {
            if (event.target === modal) {
                handleCancel();
            }
        };

        const handleKeyDown = (event) => {
            if (event.key === 'Escape') {
                handleCancel();
            } else if (event.key === 'Enter') {
                handleConfirm();
            }
        };

        confirmBtn.addEventListener('click', handleConfirm);
        cancelBtn.addEventListener('click', handleCancel);
        closeBtn.addEventListener('click', handleCancel);
        modal.addEventListener('click', handleBackdropClick);
        document.addEventListener('keydown', handleKeyDown);
        modal.classList.add('show');
        confirmBtn.focus();
    });
}

function buildPrivateKeyContent(privateKey, address = null, note = 'Keep this private key offline. Anyone with this value can control the institutional wallet.') {
    if (!privateKey) {
        return '';
    }
    return `
        ${address ? `
            <div class="secret-header">
                <span class="info-label">Wallet Address</span>
                <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${address}')">
                    <i class="fas fa-copy"></i>
                    Copy
                </button>
            </div>
            <code class="secret-value">${address}</code>
        ` : ''}
        <div class="secret-header" style="margin-top: ${address ? 'var(--spacing-md)' : '0'}">
            <span class="info-label">Private Key</span>
            <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${privateKey}')">
                <i class="fas fa-copy"></i>
                Copy
            </button>
        </div>
        <code class="secret-value">${privateKey}</code>
        <div class="warning-text" style="margin-top: var(--spacing-md)">
            <i class="fas fa-lock"></i>
            ${note}
        </div>
    `;
}

function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    try {
        document.execCommand('copy');
        showToast('Copied to clipboard', 'success');
    } catch (err) {
        console.error('Clipboard copy failed', err);
        showToast('Unable to copy to clipboard', 'error');
    } finally {
        document.body.removeChild(textarea);
    }
}

function copyToClipboard(text) {
    if (!text) return;
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => showToast('Copied to clipboard', 'success'))
            .catch(() => fallbackCopy(text));
    } else {
        fallbackCopy(text);
    }
}

window.copyToClipboard = copyToClipboard;

async function showPrivateKeyModal(privateKey, address = null, title = 'Institutional Wallet Private Key') {
    const content = buildPrivateKeyContent(
        privateKey,
        address,
        'Keep this private key offline. Anyone with this value can control the institutional wallet.'
    );
    await showInfoModal(title, content, true);
}

// Update last refresh timestamp
function updateLastRefreshTime() {
    const now = Date.now();
    DashboardState.lastUpdate = now;
    const lastUpdateEl = document.getElementById('lastUpdate');
    if (lastUpdateEl) {
        lastUpdateEl.textContent = `Last update: ${formatTimestamp(now)}`;
    }
}

function updateDashboardAccessNotices(status) {
    const badge = document.getElementById('dashboardAccessBadge');
    const footer = document.getElementById('dashboardSecurityNotice');
    if (!badge || !footer || !status) {
        return;
    }

    const localOnly = status.dashboardLocalOnly !== false;
    const privateEnabled = status.allowPrivateNetworks === true && status.dashboardAllowPrivate === true;

    if (localOnly && !status.allowPrivateNetworks) {
        badge.textContent = 'Localhost Only';
        footer.textContent = '🔒 This dashboard is only accessible internally for security.';
    } else if (localOnly && privateEnabled) {
        badge.textContent = 'Private Network Access Enabled';
        footer.textContent = '⚠️ Security recommendation: restrict access to localhost or trusted private networks only.';
    } else if (!localOnly) {
        badge.textContent = 'External Access Allowed';
        footer.textContent = '⚠️ This dashboard may be accessible externally; enforce firewall or proxy restrictions.';
    } else {
        badge.textContent = 'Localhost Only';
        footer.textContent = '🔒 This dashboard is only accessible internally for security.';
    }
}

function renderProvisioningResult(result) {
    const container = document.getElementById('provisioningResult');
    if (!container) {
        return;
    }
    if (!result) {
        container.innerHTML = '';
        return;
    }

    const entries = (result.domains || []).map(entry => {
        if (entry.transactionHash) {
            return `
                <div class="info-line">
                    <span class="info-label">${entry.organization}</span>
                    <span class="info-value"><code>${entry.transactionHash}</code></span>
                </div>
            `;
        }
        return `
            <div class="info-line">
                <span class="info-label">${entry.organization}</span>
                <span class="info-value warning-text">${entry.error || 'Failed'}</span>
            </div>
        `;
    }).join('');

    container.innerHTML = entries || '<span class="muted">No organizations returned.</span>';
}

// Update header button visibility based on wallet and token status
function updateApplyInviteButtonVisibility() {
    const headerBtn = document.getElementById('applyProvisioningTokenHeaderBtn');
    if (headerBtn) {
        // Show button only if wallet is configured AND token not yet applied
        const shouldShow = DashboardState.walletAddress && !DashboardState.inviteTokenApplied;
        headerBtn.style.display = shouldShow ? 'inline-flex' : 'none';
    }
}

// Show/hide invite token modal
function showProvisioningTokenModal() {
    const modal = document.getElementById('provisioningTokenModal');
    const tokenInput = document.getElementById('provisioningTokenInput');
    const resultDiv = document.getElementById('provisioningResult');
    
    if (!DashboardState.walletAddress) {
        showToast('Configure your institutional wallet before applying a token.', 'error');
        return;
    }

    if (DashboardState.walletAddress) {
        DashboardState.invitePromptedWallet = DashboardState.walletAddress;
    }
    
    if (modal) {
        modal.classList.add('show');
        modal.style.display = '';
        if (tokenInput) tokenInput.value = '';
        if (resultDiv) resultDiv.innerHTML = '';
    }
}

function hideProvisioningTokenModal() {
    const modal = document.getElementById('provisioningTokenModal');
    if (modal) {
        modal.classList.remove('show');
        modal.style.display = '';
    }
}

async function readJsonResponse(response) {
    const text = await response.text();
    if (!text) {
        return { data: null, text: '' };
    }
    try {
        return { data: JSON.parse(text), text };
    } catch (error) {
        return { data: null, text, parseError: error };
    }
}

function extractResponseErrorMessage(response, result, fallbackMessage) {
    const parsed = result && result.data ? result.data : null;
    const text = result && typeof result.text === 'string' ? result.text.trim() : '';
    return (
        (parsed && (parsed.error || parsed.message || parsed.details)) ||
        text ||
        fallbackMessage ||
        `HTTP ${response.status}${response.statusText ? `: ${response.statusText}` : ''}`
    );
}

async function applyProvisioningToken() {
    const tokenInput = document.getElementById('provisioningTokenInput');
    if (!tokenInput) {
        return;
    }

    const token = tokenInput.value.trim();
    if (!token) {
        showToast('Provisioning token cannot be empty.', 'error');
        return;
    }

    if (!DashboardState.walletAddress) {
        showToast('Configure your institutional wallet before applying a token.', 'error');
        return;
    }

    const resultDiv = document.getElementById('provisioningResult');
    const applyBtn = document.getElementById('applyProvisioningBtn');
    
    // Disable button during processing
    if (applyBtn) applyBtn.disabled = true;

    try {
        // Show progress spinner with initial message
        showProvisioningProgress('Validating token format...');
        
        // Detect token type by decoding JWT payload
        const tokenType = detectTokenType(token);
        const endpoint = tokenType === 'consumer' 
            ? '/institution-config/apply-consumer-token'
            : '/institution-config/apply-provider-token';
        
        // Update progress message
        updateProvisioningProgress('Contacting marketplace...');
        
        // Add artificial delay to show the "contacting marketplace" message
        await new Promise(resolve => setTimeout(resolve, 800));
        
        // Update progress message
        updateProvisioningProgress('Verifying credentials with marketplace...');
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });

        // Update progress message
        updateProvisioningProgress('Processing registration on-chain...');

        const result = await readJsonResponse(response);
        if (result.parseError) {
            throw new Error('Invalid response from server.');
        }
        if (!result.data) {
            throw new Error('Empty response from server.');
        }
        const data = result.data;
        if (!response.ok) {
            throw new Error(data.error || 'Unable to apply provisioning token.');
        }

        // Update progress message
        updateProvisioningProgress('Waiting for blockchain confirmation...');
        
        // Add artificial delay to show the blockchain confirmation message
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Update progress message
        updateProvisioningProgress('Finalizing registration...');

        renderProvisioningResult(data, tokenType);

        const registrationCompleted = data.success && data.registered === true;

        if (registrationCompleted) {
            DashboardState.inviteTokenApplied = true;
            persistInviteTokenState(
                DashboardState.walletAddress,
                true,
                DashboardState.contractAddress
            );
            DashboardState.invitePromptedWallet = DashboardState.walletAddress;
            updateApplyInviteButtonVisibility();
        }

        const title = registrationCompleted
            ? (tokenType === 'consumer' ? 'Consumer Token Applied' : 'Provider Token Applied')
            : (tokenType === 'consumer' ? 'Consumer Token Saved' : 'Provider Token Saved');
        const message = registrationCompleted
            ? `Registration completed successfully. Type: ${tokenType}`
            : `Token validated and configuration saved, but registration did not complete. Request a fresh token and retry. Type: ${tokenType}`;

        await showInfoModal(title, message, registrationCompleted);

        if (registrationCompleted) {
            hideProvisioningTokenModal();
        }
        await refreshAllData();
    } catch (error) {
        console.error('Failed to apply provisioning token:', error);
        showToast(error.message || 'Failed to apply provisioning token', 'error');
        renderProvisioningResult({ error: error.message }, 'unknown');
    } finally {
        // Re-enable button
        if (applyBtn) applyBtn.disabled = false;
    }
}

// Show provisioning progress spinner
function showProvisioningProgress(message) {
    const resultDiv = document.getElementById('provisioningResult');
    if (!resultDiv) return;
    
    resultDiv.innerHTML = `
        <div class="provisioning-progress">
            <div class="spinner-container">
                <div class="spinner"></div>
            </div>
            <div class="progress-message">${message}</div>
        </div>
    `;
}

// Update provisioning progress message
function updateProvisioningProgress(message) {
    const messageEl = document.querySelector('#provisioningResult .progress-message');
    if (messageEl) {
        messageEl.textContent = message;
    }
}

// Helper function to detect token type from JWT payload
function detectTokenType(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return 'provider'; // Default to provider
        
        const payload = JSON.parse(atob(parts[1]));
        return payload.type || 'provider'; // Check 'type' claim
    } catch (error) {
        console.warn('Failed to decode token, defaulting to provider type', error);
        return 'provider';
    }
}

// Render provisioning result
function renderProvisioningResult(data, tokenType) {
    const resultDiv = document.getElementById('provisioningResult');
    if (!resultDiv) return;
    
    if (data.error) {
        resultDiv.innerHTML = `<div class="error-message"><i class="fas fa-exclamation-triangle"></i> ${data.error}</div>`;
        return;
    }
    
    if (data.success) {
        const config = data.config || {};
        const registrationCompleted = data.registered === true;
        let html = registrationCompleted
            ? '<div class="success-message"><i class="fas fa-check-circle"></i> Token applied successfully!</div>'
            : '<div class="warning-message"><i class="fas fa-exclamation-triangle"></i> Token validated, but registration did not complete.</div>';
        html += '<div class="token-details">';
        html += `<p><strong>Type:</strong> ${tokenType === 'consumer' ? 'Consumer (reserves only)' : 'Provider (publishes labs)'}</p>`;
        
        if (tokenType === 'consumer') {
            if (config.consumerName) html += `<p><strong>Name:</strong> ${config.consumerName}</p>`;
            if (config.consumerOrganization) html += `<p><strong>Organization:</strong> ${config.consumerOrganization}</p>`;
        } else {
            if (config.providerName) html += `<p><strong>Provider:</strong> ${config.providerName}</p>`;
            if (config.providerOrganization) html += `<p><strong>Organization:</strong> ${config.providerOrganization}</p>`;
            if (config.publicBaseUrl) html += `<p><strong>Auth URI:</strong> ${config.publicBaseUrl}</p>`;
        }
        
        html += `<p><strong>Registered:</strong> ${data.registered ? 'Yes ✓' : 'Pending'}</p>`;
        if (!registrationCompleted) {
            html += '<p><strong>Next step:</strong> Request a fresh invitation token and retry.</p>';
        }
        html += '</div>';
        resultDiv.innerHTML = html;
    }
}

// Welcome Modal Functions
function showWelcomeModal() {
    const modal = document.getElementById('welcomeModal');
    if (modal) {
        modal.classList.add('show');
    }
}

function hideWelcomeModal(dismissed = false) {
    const modal = document.getElementById('welcomeModal');
    if (modal) {
        modal.classList.remove('show');
    }
    if (dismissed) {
        DashboardState.welcomeModalDismissed = true;
    }
}

function updateMarketplaceUrl(url) {
    const link = document.getElementById('marketplaceLink');
    if (link && url) {
        link.href = url;
    }
}

function renderWalletSetupPrompt() {
    const walletAddressEl = document.getElementById('walletAddress');
    if (!walletAddressEl) {
        return;
    }

    walletAddressEl.innerHTML = '<span class="warning-text clickable" id="walletSetupTrigger">Not configured - Click to set up</span>';
    setTimeout(() => {
        const trigger = document.getElementById('walletSetupTrigger');
        if (trigger) {
            trigger.addEventListener('click', toggleWalletSetupDropdown);
        }
    }, 100);
}

// Load system status
async function loadSystemStatus() {
    console.log('[loadSystemStatus] Starting...');
    try {
        console.log('[loadSystemStatus] Calling API.getSystemStatus()...');
        const [data, providerConfig] = await Promise.all([
            API.getSystemStatus(),
            API.getProviderConfigStatus().catch(error => {
                console.warn('[loadSystemStatus] provider config status unavailable', error);
                return null;
            })
        ]);
        console.log('[loadSystemStatus] Received data:', data);
        if (providerConfig) {
            console.log('[loadSystemStatus] Provider config status:', providerConfig);
        }
        
        if (data.success) {
            const walletConfigured = data.walletConfigured;
            const walletAddress = data.institutionalWalletAddress;
            const contractAddress =
                data.contractAddress ||
                data.verifyingContract ||
                data.billingAdminEip712?.verifyingContract ||
                null;
            DashboardState.isInstitution = data.institutionControlsEnabled === true || data.isInstitution === true;
            DashboardState.isProvider = data.providerControlsEnabled === true || data.isProvider === true;
            DashboardState.isOperator = data.operatorControlsEnabled === true || data.isDefaultAdmin === true;
            const previousWallet = DashboardState.walletAddress;
            DashboardState.walletAddress = walletAddress || null;
            DashboardState.contractAddress = contractAddress;
            
            if (DashboardState.walletAddress !== previousWallet) {
                DashboardState.invitePromptedWallet = null;
            }
            
            if (DashboardState.walletAddress) {
                const storedInviteApplied = loadInviteTokenState(
                    DashboardState.walletAddress,
                    DashboardState.contractAddress
                );
                const providerApplied = providerConfig && providerConfig.isRegistered === true;

                DashboardState.inviteTokenApplied = storedInviteApplied || providerApplied;

                if (providerApplied) {
                    persistInviteTokenState(
                        DashboardState.walletAddress,
                        true,
                        DashboardState.contractAddress
                    );
                    DashboardState.invitePromptedWallet = DashboardState.walletAddress;
                }
            } else {
                DashboardState.inviteTokenApplied = false;
                DashboardState.invitePromptedWallet = null;
                DashboardState.contractAddress = null;
                hideProvisioningTokenModal();
            }
            
            // Update marketplace URL if provided
            if (data.marketplaceUrl) {
                updateMarketplaceUrl(data.marketplaceUrl);
            }
            
            // Show welcome modal after wallet exists and token is still pending
            const shouldPromptToken = !!walletAddress && !DashboardState.inviteTokenApplied;
            if (shouldPromptToken && !DashboardState.welcomeModalDismissed) {
                showWelcomeModal();
            } else {
                hideWelcomeModal(false);
            }
            
            console.log('[loadSystemStatus] Wallet configured:', walletConfigured);
            console.log('[loadSystemStatus] Wallet address:', walletAddress);
            console.log('[loadSystemStatus] Contract address:', data.contractAddress);
            
            // Update wallet address display
            const walletAddressEl = document.getElementById('walletAddress');
            console.log('[loadSystemStatus] walletAddressEl:', walletAddressEl);
            if (walletAddress) {
                walletAddressEl.textContent = formatAddress(walletAddress);
                walletAddressEl.classList.remove('warning-text');
            } else {
                renderWalletSetupPrompt();
            }

            // Show/hide reveal private key button in header
            const revealPrivateKeyBtn = document.getElementById('revealPrivateKeyBtn');
            if (revealPrivateKeyBtn) {
                revealPrivateKeyBtn.style.display = walletAddress ? 'inline-flex' : 'none';
                revealPrivateKeyBtn.disabled = !walletAddress;
            }
            
            // Update Apply Invite Token button visibility
            updateApplyInviteButtonVisibility();
            maybePromptInviteToken();
            updateRoleBasedSections();
            
            // Show/hide wallet setup dropdown
            const dropdown = document.getElementById('walletSetupDropdown');
            if (dropdown) {
                dropdown.style.display = 'none'; // Always start hidden, user clicks to open
            }
            
            const detectedContractAddress =
                data.contractAddress ||
                data.verifyingContract ||
                data.billingAdminEip712?.verifyingContract ||
                null;

            document.getElementById('contractAddress').textContent =
                detectedContractAddress ? formatAddress(detectedContractAddress) : 'Not configured';
            
            console.log('[loadSystemStatus] Updated contract address element');
            
            // Update network buttons to show active network
            const activeNet =
                data.activeNetwork ||
                data.network ||
                data.chainId ||
                'sepolia';
            updateNetworkButtons(activeNet);
            
            // Update status indicator
            const statusIndicator = document.getElementById('statusIndicator');
            if (walletConfigured) {
                statusIndicator.querySelector('.status-dot').style.background = 'var(--neon-green)';
                statusIndicator.querySelector('.status-text').textContent = 'Connected';
            } else {
                statusIndicator.querySelector('.status-dot').style.background = 'var(--neon-yellow)';
                statusIndicator.querySelector('.status-text').textContent = 'Wallet Setup Required';
            }

            updateDashboardAccessNotices(data);
        }
        
        updateLastRefreshTime();
        console.log('[loadSystemStatus] Completed successfully');
    } catch (error) {
        console.error('[loadSystemStatus] ERROR:', error);
        console.error('Failed to load system status:', error);
        showToast('Failed to load system status: ' + error.message, 'error');

        DashboardState.walletAddress = null;
        DashboardState.contractAddress = null;
        DashboardState.isInstitution = false;
        DashboardState.isProvider = false;
        DashboardState.isOperator = false;
        DashboardState.inviteTokenApplied = false;
        DashboardState.invitePromptedWallet = null;
        hideProvisioningTokenModal();
        updateApplyInviteButtonVisibility();
        renderWalletSetupPrompt();
        updateRoleBasedSections();

        const contractAddressEl = document.getElementById('contractAddress');
        if (contractAddressEl) {
            contractAddressEl.textContent = 'Unavailable';
        }
        
        // Update status indicator to error state
        const statusIndicator = document.getElementById('statusIndicator');
        statusIndicator.querySelector('.status-dot').style.background = 'var(--neon-red)';
        statusIndicator.querySelector('.status-text').textContent = 'Disconnected';
    }
}

// Toggle wallet setup dropdown
function toggleWalletSetupDropdown() {
    const dropdown = document.getElementById('walletSetupDropdown');
    if (dropdown) {
        const isVisible = dropdown.style.display === 'block';
        
        if (isVisible) {
            dropdown.style.opacity = '0';
            setTimeout(() => {
                dropdown.style.display = 'none';
            }, 300);
        } else {
            dropdown.style.display = 'block';
            setTimeout(() => {
                dropdown.style.opacity = '1';
            }, 10);
        }
    }
}

// Update network buttons to show active network
function updateNetworkButtons(activeNetwork) {
    const sepoliaBtn = document.getElementById('sepoliaBtn');
    const mainnetBtn = document.getElementById('mainnetBtn');
    const normalized = (activeNetwork || '').toString().trim().toLowerCase();
    
    if (sepoliaBtn && mainnetBtn) {
        // Remove active class from both
        sepoliaBtn.classList.remove('active');
        mainnetBtn.classList.remove('active');
        
        // Add active class to the current network
        if (normalized.includes('sepolia') || normalized === '11155111') {
            sepoliaBtn.classList.add('active');
        } else if (normalized.includes('mainnet') || normalized === '1') {
            mainnetBtn.classList.add('active');
        }
    }
}

async function handleRevealPrivateKey() {
    const password = await showInputModal(
        'Show Private Key',
        'Enter the institutional wallet password to decrypt the private key:',
        'password'
    );

    if (!password) {
        return;
    }

    try {
        showToast('Decrypting wallet...', 'info');
        const data = await API.revealPrivateKey(password);
        if (data.success && data.privateKey) {
            await showPrivateKeyModal(data.privateKey, data.address);
        } else {
            showToast(data.error || 'Failed to reveal private key', 'error');
        }
    } catch (error) {
        showToast('Failed to reveal private key: ' + error.message, 'error');
    }
}


// Switch blockchain network
async function switchNetwork(networkId) {
    const sepoliaBtn = document.getElementById('sepoliaBtn');
    const mainnetBtn = document.getElementById('mainnetBtn');
    
    try {
        // Disable buttons during switch
        if (sepoliaBtn) sepoliaBtn.disabled = true;
        if (mainnetBtn) mainnetBtn.disabled = true;
        
        showToast(`Switching to ${networkId}...`, 'info');
        
        const data = await API.switchNetwork(networkId);
        
        if (data.success) {
            showToast(`Successfully switched to ${networkId}`, 'success');
            
            // Update network buttons
            updateNetworkButtons(networkId);
            
            // Auto-refresh all data to reflect new network
            await refreshAllData();
        } else {
            showToast(`Failed to switch network: ${data.error || 'Unknown error'}`, 'error');
            
            // Revert buttons to previous state
            await loadSystemStatus();
        }
    } catch (error) {
        console.error('Network switch failed:', error);
        showToast(`Network switch failed: ${error.message}`, 'error');
        
        // Revert buttons to previous state
        await loadSystemStatus();
    } finally {
        // Re-enable buttons
        if (sepoliaBtn) sepoliaBtn.disabled = false;
        if (mainnetBtn) mainnetBtn.disabled = false;
    }
}


// Load wallet balances
async function loadBalances() {
    try {
        // Get system status to know the active network
        const statusData = await API.getSystemStatus();
        const activeNetwork = statusData.activeNetwork || 'sepolia';
        
        // Get all balances and billing info in parallel
        const [data, billingData] = await Promise.all([
            API.getBalance(),
            API.getBillingInfo().catch(err => ({ success: false }))
        ]);
        
        if (data.success && data.balances) {
            const balanceGrid = document.getElementById('balanceGrid');
            balanceGrid.innerHTML = '';
            
            // Only show balance for the active network
            const balanceData = data.balances[activeNetwork];
            
            if (!balanceData) {
                balanceGrid.innerHTML = `
                    <div class="balance-item">
                        <div class="balance-network">${activeNetwork}</div>
                        <div class="balance-amount" style="color: var(--text-muted); font-size: 1rem;">
                            No data available
                        </div>
                    </div>
                `;
                return;
            }
            
            if (balanceData.error) {
                balanceGrid.innerHTML = `
                    <div class="balance-item">
                        <div class="balance-network">${activeNetwork}</div>
                        <div class="balance-amount" style="color: var(--neon-red); font-size: 1rem;">
                            Error: ${balanceData.error}
                        </div>
                    </div>
                `;
            } else {
                const ethBalance = formatEthDisplay(balanceData.balanceEth ?? weiToEth(balanceData.balanceWei));
                
                // Display ETH balance
                balanceGrid.innerHTML += `
                    <div class="balance-item">
                        <div class="balance-label">ETH Balance</div>
                        <div class="balance-amount">${ethBalance} ETH</div>
                    </div>
                `;
                
                // Display closed service credit balance for the connected wallet
                if (balanceData.labBalance !== undefined) {
                    // Service credits use the same generic formatter for dashboard display
                    const labBalance = formatEthDisplay(balanceData.labBalance || '0');
                    balanceGrid.innerHTML += `
                        <div class="balance-item">
                            <div class="balance-label">Service credits</div>
                            <div class="balance-amount">${labBalance} credits</div>
                        </div>
                    `;
                    
                    // Check if user is a registered provider from billing data
                    const isProvider = billingData.success && billingData.isProvider === true;
                    const stakeInfo = billingData.stakeInfo || null;
                    // billing and bonded amounts only show 8 decimals
                    const billingBalance = formatEthDisplay(billingData.billingBalanceFormatted || '0', 8);
                    
                    // Display billing balance if provider
                    if (isProvider && parseFloat(billingBalance) > 0) {
                        balanceGrid.innerHTML += `
                            <div class="balance-item">
                                <div class="balance-label">
                                    <i class="fas fa-university" style="margin-right: 0.3rem; color: var(--neon-cyan);"></i>
                                    Provider billing balance
                                </div>
                                <div class="balance-amount" style="color: var(--neon-cyan);">${billingBalance} credits</div>
                            </div>
                        `;
                    }
                    
                    // Display Bonded Amount if provider
                    if (isProvider && stakeInfo && stakeInfo.stakedAmountFormatted) {
                        const bondedAmount = formatEthDisplay(stakeInfo.stakedAmountFormatted, 8);
                        if (parseFloat(bondedAmount) > 0) {
                            balanceGrid.innerHTML += `
                                <div class="balance-item">
                                    <div class="balance-label">
                                        <i class="fas fa-lock" style="margin-right: 0.3rem; color: var(--neon-purple);"></i>
                                        Bonded
                                    </div>
                                    <div class="balance-amount" style="color: var(--neon-purple);">${bondedAmount} credits</div>
                                </div>
                            `;
                        }
                    }
                    
                    // Show promotional message only if NOT a provider and credit balance is 0
                    const promoContainer = document.getElementById('labPromoMessage');
                    if (promoContainer) {
                        if (!isProvider && parseFloat(labBalance) === 0) {
                            promoContainer.style.display = 'block';
                            promoContainer.innerHTML = `
                                <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, rgba(0, 255, 157, 0.1), rgba(0, 229, 255, 0.1)); border-radius: 0.5rem; margin-top: 1rem; border: 1px solid rgba(0, 255, 157, 0.2);">
                                    <div style="font-size: 1.1rem; color: var(--neon-cyan); margin-bottom: 0.5rem;">
                                        <i class="fas fa-rocket" style="margin-right: 0.5rem; color: var(--neon-green);"></i>
                                        Register as a provider now to get <strong style="color: var(--neon-green);">1000 onboarding credits</strong>!
                                    </div>
                                    <a href="https://marketplace-decentralabs.vercel.app" 
                                       target="_blank" 
                                       style="color: var(--neon-green); text-decoration: none; font-weight: bold; font-size: 1rem; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 0.5rem;">
                                        <i class="fas fa-external-link-alt"></i>
                                        Visit Marketplace
                                    </a>
                                </div>
                            `;
                        } else {
                            promoContainer.style.display = 'none';
                            promoContainer.innerHTML = '';
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('Failed to load balances:', error);
        showToast('Failed to load balances: ' + error.message, 'error');
    }
}

function setCollectStatusText(message, tone = null) {
    const statusEl = document.getElementById('collectStatusText');
    if (!statusEl) return;
    statusEl.textContent = message || '--';
    statusEl.className = 'collect-status-value';
    if (tone) {
        statusEl.classList.add(tone);
    }
}

function clearCollectLabsRetryTimer() {
    if (DashboardState.collectLabsRetryTimeout) {
        clearTimeout(DashboardState.collectLabsRetryTimeout);
        DashboardState.collectLabsRetryTimeout = null;
    }
}

function resetCollectLabsRetryState() {
    clearCollectLabsRetryTimer();
    DashboardState.collectLabsRetryAttempts = 0;
}

function isRetriableCollectLabsError(error) {
    const message = String(error?.message || '').toLowerCase();
    if (!message) {
        return false;
    }

    return (
        message.includes('failed to fetch') ||
        message.includes('networkerror') ||
        message.includes('load failed') ||
        message.includes('http 5') ||
        message.includes('timeout') ||
        message.includes('unexpected token') ||
        message.includes('invalid response') ||
        message.includes('institutional wallet not configured') ||
        message.includes('failed to retrieve provider labs')
    );
}

function scheduleCollectLabsRetry(error) {
    if (!isRetriableCollectLabsError(error)) {
        return false;
    }

    return scheduleNextCollectLabsRetry();
}

function shouldRetryEmptyCollectLabs() {
    return Boolean(DashboardState.walletAddress) && (DashboardState.isProvider || DashboardState.isOperator);
}

function scheduleNextCollectLabsRetry(statusMessage = null) {
    if (DashboardState.collectLabsRetryAttempts >= COLLECT_LABS_RETRY_DELAYS_MS.length) {
        return false;
    }

    clearCollectLabsRetryTimer();
    const attemptIndex = DashboardState.collectLabsRetryAttempts;
    const delayMs = COLLECT_LABS_RETRY_DELAYS_MS[attemptIndex];
    DashboardState.collectLabsRetryAttempts += 1;

    setCollectStatusText(
        statusMessage || `Retrying labs in ${Math.ceil(delayMs / 1000)}s...`,
        'warning'
    );
    DashboardState.collectLabsRetryTimeout = setTimeout(() => {
        DashboardState.collectLabsRetryTimeout = null;
        loadCollectLabs();
    }, delayMs);

    return true;
}

function setCollectPendingClosuresText(value) {
    const closuresEl = document.getElementById('collectPendingClosures');
    if (!closuresEl) return;
    closuresEl.textContent = value ?? '--';
}

function setCollectLifecycleSummaryText(value) {
    const lifecycleEl = document.getElementById('collectLifecycleSummary');
    if (!lifecycleEl) return;
    const normalizedValue = String(value || '').trim();
    lifecycleEl.textContent = normalizedValue;
    lifecycleEl.classList.toggle('hidden', !normalizedValue);
}

function formatLifecycleBucket(label, rawValue, formattedValue) {
    const raw = rawValue ?? '0';
    try {
        if (BigInt(raw.toString()) <= 0n) {
            return null;
        }
    } catch (error) {
        return null;
    }
    const amount = formattedValue || formatLabTokenRaw(raw);
    return `${label} ${amount} credits`;
}

function buildCollectLifecycleSummary(data) {
    const items = [
        formatLifecycleBucket('Accrued', data.accruedReceivableRaw, data.accruedReceivableLab),
        formatLifecycleBucket('Queued', data.settlementQueuedRaw, data.settlementQueuedLab),
        formatLifecycleBucket('Invoiced', data.invoicedReceivableRaw, data.invoicedReceivableLab),
        formatLifecycleBucket('Approved', data.approvedReceivableRaw, data.approvedReceivableLab),
        formatLifecycleBucket('Disputed', data.disputedReceivableRaw, data.disputedReceivableLab),
        formatLifecycleBucket('Paid', data.paidReceivableRaw, data.paidReceivableLab),
        formatLifecycleBucket('Reversed', data.reversedReceivableRaw, data.reversedReceivableLab),
    ].filter(Boolean);

    return items.length ? items.join(' | ') : '';
}

function getReceivableTransitionPreset(value) {
    return RECEIVABLE_TRANSITION_PRESETS[value] || null;
}

function formatPendingClosures(rawValue) {
    if (rawValue === null || rawValue === undefined || rawValue === '') {
        return '0';
    }
    try {
        return BigInt(rawValue.toString()).toString();
    } catch (error) {
        return String(rawValue);
    }
}

function setCollectPanelCompact(isCompact) {
    const panel = document.getElementById('collectPanel');
    if (!panel) return;
    panel.classList.toggle('compact', Boolean(isCompact));
}

function renderCollectLabOptions(selectEl, labs, preferredLabId = null) {
    if (!selectEl) {
        return null;
    }
    if (!Array.isArray(labs) || !labs.length) {
        selectEl.innerHTML = '<option value="">No labs available</option>';
        updateCollectDetailVisibility();
        return null;
    }

    const availableIds = labs.map(item => String(item.labId));
    const selectedLabId = availableIds.includes(String(preferredLabId))
        ? String(preferredLabId)
        : availableIds[0];

    selectEl.innerHTML = labs.map(item => {
        const labId = String(item.labId);
        const baseLabel = item.name || item.label || `Lab #${labId}`;
        const suffix = item.operatorReviewOnly ? ' (operator review)' : '';
        const label = `${baseLabel}${suffix}`;
        return `<option value="${escapeHtml(labId)}">${escapeHtml(label)}</option>`;
    }).join('');

    selectEl.value = selectedLabId;
    updateCollectDetailVisibility();
    return selectedLabId;
}

function updateCollectButtonState() {
    const collectBtn = document.getElementById('collectLabBtn');
    if (!collectBtn) return;

    if (DashboardState.collectSubmitting) {
        collectBtn.disabled = true;
        collectBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Requesting payout...';
        return;
    }

    let buttonLabel = 'Request Payout';
    const pendingClosuresEl = document.getElementById('collectPendingClosures');
    const pendingTotalEl = document.getElementById('collectPendingTotal');

    try {
        const pendingClosures = BigInt(pendingClosuresEl?.textContent?.trim() || '0');
        const pendingTotalText = (pendingTotalEl?.textContent || '0').replace(/\s*credits\s*$/i, '').trim();
        const pendingTotal = BigInt(decimalToRawUnits(pendingTotalText || '0', CREDIT_DECIMALS));

        if (pendingClosures > 0n && pendingTotal > 0n) {
            buttonLabel = 'Close Reservations & Queue Payout';
        } else if (pendingClosures > 0n) {
            buttonLabel = 'Close Reservations';
        }
    } catch (error) {
        buttonLabel = 'Request Payout';
    }

    collectBtn.innerHTML = `<i class="fas fa-coins"></i> ${buttonLabel}`;
    collectBtn.disabled =
        DashboardState.collectLoadingStatus ||
        !DashboardState.collectCanExecute ||
        !DashboardState.selectedCollectLabId;
}

function getSelectedCollectLab() {
    if (!DashboardState.selectedCollectLabId || !Array.isArray(DashboardState.collectLabs)) {
        return null;
    }
    return DashboardState.collectLabs.find(
        item => String(item.labId) === String(DashboardState.selectedCollectLabId)
    ) || null;
}

async function loadCollectLabs() {
    const selectEl = document.getElementById('collectLabSelect');
    const pendingEl = document.getElementById('collectPendingTotal');
    if (!selectEl || !pendingEl) {
        return;
    }
    loadCollectLabNameCache();
    clearCollectLabsRetryTimer();
    const previousLabs = Array.isArray(DashboardState.collectLabs)
        ? DashboardState.collectLabs.slice()
        : [];
    const previousSelection = DashboardState.selectedCollectLabId;

    DashboardState.collectLoadingStatus = true;
    DashboardState.collectCanExecute = false;
    DashboardState.selectedCollectLabId = null;
    updateCollectDetailVisibility();
    updateCollectButtonState();
    setCollectStatusText('Loading labs...');
    setCollectPanelCompact(false);
    pendingEl.textContent = '--';
    setCollectPendingClosuresText('--');
    selectEl.disabled = true;
    selectEl.innerHTML = '<option value="">Loading labs...</option>';

    try {
        const data = await API.getProviderLabs();
        const labs = enrichCollectLabsWithCachedNames(Array.isArray(data.labs) ? data.labs : []);

        if (Number.isFinite(Number(data.maxBatch)) && Number(data.maxBatch) > 0) {
            DashboardState.collectMaxBatch = Math.max(1, Math.min(100, Number(data.maxBatch)));
        }

        if (!data.success) {
            throw new Error(data.error || 'Failed to load provider labs');
        }

        if (!labs.length) {
            if (previousLabs.length) {
                DashboardState.collectLabs = previousLabs;
                DashboardState.selectedCollectLabId = renderCollectLabOptions(
                    selectEl,
                    previousLabs,
                    previousSelection
                );
                selectEl.disabled = false;
                setCollectPanelCompact(false);
                await loadCollectStatusForSelectedLab();
                return;
            }

            const retryScheduled = shouldRetryEmptyCollectLabs()
                ? scheduleNextCollectLabsRetry('Waiting for labs...')
                : false;

            DashboardState.collectLabs = [];
            DashboardState.selectedCollectLabId = null;
            selectEl.innerHTML = retryScheduled
                ? '<option value="">Checking labs...</option>'
                : '<option value="">No labs available</option>';
            pendingEl.textContent = '0 credits';
            setCollectPendingClosuresText('0');
            if (!retryScheduled) {
                setCollectStatusText('Not available', 'warning');
            }
            setCollectPanelCompact(true);
            updateCollectDetailVisibility();
            if (!retryScheduled) {
                resetCollectLabsRetryState();
            }
            return;
        }

        resetCollectLabsRetryState();
        DashboardState.collectLabs = labs;
        DashboardState.selectedCollectLabId = renderCollectLabOptions(
            selectEl,
            labs,
            previousSelection
        );
        selectEl.disabled = false;
        setCollectPanelCompact(false);
        updateCollectDetailVisibility();

        await loadCollectStatusForSelectedLab();
    } catch (error) {
        const retryScheduled = scheduleCollectLabsRetry(error);
        if (previousLabs.length) {
            DashboardState.collectLabs = previousLabs;
            DashboardState.selectedCollectLabId = renderCollectLabOptions(
                selectEl,
                previousLabs,
                previousSelection
            );
            selectEl.disabled = false;
            setCollectPanelCompact(false);
            await loadCollectStatusForSelectedLab();
            if (!retryScheduled) {
                setCollectStatusText('Using last known labs', 'warning');
            }
            return;
        }

        DashboardState.collectLabs = [];
        DashboardState.selectedCollectLabId = null;
        DashboardState.collectCanExecute = false;
        selectEl.innerHTML = '<option value="">Failed to load labs</option>';
        pendingEl.textContent = '--';
        setCollectPendingClosuresText('--');
        setCollectStatusText('Unavailable', 'error');
        setCollectPanelCompact(true);
        updateCollectDetailVisibility();
        if (!retryScheduled) {
            resetCollectLabsRetryState();
        }
    } finally {
        DashboardState.collectLoadingStatus = false;
        updateCollectButtonState();
    }
}

async function loadCollectStatusForSelectedLab() {
    const selectEl = document.getElementById('collectLabSelect');
    const pendingEl = document.getElementById('collectPendingTotal');
    if (!selectEl || !pendingEl) {
        return;
    }

    const selectedLabId = selectEl.value || DashboardState.selectedCollectLabId;
    DashboardState.selectedCollectLabId = selectedLabId || null;
    updateCollectDetailVisibility();
    if (!selectedLabId) {
        DashboardState.collectCanExecute = false;
        pendingEl.textContent = '0 credits';
        setCollectPendingClosuresText('0');
        setCollectStatusText('Select a lab', 'warning');
        setCollectLifecycleSummaryText('');
        updateCollectButtonState();
        return;
    }

    DashboardState.collectLoadingStatus = true;
    DashboardState.collectCanExecute = false;
    updateCollectDetailVisibility();
    pendingEl.textContent = '--';
    setCollectPendingClosuresText('--');
    setCollectStatusText('Checking...');
    setCollectLifecycleSummaryText('');
    updateCollectButtonState();

    try {
        const data = await API.getProviderReceivableStatus(selectedLabId, DashboardState.collectMaxBatch);
        if (!data.success) {
            throw new Error(data.error || 'Failed to load provider receivable status');
        }

        const selectedLab = getSelectedCollectLab();
        const payoutEnabledForSelectedLab = data.providerPayoutEnabled === true
            || selectedLab?.providerPayoutEnabled === true
            || selectedLab?.ownedByInstitutionalProvider === true;
        const operatorReviewOnly = data.operatorReviewOnly === true
            || selectedLab?.operatorReviewOnly === true;

        const totalLab = data.totalReceivableLab || formatLabTokenRaw(data.totalReceivableRaw);
        pendingEl.textContent = `${totalLab} credits`;
        const pendingClosuresRaw = data.eligibleReservationCount ?? '0';
        const pendingClosures = formatPendingClosures(pendingClosuresRaw);
        setCollectPendingClosuresText(pendingClosures);
        setCollectLifecycleSummaryText(buildCollectLifecycleSummary(data));

        let hasPendingClosures = false;
        let hasPendingPayout = false;
        try {
            hasPendingClosures = BigInt(pendingClosuresRaw.toString()) > 0n;
            hasPendingPayout = BigInt((data.totalReceivableRaw ?? '0').toString()) > 0n;
        } catch (error) {
            hasPendingClosures = false;
            hasPendingPayout = false;
        }

        DashboardState.collectCanExecute = DashboardState.isProvider
            && payoutEnabledForSelectedLab
            && data.canRequestPayout === true;
        updateCollectDetailVisibility();

        if (DashboardState.collectCanExecute) {
            if (hasPendingClosures && hasPendingPayout) {
                setCollectStatusText('Ready for clouse & payout', 'success');
            } else if (hasPendingClosures) {
                setCollectStatusText('Ready for closure', 'success');
            } else {
                setCollectStatusText('Ready for payout request', 'success');
            }
        } else if (DashboardState.isProvider && !payoutEnabledForSelectedLab) {
            setCollectStatusText('Payout requests are limited to this provider wallet\'s labs', 'warning');
        } else if (!DashboardState.isProvider && DashboardState.isOperator && operatorReviewOnly) {
            setCollectStatusText('Operator review only', 'info');
        } else if (!DashboardState.isProvider && DashboardState.isOperator && data.canRequestPayout === true) {
            setCollectStatusText('Payout available for owning provider', 'info');
        } else if (data.payoutRequestReason) {
            setCollectStatusText(data.payoutRequestReason, 'warning');
        } else {
            setCollectStatusText('No payout currently available', 'warning');
        }

    } catch (error) {
        DashboardState.collectCanExecute = false;
        pendingEl.textContent = '--';
        setCollectPendingClosuresText('--');
        setCollectStatusText('Status unavailable', 'error');
        setCollectLifecycleSummaryText('');
        updateCollectDetailVisibility();
    } finally {
        DashboardState.collectLoadingStatus = false;
        updateCollectButtonState();
    }
}

async function handleCollectLabPayout() {
    const labId = DashboardState.selectedCollectLabId;
    const selectedLab = getSelectedCollectLab();
    if (!labId) {
        showToast('Select a lab first', 'error');
        return;
    }
    if (selectedLab && selectedLab.providerPayoutEnabled === false) {
        showToast('Payout requests are limited to labs associated with this provider wallet', 'error');
        return;
    }
    if (!DashboardState.collectCanExecute) {
        showToast('No requestable provider receivable for the selected lab', 'error');
        return;
    }

    const collectTarget = getCollectTargetLabel(selectedLab);
    const confirmed = await showConfirmModal(
        'Request Provider Payout',
        `Request provider payout for ${collectTarget}?`,
        {
            icon: 'coins',
            confirmText: 'Request payout',
            confirmButtonClass: 'btn-primary'
        }
    );
    if (!confirmed) {
        return;
    }

    DashboardState.collectSubmitting = true;
    updateCollectButtonState();

    try {
        const result = await API.requestProviderPayout(labId, DashboardState.collectMaxBatch);
        if (result.success) {
            showToast(`Payout transaction submitted for ${collectTarget}. Tx: ${formatAddress(result.transactionHash)}`, 'info');
            setCollectStatusText('Payout transaction submitted', 'info');
            DashboardState.collectCanExecute = false;
            updateCollectButtonState();

            try {
                const txStatus = await waitForAdminTransactionConfirmation(result.transactionHash);
                if (txStatus.status === 'success') {
                    showToast(`Payout completed for ${collectTarget}. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                    setCollectStatusText('Payout confirmed on-chain', 'success');
                } else {
                    showToast(`Payout transaction failed for ${collectTarget}. Tx: ${formatAddress(result.transactionHash)}`, 'error');
                    setCollectStatusText('Payout transaction failed', 'error');
                }
            } catch (confirmationError) {
                showToast(
                    `Payout transaction submitted for ${collectTarget}. Confirmation still pending. Tx: ${formatAddress(result.transactionHash)}`,
                    'info'
                );
                setCollectStatusText('Waiting for on-chain confirmation', 'info');
            } finally {
                await Promise.allSettled([
                    loadBalances(),
                    loadRecentTransactions(),
                    loadCollectStatusForSelectedLab()
                ]);
            }
        } else {
            showToast('Payout request failed: ' + (result.message || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast('Payout request failed: ' + error.message, 'error');
    } finally {
        DashboardState.collectSubmitting = false;
        updateCollectButtonState();
    }
}

async function handleProviderSettlementTransition(event) {
    event.preventDefault();

    const labId = DashboardState.selectedCollectLabId;
    if (!labId) {
        showToast('Select a lab first', 'error');
        return;
    }

    const transitionSelect = document.getElementById('providerSettlementTransitionSelect');
    const amountInput = document.getElementById('providerSettlementAmountInput');
    const referenceInput = document.getElementById('providerSettlementReferenceInput');
    const selectedPreset = getReceivableTransitionPreset(transitionSelect?.value);

    if (!selectedPreset) {
        showToast('Select a settlement transition', 'error');
        return;
    }

    let amountRaw;
    try {
        amountRaw = decimalToRawUnits(amountInput?.value ?? '', CREDIT_DECIMALS);
    } catch (error) {
        showToast(error.message, 'error');
        return;
    }

    if (amountRaw === '0') {
        showToast('Transition amount must be greater than zero', 'error');
        return;
    }

    const collectTarget = getCollectTargetLabel();
    const formattedAmount = amountInput?.value?.trim() || formatLabTokenRaw(amountRaw);
    const confirmed = await showConfirmModal(
        'Submit Settlement Transition',
        `Submit "${selectedPreset.label}" for ${collectTarget} with amount ${formattedAmount} credits?`,
        {
            icon: 'file-invoice-dollar',
            confirmText: 'Submit transition',
            confirmButtonClass: 'btn-secondary'
        }
    );
    if (!confirmed) {
        return;
    }

    try {
        const result = await API.transitionProviderReceivableState(
            labId,
            selectedPreset.from,
            selectedPreset.to,
            amountRaw,
            referenceInput?.value?.trim() || ''
        );

        if (result.success) {
            showToast(`Settlement transition submitted. Tx: ${formatAddress(result.transactionHash)}`, 'success');
            if (event.target && typeof event.target.reset === 'function') {
                event.target.reset();
            }
            setTimeout(() => {
                loadRecentTransactions();
                loadCollectStatusForSelectedLab();
            }, 5000);
        } else {
            showToast('Settlement transition failed: ' + (result.message || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast('Settlement transition failed: ' + error.message, 'error');
    }
}

// Load billing administration data
async function loadBillingAdminData() {
    try {
        const data = await API.getBillingInfo();
        
        if (data.success) {
            // Check if wallet is configured
            if (data.walletConfigured === false) {
                // Wallet NOT configured - show "--" or "Not configured"
                document.getElementById('currentUserLimit').textContent = '--';
                document.getElementById('currentPeriod').textContent = '--';
                document.getElementById('periodStartDateTop').textContent = '--';
                document.getElementById('periodEndDateTop').textContent = '--';
                return;
            }
            
            // Wallet IS configured - show values (either from contract or defaults)
            // Update current user limit
            const limitTokens = formatLabTokenRaw(data.userLimit);
            document.getElementById('currentUserLimit').textContent = `${limitTokens} credits`;
            
            // Update current period
            const periodDays = Math.floor(data.periodDuration / 86400);
            document.getElementById('currentPeriod').textContent = `${periodDays} days`;
            
            // Update top ongoing period box
            const startDate = new Date(data.periodStart * 1000);
            const endDate = new Date(data.periodEnd * 1000);
            document.getElementById('periodStartDateTop').textContent = startDate.toLocaleDateString();
            document.getElementById('periodEndDateTop').textContent = endDate.toLocaleDateString();
        }
    } catch (error) {
        console.error('Failed to load billing data:', error);
        
        // On error, show "--" (likely wallet not configured)
        document.getElementById('currentUserLimit').textContent = '--';
        document.getElementById('currentPeriod').textContent = '--';
        document.getElementById('periodStartDateTop').textContent = '--';
        document.getElementById('periodEndDateTop').textContent = '--';
    }
}

// Load recent transactions
async function loadRecentTransactions(limit = DashboardState.transactionsLimit) {
    try {
        DashboardState.transactionsLimit = limit;
        const data = await API.getRecentTransactions(limit);
        const container = document.getElementById('transactionsContainer');
        const loadMoreWrap = document.getElementById('transactionsLoadMoreWrap');
        const loadMoreBtn = document.getElementById('transactionsLoadMoreBtn');
        
        if (data.success && data.transactions && data.transactions.length > 0) {
            container.innerHTML = data.transactions.map(tx => `
                <div class="transaction-item">
                    <div class="tx-row">
                        <div class="tx-type">${tx.type || 'Tx'}</div>
                        <div class="tx-hash">${formatAddress(tx.hash)}</div>
                    </div>
                    <div class="tx-description">${tx.description || ''}</div>
                    <div class="tx-meta">
                        <span>${tx.amountTokens || '--'}</span>
                        <span>${formatTimestamp(tx.timestamp)}</span>
                        <span class="tx-status">${tx.status || 'submitted'}</span>
                    </div>
                </div>
            `).join('');
            if (loadMoreWrap) {
                loadMoreWrap.classList.toggle('hidden', data.hasMore !== true);
            }
            if (loadMoreBtn) {
                loadMoreBtn.disabled = false;
            }
        } else {
            container.innerHTML = `
                <div class="no-data">
                    <span class="icon">?</span>
                    <p>No transactions recorded yet</p>
                    <small>${data.note || 'Execute an admin operation or institutional reservation to populate this list.'}</small>
                </div>
            `;
            if (loadMoreWrap) {
                loadMoreWrap.classList.add('hidden');
            }
        }
    } catch (error) {
        console.error('Failed to load transactions:', error);
    }
}

// Refresh all data
async function refreshAllData() {
    console.log('Refreshing dashboard data...');
    await loadSystemStatus();
    await Promise.all([
        loadBalances(),
        loadCollectLabs(),
        loadBillingAdminData(),
        loadRecentTransactions()
    ]);
    showToast('Dashboard refreshed successfully', 'success');
}

// Show top spenders modal
async function showTopSpendersModal() {
    const modal = document.getElementById('topSpendersModal');
    const container = document.getElementById('topSpendersContainer');
    
    // Show modal
    modal.classList.add('show');
    
    // Show loading
    container.innerHTML = `
        <div class="loading-spinner">
            <i class="fas fa-spinner fa-spin"></i> Loading spenders data...
        </div>
    `;
    
    try {
        const data = await API.getTopSpenders(10);
        
        if (data.success && data.spenders && data.spenders.length > 0) {
            container.innerHTML = `
                <table class="spenders-table">
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>User (PUC)</th>
                            <th>Spent (current period)</th>
                            <th>Remaining</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.spenders.map((spender, index) => {
                            const rank = index + 1;
                            const rankClass = rank === 1 ? 'gold' : rank === 2 ? 'silver' : rank === 3 ? 'bronze' : 'normal';
                            
                            return `
                                <tr>
                                    <td>
                                        <span class="rank-badge ${rankClass}">${rank}</span>
                                    </td>
                                    <td class="puc-cell">${spender.puc}</td>
                                    <td class="spent-amount">${spender.amountLab || '0'} LAB</td>
                                    <td class="spent-amount">${spender.remainingLab || '--'} LAB</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            `;
        } else {
            container.innerHTML = `
                <div class="no-data-modal">
                    <i class="fas fa-inbox"></i>
                    <p>${data.note || 'No spending data available for the current period'}</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Failed to load top spenders:', error);
        container.innerHTML = `
            <div class="no-data-modal">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Failed to load spenders data</p>
                <small>${error.message}</small>
            </div>
        `;
    }
}

// Close top spenders modal
function closeTopSpendersModal() {
    const modal = document.getElementById('topSpendersModal');
    modal.classList.remove('show');
}

// Handle form submissions
function setupFormHandlers() {
    // Set user limit form
    document.getElementById('limitsForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const limitTokens = document.getElementById('userLimitInput').value.trim();
        
        if (!limitTokens || isNaN(limitTokens)) {
            showToast('Please enter a valid limit in service credits', 'error');
            return;
        }
        
        let limitRaw;
        try {
            limitRaw = decimalToRawUnits(limitTokens, CREDIT_DECIMALS);
        } catch (error) {
            showToast(error.message, 'error');
            return;
        }
        
        try {
            const result = await API.setUserLimit(limitRaw);
            if (result.success) {
                showToast(`Limit updated successfully. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('userLimitInput').value = '';
                setTimeout(() => loadBillingAdminData(), 5000); // Reload after 5 seconds
            } else {
                showToast('Failed to update limit: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error updating limit: ' + error.message, 'error');
        }
    });
    
    // Set spending period form
    document.getElementById('periodForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const periodDays = document.getElementById('periodInput').value.trim();
        
        if (!periodDays || isNaN(periodDays)) {
            showToast('Please enter a valid period in days', 'error');
            return;
        }
        
        // Convert days to seconds
        const periodSeconds = (parseFloat(periodDays) * 86400).toString();
        
        try {
            const result = await API.setSpendingPeriod(periodSeconds);
            if (result.success) {
                showToast(`Period updated successfully. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('periodInput').value = '';
                setTimeout(() => loadBillingAdminData(), 5000);
            } else {
                showToast('Failed to update period: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error updating period: ' + error.message, 'error');
        }
    });

    const issueServiceCreditsForm = document.getElementById('issueServiceCreditsForm');
    if (issueServiceCreditsForm) {
        issueServiceCreditsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const creditAccount = document.getElementById('issueCreditAccountInput').value.trim();
            const amountInput = document.getElementById('issueCreditAmountInput').value.trim();
            const reference = document.getElementById('issueCreditReferenceInput').value.trim();

            if (!creditAccount) {
                showToast('Customer account is required', 'error');
                return;
            }

            let amountRaw;
            try {
                amountRaw = decimalToRawUnits(amountInput, CREDIT_DECIMALS);
            } catch (error) {
                showToast(error.message, 'error');
                return;
            }

            if (amountRaw === '0') {
                showToast('Issued amount must be greater than zero', 'error');
                return;
            }

            try {
                const result = await API.issueServiceCredits(creditAccount, amountRaw, reference);
                if (result.success) {
                    showToast(`Service credits issued. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                    issueServiceCreditsForm.reset();
                    setTimeout(() => {
                        loadBalances();
                        loadBillingAdminData();
                    }, 5000);
                } else {
                    showToast('Issuance failed: ' + result.message, 'error');
                }
            } catch (error) {
                showToast('Error issuing credits: ' + error.message, 'error');
            }
        });
    }

    const adjustServiceCreditsForm = document.getElementById('adjustServiceCreditsForm');
    if (adjustServiceCreditsForm) {
        adjustServiceCreditsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const creditAccount = document.getElementById('adjustCreditAccountInput').value.trim();
            const deltaInput = document.getElementById('adjustCreditDeltaInput').value.trim();
            const reference = document.getElementById('adjustCreditReferenceInput').value.trim();

            if (!creditAccount) {
                showToast('Customer account is required', 'error');
                return;
            }

            let creditDelta;
            try {
                creditDelta = decimalToRawUnits(deltaInput, CREDIT_DECIMALS);
            } catch (error) {
                showToast(error.message, 'error');
                return;
            }

            if (creditDelta === '0') {
                showToast('Adjustment delta must not be zero', 'error');
                return;
            }

            try {
                const result = await API.adjustServiceCredits(creditAccount, creditDelta, reference);
                if (result.success) {
                    showToast(`Service credit adjustment submitted. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                    adjustServiceCreditsForm.reset();
                    setTimeout(() => {
                        loadBalances();
                        loadBillingAdminData();
                    }, 5000);
                } else {
                    showToast('Adjustment failed: ' + result.message, 'error');
                }
            } catch (error) {
                showToast('Error adjusting credits: ' + error.message, 'error');
            }
        });
    }

    const providerSettlementTransitionForm = document.getElementById('providerSettlementTransitionForm');
    if (providerSettlementTransitionForm) {
        providerSettlementTransitionForm.addEventListener('submit', handleProviderSettlementTransition);
    }
}

// Setup button handlers
function setupButtonHandlers() {
    // Welcome modal continue button
    const continueBtn = document.getElementById('continueBtn');
    if (continueBtn) {
        continueBtn.addEventListener('click', () => {
            hideWelcomeModal(true);
            showProvisioningTokenModal();
        });
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshAllData);
    }
    
    // Refresh balance button (optional - may not exist)
    const refreshBalanceBtn = document.getElementById('refreshBalanceBtn');
    if (refreshBalanceBtn) {
        refreshBalanceBtn.addEventListener('click', loadBalances);
    }

    // Apply Invite Token button in header
    const applyProvisioningTokenHeaderBtn = document.getElementById('applyProvisioningTokenHeaderBtn');
    if (applyProvisioningTokenHeaderBtn) {
        applyProvisioningTokenHeaderBtn.addEventListener('click', showProvisioningTokenModal);
    }
    
    // Apply Invite Token button in modal
    const applyProvisioningBtn = document.getElementById('applyProvisioningBtn');
    if (applyProvisioningBtn) {
        applyProvisioningBtn.addEventListener('click', applyProvisioningToken);
    }
    
    // Cancel/Close Invite Modal buttons
    const closeProvisioningModalBtn = document.getElementById('closeProvisioningModalBtn');
    const cancelProvisioningBtn = document.getElementById('cancelProvisioningBtn');
    if (closeProvisioningModalBtn) {
        closeProvisioningModalBtn.addEventListener('click', hideProvisioningTokenModal);
    }
    if (cancelProvisioningBtn) {
        cancelProvisioningBtn.addEventListener('click', hideProvisioningTokenModal);
    }
    
    // Network buttons
    const sepoliaBtn = document.getElementById('sepoliaBtn');
    const mainnetBtn = document.getElementById('mainnetBtn');
    if (sepoliaBtn) {
        sepoliaBtn.addEventListener('click', () => {
            if (!sepoliaBtn.classList.contains('active')) {
                switchNetwork('sepolia');
            }
        });
    }
    if (mainnetBtn) {
        mainnetBtn.addEventListener('click', () => {
            if (!mainnetBtn.classList.contains('active')) {
                switchNetwork('mainnet');
            }
        });
    }
    
    // Refresh transactions button
    const refreshTxBtn = document.getElementById('refreshTxBtn');
    if (refreshTxBtn) {
        refreshTxBtn.addEventListener('click', loadRecentTransactions);
    }

    const transactionsLoadMoreBtn = document.getElementById('transactionsLoadMoreBtn');
    if (transactionsLoadMoreBtn) {
        transactionsLoadMoreBtn.addEventListener('click', async () => {
            transactionsLoadMoreBtn.disabled = true;
            await loadRecentTransactions(Math.min(DashboardState.transactionsLimit + 10, 50));
        });
    }

    const collectLabSelect = document.getElementById('collectLabSelect');
    if (collectLabSelect) {
        collectLabSelect.addEventListener('change', async (event) => {
            DashboardState.selectedCollectLabId = event.target.value || null;
            await loadCollectStatusForSelectedLab();
        });
    }

    const collectLabBtn = document.getElementById('collectLabBtn');
    if (collectLabBtn) {
        collectLabBtn.addEventListener('click', handleCollectLabPayout);
    }

    const revealPrivateKeyBtn = document.getElementById('revealPrivateKeyBtn');
    if (revealPrivateKeyBtn) {
        revealPrivateKeyBtn.addEventListener('click', handleRevealPrivateKey);
    }

    // Reset period button
    const resetPeriodBtn = document.getElementById('resetPeriodBtn');
    if (resetPeriodBtn) {
        resetPeriodBtn.addEventListener('click', async () => {
        if (!confirm('⚠️ Reset spending period? All users\' spending will be reset to zero and a new period will begin immediately.')) {
            return;
        }
        
        try {
            showToast('Resetting spending period...', 'info');
            const result = await API.resetSpendingPeriod();
            if (result.success) {
                showToast(`Period reset successful. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                setTimeout(() => loadBillingAdminData(), 5000);
            } else {
                showToast('Failed to reset period: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error resetting period: ' + error.message, 'error');
        }
        });
    }
    
    // Show top spenders button
    const showTopSpendersBtn = document.getElementById('showTopSpendersBtn');
    if (showTopSpendersBtn) {
        showTopSpendersBtn.addEventListener('click', showTopSpendersModal);
    }
    
    // Close modal button
    const closeTopSpendersModalBtn = document.getElementById('closeTopSpendersModal');
    if (closeTopSpendersModalBtn) {
        closeTopSpendersModalBtn.addEventListener('click', closeTopSpendersModal);
    }
    
    // Close modal on click outside
    const topSpendersModal = document.getElementById('topSpendersModal');
    if (topSpendersModal) {
        topSpendersModal.addEventListener('click', (e) => {
            if (e.target.id === 'topSpendersModal') {
                closeTopSpendersModal();
            }
        });
    }
    
    // Wallet setup buttons
    const createWalletBtn = document.getElementById('createWalletBtn');
    const importWalletBtn = document.getElementById('importWalletBtn');
    
    if (createWalletBtn) {
        createWalletBtn.addEventListener('click', async () => {
            // Close dropdown
            const dropdown = document.getElementById('walletSetupDropdown');
            if (dropdown) dropdown.style.display = 'none';
            
            const password = await showInputModal(
                'Create Wallet Password',
                'Enter a secure password for the new wallet (minimum 8 characters):',
                'password'
            );
            
            if (!password || password.length < 8) {
                showToast('Password must be at least 8 characters', 'error');
                return;
            }
            
            const confirmPassword = await showInputModal(
                'Confirm Password',
                'Re-enter your password to confirm:',
                'password'
            );
            
            if (password !== confirmPassword) {
                showToast('Passwords do not match', 'error');
                return;
            }
            
            try {
                showToast('Creating wallet...', 'info');
                const response = await fetch('/wallet/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                
                const result = await readJsonResponse(response);
                if (result.parseError || !result.data) {
                    throw new Error(extractResponseErrorMessage(response, result, 'Invalid response from server.'));
                }
                const data = result.data;
                if (!response.ok) {
                    throw new Error(extractResponseErrorMessage(response, result, 'Failed to create wallet.'));
                }
                if (data.success && data.address) {
                    showToast('✓ Wallet created and configured successfully!', 'success');
                    
                    // Format success message with HTML
                    const content = `
                        <div class="info-line">
                            <span class="info-label">Status:</span>
                            <span class="info-value">Wallet Created Successfully</span>
                        </div>
                        <div class="secret-header">
                            <span class="info-label">Wallet Address</span>
                            <button class="btn btn-secondary btn-small" onclick="copyToClipboard('${data.address}')">
                                <i class="fas fa-copy"></i>
                                Copy
                            </button>
                        </div>
                        <code class="secret-value">${data.address}</code>
                        <div class="warning-text" style="margin-top: var(--spacing-md)">
                            <i class="fas fa-exclamation-triangle"></i>
                            <strong>Important:</strong> Make sure to backup your wallet securely. 
                            The dashboard will now refresh to show your new wallet.
                        </div>
                    `;

                    const secretSection = data.privateKey
                        ? buildPrivateKeyContent(
                            data.privateKey,
                            null, // Don't show address again, already shown above
                            'Copy and store this private key in a secure manager. You will not be able to view it again unless you reveal it with the password.'
                          )
                        : '';
                    
                    await showInfoModal('Institutional Wallet Created', content + secretSection, true);
                    
                    DashboardState.walletAddress = data.address;
                    DashboardState.inviteTokenApplied = false;
                    DashboardState.invitePromptedWallet = null;
                    persistInviteTokenState(data.address, false, DashboardState.contractAddress);
                    
                    // Refresh dashboard to show new wallet
                    await refreshAllData();
                } else {
                    showToast('Failed to create wallet: ' + (data.error || data.message || 'Unknown error'), 'error');
                }
            } catch (error) {
                showToast('Error creating wallet: ' + error.message, 'error');
            }
        });
    }
    
    if (importWalletBtn) {
        importWalletBtn.addEventListener('click', async () => {
            // Close dropdown
            const dropdown = document.getElementById('walletSetupDropdown');
            if (dropdown) dropdown.style.display = 'none';
            
            const privateKeyInput = await showInputModal(
                'Import Wallet',
                'Enter the wallet private key (64 hex chars, with or without 0x):',
                'text'
            );

            if (!privateKeyInput) {
                showToast('Private key is required to import a wallet', 'error');
                return;
            }

            const trimmedKey = privateKeyInput.trim();
            const normalizedKey = trimmedKey.startsWith('0x') ? trimmedKey : `0x${trimmedKey}`;
            const privateKeyPattern = /^0x[0-9a-fA-F]{64}$/;
            if (!privateKeyPattern.test(normalizedKey)) {
                showToast('Invalid private key format. Expected 0x followed by 64 hex characters.', 'error');
                return;
            }
            
            const password = await showInputModal(
                'Wallet Password',
                'Enter password to encrypt the imported wallet (minimum 8 characters):',
                'password'
            );
            
            if (!password || password.length < 8) {
                showToast('Password must be at least 8 characters', 'error');
                return;
            }
            
            try {
                showToast('Importing wallet...', 'info');
                const response = await fetch('/wallet/import', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ privateKey: normalizedKey, password })
                });
                
                const result = await readJsonResponse(response);
                if (result.parseError || !result.data) {
                    throw new Error(extractResponseErrorMessage(response, result, 'Invalid response from server.'));
                }
                const data = result.data;
                if (!response.ok) {
                    throw new Error(extractResponseErrorMessage(response, result, 'Failed to import wallet.'));
                }
                if (data.success && data.address) {
                    showToast('Wallet imported and configured successfully!', 'success');
                    
                    // Format success message with HTML
                    const content = `
                        <div class="info-line">
                            <span class="info-label">Status:</span>
                            <span class="info-value">Wallet Imported Successfully</span>
                        </div>
                        <div class="info-line">
                            <span class="info-label">Address:</span>
                            <span class="info-value">${data.address}</span>
                        </div>
                        <div class="warning-text">
                            <i class="fas fa-check-circle"></i>
                            The wallet has been automatically configured and saved. 
                            The dashboard will now refresh to show your imported wallet.
                        </div>
                    `;
                    
                    await showInfoModal('Institutional Wallet Imported', content, true);
                    
                    DashboardState.walletAddress = data.address;
                    DashboardState.inviteTokenApplied = false;
                    DashboardState.invitePromptedWallet = null;
                    persistInviteTokenState(data.address, false, DashboardState.contractAddress);
                    
                    // Refresh dashboard to show imported wallet
                    await refreshAllData();
                } else {
                    showToast('Failed to import wallet: ' + (data.error || data.message || 'Unknown error'), 'error');
                }
            } catch (error) {
                showToast('Error importing wallet: ' + error.message, 'error');
            }
        });
    }
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (event) => {
        const dropdown = document.getElementById('walletSetupDropdown');
        const trigger = document.getElementById('walletSetupTrigger');
        
        if (dropdown && trigger && 
            !dropdown.contains(event.target) && 
            !trigger.contains(event.target)) {
            dropdown.style.display = 'none';
        }
    });
}

// Setup auto-refresh
function setupAutoRefresh() {
    if (DashboardState.autoRefreshEnabled) {
        DashboardState.autoRefreshInterval = setInterval(() => {
            console.log('Auto-refresh triggered');
            refreshAllData();
        }, DashboardState.refreshIntervalMs);
    }
}

// Stop auto-refresh (cleanup)
function stopAutoRefresh() {
    if (DashboardState.autoRefreshInterval) {
        clearInterval(DashboardState.autoRefreshInterval);
        DashboardState.autoRefreshInterval = null;
    }
    clearCollectLabsRetryTimer();
}

// Initialize dashboard
async function initDashboard() {
    console.log('Initializing operations dashboard...');
    
    // Setup event handlers
    setupFormHandlers();
    setupButtonHandlers();
    
    // Load initial data
    await refreshAllData();
    
    // Setup auto-refresh
    setupAutoRefresh();
    
    console.log('Dashboard initialized successfully');
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});

// Start the dashboard when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDashboard);
} else {
    initDashboard();
}

