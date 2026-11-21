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
    institutionRegistered: false,
    marketplaceUrl: 'https://www.decentralabs-marketplace.app/',
    collectLabs: [],
    collectLabNames: {},
    selectedCollectLabId: null,
    collectCanExecute: false,
    collectLoadingStatus: false,
    collectSubmitting: false,
    collectMaxBatch: 50,
    collectPageSize: 20,
    collectOffset: 0,
    collectHasMore: false,
    collectTotalLabs: 0,
    collectLabsRetryTimeout: null,
    collectLabsRetryAttempts: 0,
    collectAggregates: null,
    settlementLatestBatchId: null,
    settlementInvoices: [],
    providerIncomeReport: null,
    providerIncomeReportError: null,
    providerGatewayDepartments: [],
    providerGatewayDepartmentsError: null,
    transactionsLimit: 10,
    operatingMode: 'unknown',
    providerRegistrationEnabled: false,
    registrationRole: null
};

const COLLECT_LABS_RETRY_DELAYS_MS = [1500, 3500, 7000];

function updateRoleBasedSections() {
    const hasWallet = Boolean(DashboardState.walletAddress);
    const showInstitutionControls = hasWallet && DashboardState.isInstitution;
    const providerModeEnabled = DashboardState.operatingMode === 'provider-consumer';
    const showProviderControls = hasWallet && providerModeEnabled && DashboardState.isProvider;
    const showOperatorControls = hasWallet && DashboardState.isOperator;
    const showProviderOperatorControls = providerModeEnabled && showOperatorControls;

    const providerIncomeSection = document.getElementById('providerIncomeReportCard');
    const settlementSection = document.getElementById('settlementOperationsSection');
    const gatewayDepartmentsSection = document.getElementById('providerGatewayDepartmentsSection');
    const settlementTitle = document.getElementById('settlementOperationsTitle');
    const providerSettlementControls = document.getElementById('providerSettlementControls');
    const providerPayoutActions = document.getElementById('providerPayoutActions');
    const providerSettlementTransitionForm = document.getElementById('providerSettlementTransitionForm');
    const operatorCreditPolicySection = document.getElementById('operatorCreditPolicySection');
    const accessPoliciesSection = document.getElementById('accessPoliciesSection');
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
    const providerSettlementOperationSelect = document.getElementById('providerSettlementOperationSelect');

    if (providerIncomeSection) {
        providerIncomeSection.classList.toggle('hidden', !showProviderControls && !showProviderOperatorControls);
    }
    if (settlementSection) {
        settlementSection.classList.toggle('hidden', !showProviderControls && !showProviderOperatorControls);
    }
    if (gatewayDepartmentsSection) {
        gatewayDepartmentsSection.classList.toggle('hidden', !showProviderOperatorControls);
    }
    if (providerSettlementControls) {
        providerSettlementControls.classList.toggle('hidden', !showProviderControls && !showProviderOperatorControls);
    }
    if (providerPayoutActions) {
        providerPayoutActions.classList.toggle(
            'hidden',
            !showProviderControls || !(Array.isArray(DashboardState.collectLabs) && DashboardState.collectLabs.length > 0 && DashboardState.selectedCollectLabId)
        );
    }
    if (providerSettlementTransitionForm) {
        providerSettlementTransitionForm.classList.toggle('hidden', !showProviderControls && !showProviderOperatorControls);
    }
    if (providerSettlementOperationSelect) {
        [...providerSettlementOperationSelect.options].forEach((option) => {
            option.disabled = option.value === 'submit'
                ? !showProviderControls
                : !showProviderOperatorControls;
        });
        if (!showProviderOperatorControls && providerSettlementOperationSelect.value !== 'submit') {
            providerSettlementOperationSelect.value = 'submit';
        }
        WalletDashboardProviderSettlement.updateProviderSettlementOperationFields();
    }
    if (operatorCreditPolicySection) {
        operatorCreditPolicySection.classList.toggle('hidden', !showInstitutionControls && !showOperatorControls);
    }
    if (accessPoliciesSection) {
        accessPoliciesSection.classList.toggle('hidden', !showInstitutionControls && !showOperatorControls);
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
        collectLifecycleSummary.classList.toggle('hidden', !showProviderControls && !showProviderOperatorControls);
    }

    if (settlementTitle) {
        if (showProviderControls && showProviderOperatorControls) {
            settlementTitle.textContent = 'Provider Settlement and Operator Review';
        } else if (showProviderOperatorControls) {
            settlementTitle.textContent = 'Operator Settlement Review';
        } else if (showProviderControls) {
            settlementTitle.textContent = 'Provider Settlement';
        } else {
            settlementTitle.textContent = 'Settlement Operations';
        }
    }

    if (creditPolicyTitle) {
        if (showInstitutionControls && showOperatorControls) {
            creditPolicyTitle.textContent = 'Spending Policy and Operator Controls';
        } else if (showInstitutionControls) {
            creditPolicyTitle.textContent = 'Spending Policy';
        } else if (showOperatorControls) {
            creditPolicyTitle.textContent = 'Operator Controls';
        } else {
            creditPolicyTitle.textContent = 'Administration';
        }
    }

    if (collectLabSelectLabel) {
        if (showProviderControls && !showProviderOperatorControls) {
            collectLabSelectLabel.textContent = 'Select one of your labs';
        } else if (showProviderOperatorControls) {
            collectLabSelectLabel.textContent = 'Select lab for settlement review';
        } else {
            collectLabSelectLabel.textContent = 'Select lab';
        }
    }

    if (collectLifecycleSummary && !collectLifecycleSummary.textContent.trim()) {
        collectLifecycleSummary.classList.add('hidden');
    }

    window.WalletDashboardTabs?.setRoleVisibility({
        isInstitution: showInstitutionControls,
        isProvider: showProviderControls,
        isOperator: showOperatorControls,
        operatingMode: DashboardState.operatingMode
    });
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
        actionsEl.classList.toggle(
            'hidden',
            DashboardState.operatingMode !== 'provider-consumer' || !DashboardState.isProvider || !showDetails
        );
    }
}

// Utility: Format wei to ETH
// show up to 12 decimal places in the dashboard (was 14 previously)
// this affects all ETH-formatting but the original request only
// targeted the "ETH Balance" display.
const MAX_ETH_DECIMALS = 12;
const CREDIT_DECIMALS = 7;
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

function formatOptionalDateFromSeconds(seconds) {
    const numeric = Number(seconds);
    if (!Number.isFinite(numeric) || numeric <= 0) {
        return '--';
    }
    return new Date(numeric * 1000).toLocaleDateString();
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

function formatSettlementEurFromCreditRaw(rawValue) {
    try {
        const value = BigInt(rawValue?.toString() || '0');
        const scale = 10n ** 8n; // 7 credit decimals at the canonical 10 credits/EUR rate
        const whole = value / scale;
        const fraction = value % scale;
        if (fraction === 0n) return whole.toString();
        return `${whole}.${fraction.toString().padStart(8, '0').replace(/0+$/, '')}`;
    } catch (error) {
        return '';
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

function setModalTitle(element, icon, title) {
    element.replaceChildren();
    const iconElement = document.createElement('i');
    iconElement.className = `fas fa-${icon}`;
    element.append(iconElement, document.createTextNode(` ${String(title ?? '')}`));
}

function renderSafeModalContent(contentElement, content) {
    if (content instanceof Node) {
        contentElement.replaceChildren(content);
        return;
    }

    const allowedTags = new Set(['BR', 'BUTTON', 'CODE', 'DIV', 'I', 'P', 'SPAN', 'STRONG']);
    const parsed = new DOMParser().parseFromString(String(content ?? ''), 'text/html');

    const copyNode = (node) => {
        if (node.nodeType === Node.TEXT_NODE) {
            return document.createTextNode(node.nodeValue || '');
        }
        if (node.nodeType !== Node.ELEMENT_NODE) {
            return null;
        }

        const tagName = node.tagName.toUpperCase();
        if (!allowedTags.has(tagName)) {
            return document.createTextNode(node.textContent || '');
        }

        const element = document.createElement(tagName.toLowerCase());
        if (node.hasAttribute('class')) {
            element.className = node.getAttribute('class');
        }
        if (tagName === 'BUTTON' && node.hasAttribute('data-copy-value')) {
            element.dataset.copyValue = node.getAttribute('data-copy-value');
            element.addEventListener('click', () => copyToClipboard(element.dataset.copyValue));
        }
        node.childNodes.forEach((child) => {
            const safeChild = copyNode(child);
            if (safeChild) element.appendChild(safeChild);
        });
        return element;
    };

    contentElement.replaceChildren();
    parsed.body.childNodes.forEach((child) => {
        const safeChild = copyNode(child);
        if (safeChild) contentElement.appendChild(safeChild);
    });
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
        setModalTitle(titleEl, 'keyboard', title);
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
        setModalTitle(titleEl, icon, title);
        
        renderSafeModalContent(contentEl, content);
        
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

        setModalTitle(titleEl, icon, title);
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
                <button class="btn btn-secondary btn-small" data-copy-value="${escapeHtml(address)}">
                    <i class="fas fa-copy"></i>
                    Copy
                </button>
            </div>
            <code class="secret-value">${escapeHtml(address)}</code>
        ` : ''}
        <div class="secret-header${address ? ' secret-header-spaced' : ''}">
            <span class="info-label">Private Key</span>
            <button class="btn btn-secondary btn-small" data-copy-value="${escapeHtml(privateKey)}">
                <i class="fas fa-copy"></i>
                Copy
            </button>
        </div>
        <code class="secret-value">${escapeHtml(privateKey)}</code>
        <div class="warning-text warning-text-spaced">
            <i class="fas fa-lock"></i>
            ${escapeHtml(note)}
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

function rawToBigInt(value) {
    if (value === null || value === undefined || value === '') {
        return 0n;
    }
    try {
        return BigInt(value.toString());
    } catch (error) {
        return 0n;
    }
}

async function loadBalances() {
    try {
        // Get system status to know the active network
        const statusData = await API.getSystemStatus();
        const activeNetwork = statusData.activeNetwork || 'sepolia';
        const safeActiveNetwork = escapeHtml(activeNetwork);

        // Get all balances and billing info in parallel
        const [data, billingData] = await Promise.all([
            API.getBalance(),
            API.getBillingInfo().catch(() => ({ success: false }))
        ]);

        if (data.success && data.balances) {
            const balanceGrid = document.getElementById('balanceGrid');
            balanceGrid.innerHTML = '';

            // Only show balance for the active network
            const balanceData = data.balances[activeNetwork];

            if (!balanceData) {
                balanceGrid.innerHTML = `
                    <div class="balance-item">
                        <div class="balance-network">${safeActiveNetwork}</div>
                        <div class="balance-amount balance-amount-status balance-amount-muted">
                            No data available
                        </div>
                    </div>
                `;
                return;
            }

            if (balanceData.error) {
                balanceGrid.innerHTML = `
                    <div class="balance-item">
                        <div class="balance-network">${safeActiveNetwork}</div>
                        <div class="balance-amount balance-amount-status balance-amount-error">
                            Error: ${escapeHtml(balanceData.error)}
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
                    const isProvider = DashboardState.operatingMode === 'provider-consumer'
                        && billingData.success && billingData.isProvider === true;
                    const stakeInfo = billingData.stakeInfo || null;
                    // billing and bonded amounts only show 8 decimals
                    const billingBalance = formatEthDisplay(billingData.billingBalanceFormatted || '0', 8);

                    // Display billing balance if provider
                    if (isProvider && parseFloat(billingBalance) > 0) {
                        balanceGrid.innerHTML += `
                            <div class="balance-item">
                                <div class="balance-label">
                                    <i class="fas fa-university balance-icon-provider"></i>
                                    Provider billing balance
                                </div>
                                <div class="balance-amount balance-amount-cyan">${billingBalance} credits</div>
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
                                        <i class="fas fa-lock balance-icon-bonded"></i>
                                        Bonded
                                    </div>
                                    <div class="balance-amount balance-amount-purple">${bondedAmount} credits</div>
                                </div>
                            `;
                        }
                    }

                    // Consumer-only institutions should receive consumer guidance,
                    // never a provider-registration upsell.
                    const promoContainer = document.getElementById('labPromoMessage');
                    if (promoContainer) {
                        if (DashboardState.operatingMode !== 'unknown'
                            && !isProvider && parseFloat(labBalance) === 0) {
                            promoContainer.style.display = 'block';
                            const consumerOnly = DashboardState.operatingMode === 'consumer-only';
                            promoContainer.innerHTML = consumerOnly
                                ? `
                                    <div class="provider-promo-card">
                                        <div class="provider-promo-title">
                                            <i class="fas fa-wallet provider-promo-icon"></i>
                                            Fund the institution through the Marketplace to obtain service credits.
                                        </div>
                                        <a href="${escapeHtml(DashboardState.marketplaceUrl)}"
                                           target="_blank" rel="noopener noreferrer"
                                           class="provider-promo-link">
                                            <i class="fas fa-external-link-alt"></i>
                                            Open Marketplace funding
                                        </a>
                                    </div>
                                `
                                : `
                                    <div class="provider-promo-card">
                                        <div class="provider-promo-title">
                                            <i class="fas fa-rocket provider-promo-icon"></i>
                                            Register as a provider now to get <strong class="provider-promo-emphasis">1000 onboarding credits</strong>!
                                        </div>
                                        <a href="${escapeHtml(DashboardState.marketplaceUrl)}"
                                           target="_blank" rel="noopener noreferrer"
                                           class="provider-promo-link">
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
            document.getElementById('periodStartDateTop').textContent = formatOptionalDateFromSeconds(data.periodStart);
            document.getElementById('periodEndDateTop').textContent = formatOptionalDateFromSeconds(data.periodEnd);
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
            const transactions = data.transactions.map(tx => ({
                type: escapeHtml(tx.type || 'Tx'),
                hash: escapeHtml(formatAddress(tx.hash)),
                description: escapeHtml(tx.description || ''),
                amountTokens: escapeHtml(tx.amountTokens || '--'),
                timestamp: escapeHtml(formatTimestamp(tx.timestamp)),
                status: escapeHtml(tx.status || 'submitted')
            }));
            container.innerHTML = transactions.map(tx => `
                <div class="transaction-item">
                    <div class="tx-row">
                        <div class="tx-type">${tx.type}</div>
                        <div class="tx-hash">${tx.hash}</div>
                    </div>
                    <div class="tx-description">${tx.description}</div>
                    <div class="tx-meta">
                        <span>${tx.amountTokens}</span>
                        <span>${tx.timestamp}</span>
                        <span class="tx-status">${tx.status}</span>
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
    await WalletDashboardInstitutionWallet.loadSystemStatus();
    await Promise.all([
        loadBalances(),
        WalletDashboardProviderSettlement.loadCollectLabs(),
        WalletDashboardProviderSettlement.loadProviderGatewayDepartments(),
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
        providerSettlementTransitionForm.addEventListener('submit', WalletDashboardProviderSettlement.handleProviderSettlementTransition);
    }
    const providerSettlementOperationSelect = document.getElementById('providerSettlementOperationSelect');
    if (providerSettlementOperationSelect) {
        providerSettlementOperationSelect.addEventListener('change', WalletDashboardProviderSettlement.updateProviderSettlementOperationFields);
        WalletDashboardProviderSettlement.updateProviderSettlementOperationFields();
    }
}

// Setup button handlers
function setupButtonHandlers() {
    WalletDashboardProviderSettlement.setupProviderGatewayDepartmentHandlers();

    // Refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshAllData);
    }

    const provisioningTokenForm = document.getElementById('provisioningTokenForm');
    if (provisioningTokenForm) {
        provisioningTokenForm.addEventListener('submit', WalletDashboardInstitutionWallet.applyProvisioningToken);
    }
    
    // Refresh balance button (optional - may not exist)
    const refreshBalanceBtn = document.getElementById('refreshBalanceBtn');
    if (refreshBalanceBtn) {
        refreshBalanceBtn.addEventListener('click', loadBalances);
    }

    // Network buttons
    const sepoliaBtn = document.getElementById('sepoliaBtn');
    const mainnetBtn = document.getElementById('mainnetBtn');
    if (sepoliaBtn) {
        sepoliaBtn.addEventListener('click', () => {
            if (!sepoliaBtn.classList.contains('active')) {
                WalletDashboardInstitutionWallet.switchNetwork('sepolia');
            }
        });
    }
    if (mainnetBtn) {
        mainnetBtn.addEventListener('click', () => {
            if (!mainnetBtn.classList.contains('active')) {
                WalletDashboardInstitutionWallet.switchNetwork('mainnet');
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
            await WalletDashboardProviderSettlement.loadCollectStatusForSelectedLab();
        });
    }

    const providerSettlementTableBody = document.getElementById('providerSettlementLabsTableBody');
    if (providerSettlementTableBody) {
        providerSettlementTableBody.addEventListener('click', async (event) => {
            const row = event.target.closest('tr[data-lab-id]');
            if (!row) {
                return;
            }
            const labId = row.getAttribute('data-lab-id');
            if (!labId) {
                return;
            }
            const select = document.getElementById('collectLabSelect');
            if (select) {
                select.value = labId;
            }
            DashboardState.selectedCollectLabId = labId;
            await WalletDashboardProviderSettlement.loadCollectStatusForSelectedLab();
        });
    }

    const providerSettlementLoadMoreBtn = document.getElementById('providerSettlementLoadMoreBtn');
    if (providerSettlementLoadMoreBtn) {
        providerSettlementLoadMoreBtn.addEventListener('click', WalletDashboardProviderSettlement.loadMoreCollectLabs);
    }

    const collectLabBtn = document.getElementById('collectLabBtn');
    if (collectLabBtn) {
        collectLabBtn.addEventListener('click', WalletDashboardProviderSettlement.handleCollectLabPayout);
    }

    const revealPrivateKeyBtn = document.getElementById('revealPrivateKeyBtn');
    if (revealPrivateKeyBtn) {
        revealPrivateKeyBtn.addEventListener('click', WalletDashboardInstitutionWallet.handleRevealPrivateKey);
    }

    // Reset period button
    const resetPeriodBtn = document.getElementById('resetPeriodBtn');
    if (resetPeriodBtn) {
        resetPeriodBtn.addEventListener('click', async () => {
            if (!await showConfirmModal(
                'Reset spending period',
                'All users\' spending will be reset to zero and a new period will begin immediately.'
            )) {
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
                            <button class="btn btn-secondary btn-small" data-copy-value="${escapeHtml(data.address)}">
                                <i class="fas fa-copy"></i>
                                Copy
                            </button>
                        </div>
                        <code class="secret-value">${escapeHtml(data.address)}</code>
                        <div class="warning-text warning-text-spaced">
                            <i class="fas fa-exclamation-triangle"></i>
                            <strong>Important:</strong> Make sure to backup your wallet securely. 
                            The dashboard will now refresh to show your new wallet.
                        </div>
                    `;

                    await showInfoModal('Institutional Wallet Created', content, true);
                    
                    DashboardState.walletAddress = data.address;
                    DashboardState.institutionRegistered = false;
                    
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
                    DashboardState.institutionRegistered = false;
                    
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
    WalletDashboardProviderSettlement.clearCollectLabsRetryTimer();
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

window.WalletDashboardCore = Object.freeze({
    api: window.API,
    refreshAllData,
    renderSafeModalContent,
    setModalTitle,
    showInputModal,
    showPrivateKeyModal,
    updateLastRefreshTime,
    updateRoleBasedSections,
    state: DashboardState,
    collectLabsRetryDelaysMs: COLLECT_LABS_RETRY_DELAYS_MS,
    creditDecimals: CREDIT_DECIMALS,
    decimalToRawUnits,
    escapeHtml,
    formatAddress,
    formatLabTokenRaw,
    formatSettlementEurFromCreditRaw,
    loadBalances,
    loadRecentTransactions,
    rawToBigInt,
    showConfirmModal,
    showToast,
    updateCollectDetailVisibility,
    waitForAdminTransactionConfirmation
});
// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});

// Start the dashboard when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initDashboard();
    });
} else {
    initDashboard();
}

