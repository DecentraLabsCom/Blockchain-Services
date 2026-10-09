/**
 * API Client for Billing Admin Dashboard
 * Handles all communication with the backend REST API
 */

const API = {
    BASE_URL: window.location.origin,
    adminAccessToken: null,

    setAdminAccessToken(token) {
        this.adminAccessToken = typeof token === 'string' && token.trim() ? token.trim() : null;
    },

    clearAdminAccessToken() {
        this.adminAccessToken = null;
    },
    
    /**
     * Generic fetch wrapper with error handling
     */
    async request(endpoint, options = {}) {
        const url = `${this.BASE_URL}${endpoint}`;
        const method = String(options.method || 'GET').toUpperCase();
        const headers = new Headers(options.headers || {});
        if (this.adminAccessToken) {
            headers.set('Authorization', `Bearer ${this.adminAccessToken}`);
        }
        if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
            const csrf = document.cookie.split('; ').find((entry) => entry.startsWith('dlabs_csrf='));
            if (csrf) {
                headers.set('X-CSRF-Token', decodeURIComponent(csrf.slice('dlabs_csrf='.length)));
            }
        }
        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...Object.fromEntries(headers.entries())
            },
            credentials: 'same-origin'
        };

        try {
            const response = await fetch(url, config);
            if (response.status === 401 && this.adminAccessToken) {
                this.clearAdminAccessToken();
            }
            const rawBody = await response.text();
            let data = null;
            if (rawBody) {
                try {
                    data = JSON.parse(rawBody);
                } catch (parseError) {
                    data = null;
                }
            }
            
            if (!response.ok) {
                const detailFromMap = (data && data.errors && typeof data.errors === 'object')
                    ? Object.entries(data.errors)
                        .map(([field, msg]) => `${field}: ${msg}`)
                        .join(', ')
                    : '';
                const detail =
                    (data && (data.error || data.message || data.details)) ||
                    detailFromMap ||
                    rawBody ||
                    `HTTP ${response.status}${response.statusText ? `: ${response.statusText}` : ''}`;
                const error = new Error(detail);
                error.status = response.status;
                throw error;
            }
            
            return data || {};
        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);
            throw error;
        }
    },

    /**
     * GET /billing/admin/status
     * Get overall system status
     */
    async getSystemStatus() {
        return await this.request('/billing/admin/status');
    },

    /**
     * GET /institution-config/status
     * Check provider configuration/registration state
     */
    async getProviderConfigStatus() {
        return await this.request('/institution-config/status');
    },

    async getAccessPolicy() {
        return await this.request('/wallet-admin/access-policies');
    },

    async saveAccessPolicy(policy) {
        return await this.request('/wallet-admin/access-policies', {
            method: 'PUT',
            body: JSON.stringify(policy)
        });
    },

    async activateAccessPolicy() {
        return await this.request('/wallet-admin/access-policies/activate', { method: 'POST', body: '{}' });
    },

    async deactivateAccessPolicy() {
        return await this.request('/wallet-admin/access-policies/deactivate', { method: 'POST', body: '{}' });
    },

    async testAccessPolicy(payload) {
        return await this.request('/wallet-admin/access-policies/test', { method: 'POST', body: JSON.stringify(payload) });
    },

    async importAccessPolicy(policy) {
        return await this.request('/wallet-admin/access-policies/import', { method: 'POST', body: JSON.stringify(policy) });
    },

    /**
     * Apply an administrator-issued provisioning token.
     * Consumer-only deployments use the consumer endpoint; Full provider
     * deployments use the provider endpoint.
     */
    async applyProvisioningToken(token, operatingMode = 'unknown') {
        const endpointByMode = {
            'consumer-only': '/institution-config/apply-consumer-token',
            'provider-consumer': '/institution-config/apply-provider-token'
        };
        const endpoint = endpointByMode[operatingMode];
        if (!endpoint) {
            throw new Error('Backend role is unavailable. Reload the dashboard before applying a provisioning token.');
        }
        return await this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify({ token })
        });
    },

    /**
     * GET /billing/admin/balance?chainId=X
     * Get institutional wallet balance
     * @param {number|null} chainId - Optional chain ID, null for all networks
     */
    async getBalance(chainId = null) {
        const endpoint = chainId 
            ? `/billing/admin/balance?chainId=${chainId}`
            : '/billing/admin/balance';
        return await this.request(endpoint);
    },

    /**
     * GET /billing/admin/transactions?limit=X
     * Get recent transactions
     * @param {number} limit - Number of transactions to fetch
     */
    async getRecentTransactions(limit = 10) {
        return await this.request(`/billing/admin/transactions?limit=${limit}`);
    },

    /**
     * Get blockchain receipt status for an administrative transaction.
     * @param {string} txHash - Transaction hash
     */
    async getAdminTransactionStatus(txHash) {
        const params = new URLSearchParams();
        params.set('txHash', String(txHash));
        return await this.request(`/billing/admin/transaction-status?${params.toString()}`);
    },

    /**
     * POST /billing/admin/execute-internal
     * Execute administrative operation through the configured server wallet
     * @param {string} operation - Operation type (SET_USER_LIMIT, SET_SPENDING_PERIOD, etc.)
     * @param {object} params - Operation parameters
     */
    async executeAdminOperation(operation, params) {
        const payload = {
            operation,
            ...(params || {}),
            operationId: (window.crypto && typeof window.crypto.randomUUID === 'function')
                ? window.crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(36).slice(2)}`
        };

        return await this.request('/billing/admin/execute-internal', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    /**
     * Set user spending limit
     * @param {string} limitWei - Limit in wei
     */
    async setUserLimit(limitWei) {
        return await this.executeAdminOperation('SET_USER_LIMIT', {
            spendingLimit: limitWei
        });
    },

    /**
     * Set spending period
     * @param {string} periodSeconds - Period in seconds
     */
    async setSpendingPeriod(periodSeconds) {
        return await this.executeAdminOperation('SET_SPENDING_PERIOD', {
            spendingPeriod: periodSeconds
        });
    },

    /**
     * Issue managed service credits to a customer credit account.
     * @param {string} creditAccount - Ethereum account receiving the managed credits
     * @param {string} amountRaw - Raw credit amount with 7 decimals
     * @param {string} reference - Optional business reference
     */
    async issueServiceCredits(creditAccount, amountRaw, reference = '') {
        return await this.executeAdminOperation('ISSUE_SERVICE_CREDITS', {
            creditAccount,
            amount: amountRaw,
            reference
        });
    },

    /**
     * Apply an administrative service-credit delta to a customer account.
     * @param {string} creditAccount - Ethereum account being adjusted
     * @param {string} creditDelta - Signed raw delta with 7 decimals
     * @param {string} reference - Optional business reference
     */
    async adjustServiceCredits(creditAccount, creditDelta, reference = '') {
        return await this.executeAdminOperation('ADJUST_SERVICE_CREDITS', {
            creditAccount,
            creditDelta,
            reference
        });
    },

    /**
     * Dispute one canonical settlement batch.
     * @param {string} batchId - Non-zero bytes32 batch identifier
     * @param {string} reference - Mandatory external dispute reference
     */
    async disputeSettlementBatch(batchId, reference) {
        return await this.executeAdminOperation('DISPUTE_PROVIDER_SETTLEMENT_BATCH', {
            batchId,
            reference
        });
    },

    /** Reverse one canonical settlement batch, including a previously disputed batch. */
    async reverseSettlementBatch(batchId, reference) {
        return await this.executeAdminOperation('REVERSE_PROVIDER_SETTLEMENT_BATCH', {
            batchId,
            reference
        });
    },

    /** Dispute one canonical settlement claim. */
    async disputeSettlementClaim(claimId, reference) {
        return await this.executeAdminOperation('DISPUTE_PROVIDER_SETTLEMENT_CLAIM', {
            claimId,
            reference
        });
    },

    /** Reverse one canonical settlement claim, including a previously disputed claim. */
    async reverseSettlementClaim(claimId, reference) {
        return await this.executeAdminOperation('REVERSE_PROVIDER_SETTLEMENT_CLAIM', {
            claimId,
            reference
        });
    },

    /**
     * Request provider payout for a specific lab ID.
     * @param {string|number} labId - Lab token ID
     * @param {string|number} maxBatch - Max reservations to process in one tx
     */
    async requestProviderPayout(labId, maxBatch) {
        const payload = {
            labId: String(labId),
            maxBatch: String(maxBatch)
        };

        return await this.request('/billing/admin/request-provider-payout', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    /**
     * POST /wallet/switch-network
     * Switch the active blockchain network
     * @param {string} networkId - Network identifier ('mainnet' or 'sepolia')
     */
    async switchNetwork(networkId) {
        return await this.request('/wallet/switch-network', {
            method: 'POST',
            body: JSON.stringify({ networkId })
        });
    },

    /**
     * POST /wallet/reveal
     * Reveal the institutional wallet private key (password required)
     */
    async revealPrivateKey(password) {
        return await this.request('/wallet/reveal', {
            method: 'POST',
            body: JSON.stringify({ password })
        });
    },

    /**
     * Reset spending period
     */
    async resetSpendingPeriod() {
        return await this.executeAdminOperation('RESET_SPENDING_PERIOD', {});
    },

    /**
     * Get billing information (limit, period, balance)
     */
    async getBillingInfo() {
        return await this.request('/billing/admin/billing-info');
    },

    /**
     * Get top spenders for current period
     * @param {number} limit - Number of top spenders to retrieve (default: 10)
     */
    async getTopSpenders(limit = 10) {
        return await this.request(`/billing/admin/top-spenders?limit=${limit}`);
    },

    /**
     * Get labs owned by the institutional provider wallet.
     */
    async getProviderLabs(options = {}) {
        const params = new URLSearchParams();
        if (options.offset !== null && options.offset !== undefined) {
            params.set('offset', String(options.offset));
        }
        if (options.limit !== null && options.limit !== undefined) {
            params.set('limit', String(options.limit));
        }
        if (options.includeSummary !== null && options.includeSummary !== undefined) {
            params.set('includeSummary', String(Boolean(options.includeSummary)));
        }

        const query = params.toString();
        return await this.request(query
            ? `/billing/admin/provider-labs?${query}`
            : '/billing/admin/provider-labs');
    },

    /**
     * Get provider receivable and payout-request readiness for a specific lab.
     * @param {string|number} labId - Lab token ID
     * @param {number|null} maxBatch - Batch size for payout-request simulation
     */
    async getProviderReceivableStatus(labId, maxBatch = null) {
        const params = new URLSearchParams();
        params.set('labId', String(labId));
        if (maxBatch !== null && maxBatch !== undefined) {
            params.set('maxBatch', String(maxBatch));
        }
        return await this.request(`/billing/admin/provider-receivable-status?${params.toString()}`);
    },

    /** List provider invoices projected from canonical settlement claims. */
    async listProviderReceivables(status = null) {
        const query = status ? `?status=${encodeURIComponent(String(status))}` : '';
        return await this.request(`/billing/provider-receivables${query}`);
    },

    /** Submit a canonical queued settlement batch as a provider invoice claim. */
    async submitProviderInvoice(labId, payload) {
        return await this.request(`/billing/provider-receivables/${encodeURIComponent(String(labId))}/invoice`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    /** Approve a previously submitted canonical settlement claim. */
    async approveProviderInvoice(invoiceId, payload) {
        return await this.request(`/billing/provider-receivables/invoices/${encodeURIComponent(String(invoiceId))}/approve`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    /** Record payment proof for an approved canonical settlement claim. */
    async recordProviderPayout(invoiceId, payload) {
        return await this.request(`/billing/provider-receivables/invoices/${encodeURIComponent(String(invoiceId))}/pay`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

};

// Export for use in other scripts
window.API = API;
