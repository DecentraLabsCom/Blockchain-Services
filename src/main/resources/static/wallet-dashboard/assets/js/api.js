/**
 * API Client for Billing Admin Dashboard
 * Handles all communication with the backend REST API
 */

const API = {
    BASE_URL: window.location.origin,
    ZERO_ADDRESS: '0x0000000000000000000000000000000000000000',
    
    /**
     * Generic fetch wrapper with error handling
     */
    async request(endpoint, options = {}) {
        const url = `${this.BASE_URL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, config);
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
                throw new Error(detail);
            }
            
            return data || {};
        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);
            throw error;
        }
    },

    buildBillingAdminTypedData(status, payload) {
        const domainConfig = (status && status.billingAdminEip712) || {};
        const domain = {
            name: domainConfig.name || 'DecentraLabsTreasuryAdmin',
            version: domainConfig.version || '1',
            chainId: domainConfig.chainId || 11155111,
            verifyingContract: domainConfig.verifyingContract || status.contractAddress || this.ZERO_ADDRESS
        };

        const message = {
            signer: payload.adminWalletAddress,
            operation: payload.operation,
            providerAddress: payload.providerAddress || this.ZERO_ADDRESS,
            backendAddress: payload.backendAddress || this.ZERO_ADDRESS,
            spendingLimit: payload.spendingLimit || '0',
            spendingPeriod: payload.spendingPeriod || '0',
            amount: payload.amount || '0',
            labId: payload.labId || '0',
            maxBatch: payload.maxBatch || '0',
            creditAccount: payload.creditAccount || this.ZERO_ADDRESS,
            creditDelta: payload.creditDelta || '0',
            fromReceivableState: payload.fromReceivableState || '0',
            toReceivableState: payload.toReceivableState || '0',
            reference: payload.reference || '',
            timestamp: payload.timestamp
        };

        return {
            types: {
                EIP712Domain: [
                    { name: 'name', type: 'string' },
                    { name: 'version', type: 'string' },
                    { name: 'chainId', type: 'uint256' },
                    { name: 'verifyingContract', type: 'address' }
                ],
                TreasuryAdminOperation: [
                    { name: 'signer', type: 'address' },
                    { name: 'operation', type: 'string' },
                    { name: 'providerAddress', type: 'address' },
                    { name: 'backendAddress', type: 'address' },
                    { name: 'spendingLimit', type: 'uint256' },
                    { name: 'spendingPeriod', type: 'uint256' },
                    { name: 'amount', type: 'uint256' },
                    { name: 'labId', type: 'uint256' },
                    { name: 'maxBatch', type: 'uint256' },
                    { name: 'creditAccount', type: 'address' },
                    { name: 'creditDelta', type: 'int256' },
                    { name: 'fromReceivableState', type: 'uint256' },
                    { name: 'toReceivableState', type: 'uint256' },
                    { name: 'reference', type: 'string' },
                    { name: 'timestamp', type: 'uint64' }
                ]
            },
            domain,
            primaryType: 'TreasuryAdminOperation',
            message
        };
    },

    async signBillingAdminOperation(status, payload) {
        if (!window.ethereum || !window.ethereum.request) {
            throw new Error('No wallet provider found. Connect the institutional wallet to sign admin actions.');
        }
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const signer = payload.adminWalletAddress;
        if (!signer) {
            throw new Error('Institutional wallet address is missing.');
        }
        const match = (accounts || []).find(account => account.toLowerCase() === signer.toLowerCase());
        if (!match) {
            throw new Error('Connected wallet does not match the institutional wallet address.');
        }
        const typedData = this.buildBillingAdminTypedData(status, payload);
        return await window.ethereum.request({
            method: 'eth_signTypedData_v4',
            params: [match, JSON.stringify(typedData)]
        });
    },

    /**
     * GET /billing/admin/status
     * Get overall system status
     */
    async getSystemStatus() {
        try {
            return await this.request('/billing/admin/status');
        } catch (error) {
            const message = (error && error.message ? error.message : '').toLowerCase();
            if (message.includes('404')) {
                return await this.request('/treasury/admin/status');
            }
            throw error;
        }
    },

    /**
     * GET /institution-config/status
     * Check provider configuration/registration state
     */
    async getProviderConfigStatus() {
        return await this.request('/institution-config/status');
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
     * POST /billing/admin/execute
     * Execute administrative operation
     * @param {string} operation - Operation type (SET_USER_LIMIT, SET_SPENDING_PERIOD, etc.)
     * @param {object} params - Operation parameters
     */
    async executeAdminOperation(operation, params) {
        // Get institutional wallet address from status
        const status = await this.getSystemStatus();
        const adminWalletAddress = status.institutionalWalletAddress;

        if (!adminWalletAddress) {
            throw new Error('Institutional wallet not configured');
        }

        const payload = {
            adminWalletAddress,
            operation,
            ...params
        };

        payload.timestamp = Date.now();
        payload.signature = await this.signBillingAdminOperation(status, payload);

        return await this.request('/billing/admin/execute', {
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
     * @param {string} amountRaw - Raw credit amount with 5 decimals
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
     * @param {string} creditDelta - Signed raw delta with 5 decimals
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
     * Transition provider receivable lifecycle for a lab.
     * @param {string|number} labId - Lab token ID
     * @param {string|number} fromReceivableState - Source lifecycle bucket
     * @param {string|number} toReceivableState - Target lifecycle bucket
     * @param {string|number} amountRaw - Raw credit-denominated amount with 5 decimals
     * @param {string} reference - Optional business reference
     */
    async transitionProviderReceivableState(
        labId,
        fromReceivableState,
        toReceivableState,
        amountRaw,
        reference = ''
    ) {
        return await this.executeAdminOperation('TRANSITION_PROVIDER_RECEIVABLE_STATE', {
            labId: String(labId),
            fromReceivableState: String(fromReceivableState),
            toReceivableState: String(toReceivableState),
            amount: String(amountRaw),
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

        try {
            return await this.request('/billing/admin/request-provider-payout', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
        } catch (error) {
            const message = (error && error.message ? error.message : '').toLowerCase();
            // Compatibility path for environments still exposing legacy payout flow.
            if (message.includes('404')) {
                return await this.executeAdminOperation('COLLECT_LAB_PAYOUT', payload);
            }
            throw error;
        }
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
    async getProviderLabs() {
        return await this.request('/billing/admin/provider-labs');
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

        try {
            return await this.request(`/billing/admin/provider-receivable-status?${params.toString()}`);
        } catch (error) {
            const message = (error && error.message ? error.message : '').toLowerCase();
            if (message.includes('404')) {
                return await this.request(`/treasury/admin/lab-payout-status?${params.toString()}`);
            }
            throw error;
        }
    },

};

// Export for use in other scripts
window.API = API;
