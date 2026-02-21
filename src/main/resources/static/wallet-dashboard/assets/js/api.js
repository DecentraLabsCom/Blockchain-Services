/**
 * API Client for Treasury Admin Dashboard
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
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            return data;
        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);
            throw error;
        }
    },

    buildTreasuryAdminTypedData(status, payload) {
        const domainConfig = (status && status.treasuryAdminEip712) || {};
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
                    { name: 'timestamp', type: 'uint64' }
                ]
            },
            domain,
            primaryType: 'TreasuryAdminOperation',
            message
        };
    },

    async signTreasuryAdminOperation(status, payload) {
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
        const typedData = this.buildTreasuryAdminTypedData(status, payload);
        return await window.ethereum.request({
            method: 'eth_signTypedData_v4',
            params: [match, JSON.stringify(typedData)]
        });
    },

    /**
     * GET /treasury/admin/status
     * Get overall system status
     */
    async getSystemStatus() {
        return await this.request('/treasury/admin/status');
    },

    /**
     * GET /institution-config/status
     * Check provider configuration/registration state
     */
    async getProviderConfigStatus() {
        return await this.request('/institution-config/status');
    },

    /**
     * GET /treasury/admin/balance?chainId=X
     * Get institutional wallet balance
     * @param {number|null} chainId - Optional chain ID, null for all networks
     */
    async getBalance(chainId = null) {
        const endpoint = chainId 
            ? `/treasury/admin/balance?chainId=${chainId}`
            : '/treasury/admin/balance';
        return await this.request(endpoint);
    },

    /**
     * GET /treasury/admin/transactions?limit=X
     * Get recent transactions
     * @param {number} limit - Number of transactions to fetch
     */
    async getRecentTransactions(limit = 10) {
        return await this.request(`/treasury/admin/transactions?limit=${limit}`);
    },

    /**
     * GET /treasury/admin/contract-info
     * Get smart contract information
     */
    async getContractInfo() {
        return await this.request('/treasury/admin/contract-info');
    },

    /**
     * POST /treasury/admin/execute
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
        payload.signature = await this.signTreasuryAdminOperation(status, payload);

        return await this.request('/treasury/admin/execute', {
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
     * Deposit to treasury
     * @param {string} amountWei - Amount in wei
     */
    async depositTreasury(amountWei) {
        return await this.executeAdminOperation('DEPOSIT_TREASURY', {
            amount: amountWei
        });
    },

    /**
     * Withdraw from treasury
     * @param {string} amountWei - Amount in wei
     */
    async withdrawTreasury(amountWei) {
        return await this.executeAdminOperation('WITHDRAW_TREASURY', {
            amount: amountWei
        });
    },

    /**
     * Collect lab payouts for a specific lab ID.
     * @param {string|number} labId - Lab token ID
     * @param {string|number} maxBatch - Max reservations to process in one tx
     */
    async collectLabPayout(labId, maxBatch) {
        return await this.request('/treasury/admin/collect-lab-payout', {
            method: 'POST',
            body: JSON.stringify({
                labId: String(labId),
                maxBatch: String(maxBatch)
            })
        });
    },

    /**
     * Authorize backend address
     * @param {string} backendAddress - Ethereum address to authorize
     */
    async authorizeBackend(backendAddress) {
        return await this.executeAdminOperation('AUTHORIZE_BACKEND', {
            backendAddress
        });
    },

    /**
     * Revoke backend authorization
     */
    async revokeBackend() {
        return await this.executeAdminOperation('REVOKE_BACKEND', {});
    },

    /**
     * Admin reset backend for provider
     * @param {string} providerAddress - Provider Ethereum address
     * @param {string} backendAddress - Backend Ethereum address (optional)
     */
    async adminResetBackend(providerAddress, backendAddress = null) {
        return await this.executeAdminOperation('ADMIN_RESET_BACKEND', {
            providerAddress,
            backendAddress
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
     * Get treasury information (limit, period, balance)
     */
    async getTreasuryInfo() {
        return await this.request('/treasury/admin/treasury-info');
    },

    /**
     * Get top spenders for current period
     * @param {number} limit - Number of top spenders to retrieve (default: 10)
     */
    async getTopSpenders(limit = 10) {
        return await this.request(`/treasury/admin/top-spenders?limit=${limit}`);
    },

    /**
     * Get labs owned by the institutional provider wallet.
     */
    async getProviderLabs() {
        return await this.request('/treasury/admin/provider-labs');
    },

    /**
     * Get pending payout and collect readiness for a specific lab.
     * @param {string|number} labId - Lab token ID
     * @param {number|null} maxBatch - Batch size for collect simulation
     */
    async getLabPayoutStatus(labId, maxBatch = null) {
        const params = new URLSearchParams();
        params.set('labId', String(labId));
        if (maxBatch !== null && maxBatch !== undefined) {
            params.set('maxBatch', String(maxBatch));
        }
        return await this.request(`/treasury/admin/lab-payout-status?${params.toString()}`);
    }
};

// Export for use in other scripts
window.API = API;
