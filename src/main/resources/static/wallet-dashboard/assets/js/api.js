/**
 * API Client for Treasury Admin Dashboard
 * Handles all communication with the backend REST API
 */

const API = {
    BASE_URL: window.location.origin,
    
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

    /**
     * GET /treasury/admin/status
     * Get overall system status
     */
    async getSystemStatus() {
        return await this.request('/treasury/admin/status');
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
     * GET /treasury/admin/limits
     * Get spending limits configuration
     */
    async getSpendingLimits() {
        return await this.request('/treasury/admin/limits');
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
    }
};

// Export for use in other scripts
window.API = API;
