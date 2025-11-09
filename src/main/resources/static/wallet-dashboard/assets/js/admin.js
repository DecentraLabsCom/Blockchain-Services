/**
 * Treasury Admin Dashboard - Main Logic
 * Handles UI interactions, data loading, and automatic refresh
 */

// State management
const DashboardState = {
    autoRefreshInterval: null,
    autoRefreshEnabled: true,
    refreshIntervalMs: 30000, // 30 seconds
    lastUpdate: null
};

// Utility: Format wei to ETH
function weiToEth(weiString) {
    if (!weiString) return '0';
    const wei = BigInt(weiString);
    const eth = Number(wei) / 1e18;
    return eth.toFixed(6);
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

// Toast notification
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 5000);
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

// Load system status
async function loadSystemStatus() {
    try {
        const data = await API.getSystemStatus();
        
        if (data.success) {
            const walletConfigured = data.walletConfigured;
            const walletAddress = data.institutionalWalletAddress;
            
            // Update wallet address display
            const walletAddressEl = document.getElementById('walletAddress');
            if (walletAddress) {
                walletAddressEl.textContent = formatAddress(walletAddress);
                walletAddressEl.classList.remove('warning-text');
            } else {
                walletAddressEl.innerHTML = '<span class="warning-text clickable" id="walletSetupTrigger">⚠️ Not configured - Click to setup</span>';
                // Add click handler for the warning text
                setTimeout(() => {
                    const trigger = document.getElementById('walletSetupTrigger');
                    if (trigger) {
                        trigger.addEventListener('click', toggleWalletSetupDropdown);
                    }
                }, 100);
            }
            
            // Show/hide wallet setup dropdown
            const dropdown = document.getElementById('walletSetupDropdown');
            if (dropdown) {
                dropdown.style.display = 'none'; // Always start hidden, user clicks to open
            }
            
            document.getElementById('contractAddress').textContent = 
                data.contractAddress ? formatAddress(data.contractAddress) : 'Not configured';
            
            // Display active network
            const activeNetworkEl = document.getElementById('activeNetwork');
            if (data.availableNetworks) {
                const networks = data.availableNetworks;
                const activeNet = data.activeNetwork || 'sepolia'; // Default to sepolia
                const networkInfo = networks[activeNet];
                if (networkInfo) {
                    const displayName = (networkInfo.name || activeNet).charAt(0).toUpperCase() + (networkInfo.name || activeNet).slice(1);
                    activeNetworkEl.innerHTML = `<span class="network-badge">${displayName}</span>`;
                } else {
                    const displayName = activeNet.charAt(0).toUpperCase() + activeNet.slice(1);
                    activeNetworkEl.innerHTML = `<span class="network-badge">${displayName}</span>`;
                }
            } else {
                activeNetworkEl.textContent = 'Unknown';
            }
            
            // Update status indicator
            const statusIndicator = document.getElementById('statusIndicator');
            if (walletConfigured) {
                statusIndicator.querySelector('.status-dot').style.background = 'var(--neon-green)';
                statusIndicator.querySelector('.status-text').textContent = 'Connected';
            } else {
                statusIndicator.querySelector('.status-dot').style.background = 'var(--neon-yellow)';
                statusIndicator.querySelector('.status-text').textContent = 'Wallet Setup Required';
            }
        }
        
        updateLastRefreshTime();
    } catch (error) {
        console.error('Failed to load system status:', error);
        showToast('Failed to load system status: ' + error.message, 'error');
        
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

// Load wallet balances
async function loadBalances() {
    try {
        const data = await API.getBalance();
        
        if (data.success && data.balances) {
            const balanceGrid = document.getElementById('balanceGrid');
            balanceGrid.innerHTML = '';
            
            for (const [network, balanceData] of Object.entries(data.balances)) {
                if (balanceData.error) {
                    balanceGrid.innerHTML += `
                        <div class="balance-item">
                            <div class="balance-network">${network}</div>
                            <div class="balance-amount" style="color: var(--neon-red); font-size: 1rem;">
                                Error: ${balanceData.error}
                            </div>
                        </div>
                    `;
                } else {
                    const ethBalance = balanceData.balanceEth || weiToEth(balanceData.balanceWei);
                    balanceGrid.innerHTML += `
                        <div class="balance-item">
                            <div class="balance-network">${network}</div>
                            <div class="balance-amount">${ethBalance} ETH</div>
                        </div>
                    `;
                }
            }
        }
    } catch (error) {
        console.error('Failed to load balances:', error);
        showToast('Failed to load balances: ' + error.message, 'error');
    }
}

// Load spending limits
async function loadSpendingLimits() {
    try {
        const data = await API.getSpendingLimits();
        
        if (data.success && data.limits) {
            const limits = data.limits;
            
            // Daily limit
            updateLimitDisplay('daily', 
                limits.dailyLimit, 
                limits.dailySpent, 
                limits.dailyLimit
            );
            
            // Weekly limit
            updateLimitDisplay('weekly',
                limits.weeklyLimit,
                limits.weeklySpent,
                limits.weeklyLimit
            );
            
            // Monthly limit
            updateLimitDisplay('monthly',
                limits.monthlyLimit,
                limits.monthlySpent,
                limits.monthlyLimit
            );
        }
    } catch (error) {
        console.error('Failed to load spending limits:', error);
        showToast('Failed to load spending limits: ' + error.message, 'error');
    }
}

// Update limit display
function updateLimitDisplay(period, limitWei, spentWei, totalWei) {
    const limitEth = weiToEth(limitWei);
    const spentEth = weiToEth(spentWei);
    const totalEth = weiToEth(totalWei);
    const remainingEth = (parseFloat(totalEth) - parseFloat(spentEth)).toFixed(6);
    
    const percentage = totalWei !== '0' 
        ? (parseFloat(spentEth) / parseFloat(totalEth) * 100).toFixed(2)
        : 0;
    
    document.getElementById(`${period}Limit`).textContent = `${limitEth} ETH`;
    document.getElementById(`${period}Spent`).textContent = `${spentEth} ETH spent`;
    document.getElementById(`${period}Remaining`).textContent = `${remainingEth} ETH remaining`;
    document.getElementById(`${period}Progress`).style.width = `${percentage}%`;
    
    // Color code progress bar based on usage
    const progressBar = document.getElementById(`${period}Progress`);
    if (percentage > 90) {
        progressBar.style.background = 'linear-gradient(90deg, var(--neon-red), var(--neon-orange))';
    } else if (percentage > 70) {
        progressBar.style.background = 'linear-gradient(90deg, var(--neon-orange), var(--neon-yellow))';
    } else {
        progressBar.style.background = 'linear-gradient(90deg, var(--neon-green), var(--neon-blue))';
    }
}

// Load recent transactions
async function loadRecentTransactions() {
    try {
        const data = await API.getRecentTransactions(10);
        
        const container = document.getElementById('transactionsContainer');
        
        if (data.transactions && data.transactions.length > 0) {
            container.innerHTML = data.transactions.map(tx => `
                <div class="transaction-item">
                    <div class="tx-hash">${formatAddress(tx.hash)}</div>
                    <div class="tx-time">${formatTimestamp(tx.timestamp)}</div>
                    <div class="tx-amount">${tx.amount} ETH</div>
                </div>
            `).join('');
        } else {
            // Keep the "not implemented" message
            container.innerHTML = `
                <div class="no-data">
                    <span class="icon">📋</span>
                    <p>Transaction history tracking not yet implemented</p>
                    <small>${data.note || 'Consider integrating Etherscan API or event indexing'}</small>
                </div>
            `;
        }
    } catch (error) {
        console.error('Failed to load transactions:', error);
    }
}

// Refresh all data
async function refreshAllData() {
    console.log('Refreshing dashboard data...');
    await Promise.all([
        loadSystemStatus(),
        loadBalances(),
        loadSpendingLimits(),
        loadRecentTransactions()
    ]);
    showToast('Dashboard refreshed successfully', 'success');
}

// Handle form submissions
function setupFormHandlers() {
    // Set user limit form
    document.getElementById('limitsForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const limitWei = document.getElementById('userLimitInput').value.trim();
        
        if (!limitWei) {
            showToast('Please enter a valid limit in wei', 'error');
            return;
        }
        
        try {
            const result = await API.setUserLimit(limitWei);
            if (result.success) {
                showToast(`Limit updated successfully. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('userLimitInput').value = '';
                setTimeout(() => loadSpendingLimits(), 5000); // Reload after 5 seconds
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
        const periodSeconds = document.getElementById('periodInput').value.trim();
        
        if (!periodSeconds) {
            showToast('Please enter a valid period in seconds', 'error');
            return;
        }
        
        try {
            const result = await API.setSpendingPeriod(periodSeconds);
            if (result.success) {
                showToast(`Period updated successfully. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('periodInput').value = '';
            } else {
                showToast('Failed to update period: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error updating period: ' + error.message, 'error');
        }
    });
    
    // Treasury deposit button
    document.getElementById('depositBtn').addEventListener('click', async () => {
        const amountWei = document.getElementById('treasuryAmount').value.trim();
        
        if (!amountWei) {
            showToast('Please enter an amount in wei', 'error');
            return;
        }
        
        if (!confirm(`Deposit ${weiToEth(amountWei)} ETH to treasury?`)) {
            return;
        }
        
        try {
            const result = await API.depositTreasury(amountWei);
            if (result.success) {
                showToast(`Deposit successful. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('treasuryAmount').value = '';
                setTimeout(() => loadBalances(), 5000);
            } else {
                showToast('Deposit failed: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error depositing: ' + error.message, 'error');
        }
    });
    
    // Treasury withdraw button
    document.getElementById('withdrawBtn').addEventListener('click', async () => {
        const amountWei = document.getElementById('treasuryAmount').value.trim();
        
        if (!amountWei) {
            showToast('Please enter an amount in wei', 'error');
            return;
        }
        
        if (!confirm(`⚠️ Withdraw ${weiToEth(amountWei)} ETH from treasury? This action cannot be undone.`)) {
            return;
        }
        
        try {
            const result = await API.withdrawTreasury(amountWei);
            if (result.success) {
                showToast(`Withdrawal successful. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('treasuryAmount').value = '';
                setTimeout(() => loadBalances(), 5000);
            } else {
                showToast('Withdrawal failed: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error withdrawing: ' + error.message, 'error');
        }
    });
}

// Setup button handlers
function setupButtonHandlers() {
    // Refresh button
    document.getElementById('refreshBtn').addEventListener('click', refreshAllData);
    
    // Refresh balance button
    document.getElementById('refreshBalanceBtn').addEventListener('click', loadBalances);
    
    // Refresh transactions button
    document.getElementById('refreshTxBtn').addEventListener('click', loadRecentTransactions);
    
    // Edit limits button (placeholder)
    document.getElementById('editLimitsBtn').addEventListener('click', () => {
        showToast('Use the administrative operations section to modify limits', 'info');
    });
    
    // Reset period button (placeholder - needs implementation)
    document.getElementById('resetPeriodBtn').addEventListener('click', () => {
        showToast('Period reset functionality coming soon', 'info');
    });
    
    // Wallet setup buttons
    const createWalletBtn = document.getElementById('createWalletBtn');
    const importWalletBtn = document.getElementById('importWalletBtn');
    
    if (createWalletBtn) {
        createWalletBtn.addEventListener('click', async () => {
            // Close dropdown
            const dropdown = document.getElementById('walletSetupDropdown');
            if (dropdown) dropdown.style.display = 'none';
            
            const password = prompt('Enter a secure password for the new wallet:');
            if (!password || password.length < 8) {
                showToast('Password must be at least 8 characters', 'error');
                return;
            }
            
            const confirmPassword = prompt('Confirm password:');
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
                
                const data = await response.json();
                if (data.success && data.address) {
                    showToast('✓ Wallet created and configured successfully!', 'success');
                    
                    alert('✓ Institutional Wallet Created!\n\n' +
                          'Address: ' + data.address + '\n\n' +
                          'Refreshing dashboard...');
                    
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
            
            const mnemonic = prompt('Enter your 12-word mnemonic phrase:');
            if (!mnemonic || mnemonic.trim().split(/\s+/).length !== 12) {
                showToast('Invalid mnemonic (must be exactly 12 words)', 'error');
                return;
            }
            
            const password = prompt('Enter password to encrypt the wallet:');
            if (!password || password.length < 8) {
                showToast('Password must be at least 8 characters', 'error');
                return;
            }
            
            try {
                showToast('Importing wallet...', 'info');
                const response = await fetch('/wallet/import', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mnemonic: mnemonic.trim(), password })
                });
                
                const data = await response.json();
                if (data.success && data.address) {
                    showToast('✓ Wallet imported and configured successfully!', 'success');
                    alert('✓ Institutional Wallet Imported!\n\n' +
                          'Address: ' + data.address + '\n\n' +
                          'The wallet has been automatically configured and saved.\n' +
                          'Refreshing dashboard...');
                    
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
}

// Initialize dashboard
async function initDashboard() {
    console.log('Initializing Treasury Admin Dashboard...');
    
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
