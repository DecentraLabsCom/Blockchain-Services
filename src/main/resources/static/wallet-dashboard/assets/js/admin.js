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
    console.log('[loadSystemStatus] Starting...');
    try {
        console.log('[loadSystemStatus] Calling API.getSystemStatus()...');
        const data = await API.getSystemStatus();
        console.log('[loadSystemStatus] Received data:', data);
        
        if (data.success) {
            const walletConfigured = data.walletConfigured;
            const walletAddress = data.institutionalWalletAddress;
            
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
            
            console.log('[loadSystemStatus] Updated contract address element');
            
            // Update network buttons to show active network
            const activeNet = data.activeNetwork || 'sepolia';
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
        }
        
        updateLastRefreshTime();
        console.log('[loadSystemStatus] Completed successfully');
    } catch (error) {
        console.error('[loadSystemStatus] ERROR:', error);
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

// Update network buttons to show active network
function updateNetworkButtons(activeNetwork) {
    const sepoliaBtn = document.getElementById('sepoliaBtn');
    const mainnetBtn = document.getElementById('mainnetBtn');
    
    if (sepoliaBtn && mainnetBtn) {
        // Remove active class from both
        sepoliaBtn.classList.remove('active');
        mainnetBtn.classList.remove('active');
        
        // Add active class to the current network
        if (activeNetwork === 'sepolia') {
            sepoliaBtn.classList.add('active');
        } else if (activeNetwork === 'mainnet') {
            mainnetBtn.classList.add('active');
        }
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
        
        // Get all balances
        const data = await API.getBalance();
        
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
                const ethBalance = balanceData.balanceEth || weiToEth(balanceData.balanceWei);
                
                // Display ETH balance
                balanceGrid.innerHTML += `
                    <div class="balance-item">
                        <div class="balance-label">ETH Balance</div>
                        <div class="balance-amount">${ethBalance} ETH</div>
                    </div>
                `;
                
                // Display LAB token balance (always show, even if token not configured)
                if (balanceData.labBalance !== undefined) {
                    const labBalance = balanceData.labBalance || '0';
                    balanceGrid.innerHTML += `
                        <div class="balance-item">
                            <div class="balance-label">LAB Balance</div>
                            <div class="balance-amount">${labBalance} LAB</div>
                        </div>
                    `;
                    
                    // Show promotional message if LAB balance is 0 (in separate container)
                    const promoContainer = document.getElementById('labPromoMessage');
                    if (promoContainer) {
                        if (parseFloat(labBalance) === 0) {
                            promoContainer.style.display = 'block';
                            promoContainer.innerHTML = `
                                <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, rgba(0, 255, 157, 0.1), rgba(0, 229, 255, 0.1)); border-radius: 0.5rem; margin-top: 1rem; border: 1px solid rgba(0, 255, 157, 0.2);">
                                    <div style="font-size: 1.1rem; color: var(--neon-cyan); margin-bottom: 0.5rem;">
                                        <i class="fas fa-rocket" style="margin-right: 0.5rem; color: var(--neon-green);"></i>
                                        Register as a provider now to get <strong style="color: var(--neon-green);">1000 $LAB</strong>!
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

// Load treasury administration data
async function loadTreasuryAdminData() {
    try {
        const data = await API.getTreasuryInfo();
        
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
            const limitTokens = (parseFloat(data.userLimit) / 1e6).toFixed(2);
            document.getElementById('currentUserLimit').textContent = `${limitTokens} LAB`;
            
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
        console.error('Failed to load treasury data:', error);
        
        // On error, show "--" (likely wallet not configured)
        document.getElementById('currentUserLimit').textContent = '--';
        document.getElementById('currentPeriod').textContent = '--';
        document.getElementById('periodStartDateTop').textContent = '--';
        document.getElementById('periodEndDateTop').textContent = '--';
    }
}

// Load recent transactions
async function loadRecentTransactions() {
    try {
        const data = await API.getRecentTransactions(10);
        
        const container = document.getElementById('transactionsContainer');
        
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
        } else {
            container.innerHTML = `
                <div class="no-data">
                    <span class="icon">?</span>
                    <p>No transactions recorded yet</p>
                    <small>${data.note || 'Execute an admin operation or institutional reservation to populate this list.'}</small>
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
        loadTreasuryAdminData(),
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
            showToast('Please enter a valid limit in LAB tokens', 'error');
            return;
        }
        
        // Convert LAB tokens to raw amount (6 decimals)
        const limitRaw = (parseFloat(limitTokens) * 1e6).toString();
        
        try {
            const result = await API.setUserLimit(limitRaw);
            if (result.success) {
                showToast(`Limit updated successfully. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('userLimitInput').value = '';
                setTimeout(() => loadTreasuryAdminData(), 5000); // Reload after 5 seconds
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
                setTimeout(() => loadTreasuryAdminData(), 5000);
            } else {
                showToast('Failed to update period: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error updating period: ' + error.message, 'error');
        }
    });
    
    // Treasury deposit button
    document.getElementById('depositBtn').addEventListener('click', async () => {
        const amountTokens = document.getElementById('treasuryAmount').value.trim();
        
        if (!amountTokens || isNaN(amountTokens)) {
            showToast('Please enter a valid amount in LAB tokens', 'error');
            return;
        }
        
        // Convert LAB tokens to raw amount (6 decimals)
        const amountRaw = (parseFloat(amountTokens) * 1e6).toString();
        
        if (!confirm(`Deposit ${amountTokens} LAB tokens to treasury?`)) {
            return;
        }
        
        try {
            const result = await API.depositTreasury(amountRaw);
            if (result.success) {
                showToast(`Deposit successful. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('treasuryAmount').value = '';
                setTimeout(() => {
                    loadBalances();
                    loadTreasuryAdminData();
                }, 5000);
            } else {
                showToast('Deposit failed: ' + result.message, 'error');
            }
        } catch (error) {
            showToast('Error depositing: ' + error.message, 'error');
        }
    });
    
    // Treasury withdraw button
    document.getElementById('withdrawBtn').addEventListener('click', async () => {
        const amountTokens = document.getElementById('treasuryAmount').value.trim();
        
        if (!amountTokens || isNaN(amountTokens)) {
            showToast('Please enter a valid amount in LAB tokens', 'error');
            return;
        }
        
        // Convert LAB tokens to raw amount (6 decimals)
        const amountRaw = (parseFloat(amountTokens) * 1e6).toString();
        
        if (!confirm(`⚠️ Withdraw ${amountTokens} LAB tokens from treasury? This action cannot be undone.`)) {
            return;
        }
        
        try {
            const result = await API.withdrawTreasury(amountRaw);
            if (result.success) {
                showToast(`Withdrawal successful. Tx: ${formatAddress(result.transactionHash)}`, 'success');
                document.getElementById('treasuryAmount').value = '';
                setTimeout(() => {
                    loadBalances();
                    loadTreasuryAdminData();
                }, 5000);
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
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshAllData);
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
                setTimeout(() => loadTreasuryAdminData(), 5000);
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
                
                const data = await response.json();
                if (data.success && data.address) {
                    showToast('✓ Wallet created and configured successfully!', 'success');
                    
                    // Format success message with HTML
                    const content = `
                        <div class="info-line">
                            <span class="info-label">Status:</span>
                            <span class="info-value">Wallet Created Successfully</span>
                        </div>
                        <div class="info-line">
                            <span class="info-label">Address:</span>
                            <span class="info-value">${data.address}</span>
                        </div>
                        <div class="warning-text">
                            <i class="fas fa-exclamation-triangle"></i>
                            <strong>Important:</strong> Make sure to backup your wallet securely. 
                            The dashboard will now refresh to show your new wallet.
                        </div>
                    `;
                    
                    await showInfoModal('Institutional Wallet Created', content, true);
                    
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
                
                const data = await response.json();
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

