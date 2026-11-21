(() => {
    const core = window.WalletDashboardCore;
    if (!core || !core.api) {
        throw new Error('Wallet Dashboard core must load before institution wallet operations.');
    }

    const {
        api: API,
        state: DashboardState,
        formatAddress,
        rawToBigInt,
        refreshAllData,
        renderSafeModalContent,
        setModalTitle,
        showInputModal,
        showPrivateKeyModal,
        showToast,
        updateLastRefreshTime,
        updateRoleBasedSections
    } = core;
    function updateDashboardAccessNotices(status) {
        const badge = document.getElementById('dashboardAccessBadge');
        const footer = document.getElementById('dashboardSecurityNotice');
        if (!badge || !footer || !status) {
            return;
        }

        const localOnly = status.dashboardLocalOnly !== false;
        const privateEnabled = status.allowPrivateNetworks === true && status.dashboardAllowPrivate === true;
        const configuredCidrs = Array.isArray(status.dashboardAllowedCidrs) ? status.dashboardAllowedCidrs : [];

        if (localOnly && !status.allowPrivateNetworks) {
            badge.textContent = 'Localhost Only';
            footer.textContent = 'This dashboard is only accessible from localhost.';
        } else if (localOnly && privateEnabled && configuredCidrs.length > 0) {
            badge.textContent = 'Private CIDR Allowlist';
            footer.textContent = `Private access limited to: ${configuredCidrs.join(', ')}.`;
        } else if (localOnly && privateEnabled) {
            badge.textContent = 'Any Private Network';
            footer.textContent = 'Private-network access is enabled for any private range with the admin access token.';
        } else if (!localOnly) {
            badge.textContent = 'External Access Allowed';
            footer.textContent = 'This dashboard may be accessible externally; enforce firewall or proxy restrictions.';
        } else {
            badge.textContent = 'Localhost Only';
            footer.textContent = 'This dashboard is only accessible from localhost.';
        }
    }

    function updateDashboardAccessError(statusCode) {
        const badge = document.getElementById('dashboardAccessBadge');
        const footer = document.getElementById('dashboardSecurityNotice');
        if (!badge || !footer) {
            return;
        }

        if (statusCode === 401) {
            badge.textContent = 'Access Policy Requires Token';
            footer.textContent = 'Enter the Gateway administrator token to load dashboard access policy.';
        } else if (statusCode === 403) {
            badge.textContent = 'Access Policy Blocked';
            footer.textContent = 'This network is blocked by the dashboard access policy.';
        } else {
            badge.textContent = 'Access Policy Unavailable';
            footer.textContent = 'Dashboard access policy could not be loaded.';
        }
    }

    function updateOperatingModeNotices(providerConfig) {
        const welcomeInstruction = document.getElementById('welcomePairingInstruction');
        const welcomeHelp = document.getElementById('welcomePairingHelp');

        const configuredMode = providerConfig && providerConfig.operatingMode;
        const operatingMode = configuredMode === 'provider-consumer' || configuredMode === 'consumer-only'
            ? configuredMode
            : 'unknown';
        const providerMode = operatingMode === 'provider-consumer';

        DashboardState.operatingMode = operatingMode;
        DashboardState.providerRegistrationEnabled = providerConfig && providerConfig.providerRegistrationEnabled === true;
        DashboardState.registrationRole = providerConfig && providerConfig.registrationRole
            ? providerConfig.registrationRole
            : null;

        const badge = document.getElementById('operatingModeBadge');
        if (badge) {
            badge.textContent = providerMode
                ? 'Provider + Consumer Mode'
                : operatingMode === 'consumer-only'
                    ? 'Consumer-Only Mode'
                    : 'Backend Mode Unavailable';
        }

        if (welcomeInstruction) {
            welcomeInstruction.innerHTML = providerMode
                ? '<strong>Register this backend</strong> with your institution.'
                : operatingMode === 'consumer-only'
                    ? '<strong>Register this consumer backend</strong> with your institution.'
                    : '<strong>Backend role unavailable</strong>';
        }

        if (welcomeHelp) {
            welcomeHelp.textContent = operatingMode === 'unknown'
                ? 'The backend role could not be loaded. Reload the dashboard before applying a provisioning token.'
                : 'If a DecentraLabs administrator gave you a provisioning token, apply it below. Otherwise open backend pairing setup; that page explains the pairing challenge flow and links to the Marketplace.';
        }

        updateInstitutionPairingGuidance(providerConfig);
        updateRoleBasedSections();
    }

    async function loadDashboardSystemStatus(providerConfig) {
        try {
            return await API.getSystemStatus();
        } catch (error) {
            const providerMode = providerConfig?.operatingMode === 'provider-consumer';
            const requiresStandaloneToken = providerMode && (error.status === 401 || error.status === 403);
            if (!requiresStandaloneToken) throw error;

            const token = await showInputModal(
                'Provider dashboard access',
                'Enter the backend ADMIN_ACCESS_TOKEN. It stays in memory for this page and is sent only to this backend.',
                'password'
            );
            if (!token) throw error;

            API.setAdminAccessToken(token);
            try {
                return await API.getSystemStatus();
            } catch (retryError) {
                API.clearAdminAccessToken();
                throw retryError;
            }
        }
    }

    function updateInstitutionPairingGuidance(providerConfig) {
        const section = document.getElementById('institutionPairingSection');
        const status = document.getElementById('institutionPairingStatus');
        const help = document.getElementById('institutionPairingHelp');
        if (!section) return;

        const registered = providerConfig && (
            providerConfig.registered === true || providerConfig.isRegistered === true
        );
        DashboardState.institutionRegistered = Boolean(registered);

        if (status) {
            status.textContent = registered
                ? `Paired${providerConfig.registrationRole ? ` as ${providerConfig.registrationRole.toLowerCase()}` : ''}`
                : 'Pairing required';
            status.classList.toggle('registered', Boolean(registered));
        }

        if (help && providerConfig?.operatingMode === 'consumer-only') {
            help.textContent = 'This deployment is consumer-only. Pair it with the Marketplace to finance reservations and access for your institution.';
        }

        section.classList.toggle('hidden', !DashboardState.walletAddress || Boolean(registered));
        updateInstitutionPairingButtonVisibility();
    }

    function updateInstitutionPairingButtonVisibility() {
        const headerBtn = document.getElementById('openInstitutionConfigHeaderBtn');
        if (headerBtn) {
            const shouldShow = DashboardState.walletAddress && !DashboardState.institutionRegistered;
            headerBtn.style.display = shouldShow ? 'inline-flex' : 'none';
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
        if (typeof url !== 'string' || !url.trim()) return;
        DashboardState.marketplaceUrl = url;
        document.querySelectorAll('[data-marketplace-link]').forEach((link) => {
            link.href = url;
        });
    }

    function setProvisioningTokenStatus(message, tone = '') {
        const status = document.getElementById('provisioningTokenStatus');
        if (!status) return;
        status.textContent = message || '';
        status.className = 'provisioning-token-status';
        if (tone) {
            status.classList.add(tone);
        }
    }

    function isProvisioningTokenShapeValid(token) {
        return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);
    }

    async function applyProvisioningToken(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const input = document.getElementById('provisioningTokenInput');
        const submitButton = document.getElementById('applyProvisioningTokenBtn');
        if (!input || !submitButton) return;

        const token = input.value.trim();
        if (!token) {
            setProvisioningTokenStatus('Paste the provisioning token first.', 'error');
            input.focus();
            return;
        }
        if (!isProvisioningTokenShapeValid(token)) {
            setProvisioningTokenStatus('Invalid token format. Paste the complete provisioning token.', 'error');
            input.focus();
            return;
        }

        submitButton.disabled = true;
        submitButton.setAttribute('aria-busy', 'true');
        setProvisioningTokenStatus('Applying provisioning token...', 'pending');

        try {
            const data = await API.applyProvisioningToken(token, DashboardState.operatingMode);
            if (!data.success || data.registered !== true) {
                throw new Error(data.error || 'The provisioning token was not registered completely.');
            }

            DashboardState.institutionRegistered = true;
            setProvisioningTokenStatus('Institution registered successfully.', 'success');
            showToast('Institution registered successfully.', 'success');
            hideWelcomeModal(true);
            form.reset();
            await loadSystemStatus();
        } catch (error) {
            setProvisioningTokenStatus(error.message || 'Failed to apply provisioning token.', 'error');
            showToast(`Provisioning failed: ${error.message}`, 'error');
        } finally {
            input.value = '';
            submitButton.disabled = false;
            submitButton.setAttribute('aria-busy', 'false');
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
            console.log('[loadSystemStatus] Calling API.getProviderConfigStatus()...');
            const providerConfig = await API.getProviderConfigStatus().catch(error => {
                console.warn('[loadSystemStatus] provider config status unavailable', error);
                return null;
            });
            updateOperatingModeNotices(providerConfig);

            console.log('[loadSystemStatus] Calling API.getSystemStatus()...');
            const data = await loadDashboardSystemStatus(providerConfig);
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
                DashboardState.walletAddress = walletAddress || null;
                DashboardState.contractAddress = contractAddress;

                if (DashboardState.walletAddress) {
                    const registrationApplied = providerConfig && (providerConfig.registered === true || providerConfig.isRegistered === true);

                    DashboardState.institutionRegistered = Boolean(registrationApplied);
                } else {
                    DashboardState.institutionRegistered = false;
                    DashboardState.contractAddress = null;
                }

                // Update marketplace URL if provided
                if (data.marketplaceUrl) {
                    updateMarketplaceUrl(data.marketplaceUrl);
                } else if (providerConfig && providerConfig.marketplaceBaseUrl) {
                    updateMarketplaceUrl(providerConfig.marketplaceBaseUrl);
                }

                updateInstitutionPairingGuidance(providerConfig);
                updateInstitutionPairingButtonVisibility();

                // Show welcome modal while pairing is still required
                const shouldPromptPairing = !!walletAddress && !DashboardState.institutionRegistered;
                if (shouldPromptPairing && !DashboardState.welcomeModalDismissed) {
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
            DashboardState.institutionRegistered = false;
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
            updateDashboardAccessError(error.status);
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


    window.WalletDashboardInstitutionWallet = Object.freeze({
        applyProvisioningToken,
        handleRevealPrivateKey,
        loadSystemStatus,
        switchNetwork
    });
})();
