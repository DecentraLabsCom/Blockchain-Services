(() => {
    const core = window.WalletDashboardCore;
    if (!core || !core.api) {
        throw new Error('Wallet Dashboard core must load before provider settlement.');
    }

    const {
        state: DashboardState,
        api: API,
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
    } = core;

    function loadCollectLabNameCache() {
        DashboardState.collectLabNames = {};
    }

    function persistCollectLabNameCache() {
        // Lab labels are a presentation cache and remain in memory only.
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

    function setCollectStatusText(message, tone = null, tooltip = null) {
        const statusEl = document.getElementById('collectStatusText');
        if (!statusEl) return;
        statusEl.textContent = message || '--';
        statusEl.title = tooltip || '';
        if (tooltip) {
            statusEl.setAttribute('aria-label', tooltip);
        } else {
            statusEl.removeAttribute('aria-label');
        }
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
        return DashboardState.operatingMode === 'provider-consumer'
            && Boolean(DashboardState.walletAddress)
            && (DashboardState.isProvider || DashboardState.isOperator);
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
        const closuresEl = document.getElementById('collectPendingGraceReservations');
        if (!closuresEl) return;
        closuresEl.textContent = value ?? '--';
    }

    function setCollectPreviewMetrics(data) {
        const amountMetrics = [
            ['collectAttestedSessionPayout', data?.attestedSessionPayoutRaw, data?.attestedSessionPayoutLab],
            ['collectPotentialNoShowFee', data?.potentialNoShowFeeRaw, data?.potentialNoShowFeeLab],
            ['collectExistingAccrued', data?.existingAccruedReceivableRaw, data?.existingAccruedReceivableLab]
        ];

        amountMetrics.forEach(([id, rawValue, formattedValue]) => {
            const element = document.getElementById(id);
            if (!element) return;
            if (rawValue === undefined || rawValue === null || rawValue === '') {
                element.textContent = '--';
                return;
            }
            element.textContent = `${formattedValue || formatLabTokenRaw(rawValue)} credits`;
        });

        setCollectPendingClosuresText(data?.pendingGraceReservationCount ?? '--');
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
            formatLifecycleBucket('Attested session payout', data.attestedSessionPayoutRaw, data.attestedSessionPayoutLab),
            formatLifecycleBucket('Potential no-show fee', data.potentialNoShowFeeRaw, data.potentialNoShowFeeLab),
            formatLifecycleBucket('Already accrued', data.existingAccruedReceivableRaw, data.existingAccruedReceivableLab),
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

        try {
            const attestedPayoutText = document.getElementById('collectAttestedSessionPayout')?.textContent || '0';
            const noShowFeeText = document.getElementById('collectPotentialNoShowFee')?.textContent || '0';
            const attestedPayout = BigInt(decimalToRawUnits(attestedPayoutText.replace(/\s*credits\s*$/i, '').trim() || '0', CREDIT_DECIMALS));
            const noShowFee = BigInt(decimalToRawUnits(noShowFeeText.replace(/\s*credits\s*$/i, '').trim() || '0', CREDIT_DECIMALS));

            if (attestedPayout > 0n && noShowFee > 0n) {
                buttonLabel = 'Claim Sessions + No-show Fees';
            } else if (attestedPayout > 0n) {
                buttonLabel = 'Claim Attested Sessions';
            } else if (noShowFee > 0n) {
                buttonLabel = 'Claim No-show Fees';
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

    function getLabSettlementBuckets(lab) {
        const pending = rawToBigInt(lab?.accruedReceivableRaw);
        const attestedSessionPayout = rawToBigInt(lab?.attestedSessionPayoutRaw);
        const potentialNoShowFee = rawToBigInt(lab?.potentialNoShowFeeRaw);
        const existingAccruedReceivable = rawToBigInt(lab?.existingAccruedReceivableRaw);
        const queued = rawToBigInt(lab?.settlementQueuedRaw);
        const invoiced = rawToBigInt(lab?.invoicedReceivableRaw);
        const approved = rawToBigInt(lab?.approvedReceivableRaw);
        const received = rawToBigInt(lab?.paidReceivableRaw);
        const disputed = rawToBigInt(lab?.disputedReceivableRaw);
        const reversed = rawToBigInt(lab?.reversedReceivableRaw);

        return {
            pending,
            previewPending: pending + attestedSessionPayout + potentialNoShowFee,
            attestedSessionPayout,
            potentialNoShowFee,
            existingAccruedReceivable,
            claimed: queued + invoiced + approved,
            received,
            disputed,
            reversed,
            pendingClosures: rawToBigInt(lab?.pendingGraceReservationCount)
        };
    }

    function computeCollectAggregates(labs) {
        const totals = {
            pending: 0n,
            previewPending: 0n,
            attestedSessionPayout: 0n,
            potentialNoShowFee: 0n,
            existingAccruedReceivable: 0n,
            claimed: 0n,
            received: 0n,
            disputed: 0n,
            reversed: 0n,
            pendingClosures: 0n
        };

        (Array.isArray(labs) ? labs : []).forEach(lab => {
            const buckets = getLabSettlementBuckets(lab);
            totals.pending += buckets.pending;
            totals.previewPending += buckets.previewPending;
            totals.attestedSessionPayout += buckets.attestedSessionPayout;
            totals.potentialNoShowFee += buckets.potentialNoShowFee;
            totals.existingAccruedReceivable += buckets.existingAccruedReceivable;
            totals.claimed += buckets.claimed;
            totals.received += buckets.received;
            totals.disputed += buckets.disputed;
            totals.reversed += buckets.reversed;
            totals.pendingClosures += buckets.pendingClosures;
        });

        return totals;
    }

    function parseCollectSummary(summary) {
        if (!summary || typeof summary !== 'object') {
            return null;
        }
        return {
            pending: rawToBigInt(summary.pendingRaw),
            previewPending: rawToBigInt(summary.attestedSessionPayoutRaw)
                + rawToBigInt(summary.potentialNoShowFeeRaw)
                + rawToBigInt(summary.pendingRaw),
            attestedSessionPayout: rawToBigInt(summary.attestedSessionPayoutRaw),
            potentialNoShowFee: rawToBigInt(summary.potentialNoShowFeeRaw),
            existingAccruedReceivable: rawToBigInt(summary.existingAccruedReceivableRaw),
            claimed: rawToBigInt(summary.claimedRaw),
            received: rawToBigInt(summary.receivedRaw),
            disputed: rawToBigInt(summary.disputedRaw),
            reversed: rawToBigInt(summary.reversedRaw),
            pendingClosures: rawToBigInt(summary.pendingGraceReservationCount ?? summary.pendingClosures)
        };
    }

    function formatSettlementRiskValue(disputedRaw, reversedRaw) {
        const disputed = formatLabTokenRaw(disputedRaw);
        const reversed = formatLabTokenRaw(reversedRaw);
        return `${disputed} / ${reversed} credits`;
    }

    function getSettlementRowStatus(lab) {
        const buckets = getLabSettlementBuckets(lab);
        if (buckets.previewPending > 0n) {
            return { label: 'Pending claim', tone: 'ready' };
        }
        if (buckets.claimed > 0n) {
            return { label: 'In process', tone: 'progress' };
        }
        if (buckets.disputed > 0n || buckets.reversed > 0n) {
            return { label: 'Needs review', tone: 'caution' };
        }
        if (buckets.received > 0n) {
            return { label: 'Settled', tone: 'idle' };
        }
        return { label: 'No receivable', tone: 'idle' };
    }

    function renderCollectSettlementOverview() {
        const overviewEl = document.getElementById('providerSettlementOverview');
        const noteEl = document.getElementById('providerSettlementOverviewNote');
        const loadMoreBtn = document.getElementById('providerSettlementLoadMoreBtn');
        const pendingEl = document.getElementById('settlementSummaryPending');
        const claimedEl = document.getElementById('settlementSummaryClaimed');
        const receivedEl = document.getElementById('settlementSummaryReceived');
        const riskEl = document.getElementById('settlementSummaryRisk');
        const tableBody = document.getElementById('providerSettlementLabsTableBody');

        if (!overviewEl || !pendingEl || !claimedEl || !receivedEl || !riskEl || !tableBody) {
            return;
        }

        const labs = Array.isArray(DashboardState.collectLabs) ? DashboardState.collectLabs : [];
        const shouldShow = DashboardState.operatingMode === 'provider-consumer'
            && labs.length > 0
            && (DashboardState.isProvider || DashboardState.isOperator);
        overviewEl.classList.toggle('hidden', !shouldShow);

        if (!shouldShow) {
            tableBody.innerHTML = '<tr><td colspan="6" class="settlement-table-empty">No settlement data available.</td></tr>';
            if (loadMoreBtn) {
                loadMoreBtn.classList.add('hidden');
            }
            return;
        }

        const totals = DashboardState.collectAggregates || computeCollectAggregates(labs);
        DashboardState.collectAggregates = totals;
        pendingEl.textContent = `${formatLabTokenRaw(totals.previewPending)} credits`;
        claimedEl.textContent = `${formatLabTokenRaw(totals.claimed)} credits`;
        receivedEl.textContent = `${formatLabTokenRaw(totals.received)} credits`;
        riskEl.textContent = formatSettlementRiskValue(totals.disputed, totals.reversed);

        if (noteEl) {
            const scope = DashboardState.collectTotalLabs > labs.length
                ? 'Summary is cached across all visible labs.'
                : 'Summary loaded from the current lab list.';
            noteEl.textContent = `${scope} Detailed status is fetched only for the selected lab. Potential no-show fees: ${formatLabTokenRaw(totals.potentialNoShowFee)} credits; grace pending: ${totals.pendingClosures.toString()}.`;
        }
        if (loadMoreBtn) {
            loadMoreBtn.classList.toggle('hidden', DashboardState.collectHasMore !== true);
            loadMoreBtn.disabled = DashboardState.collectLoadingStatus;
        }

        tableBody.innerHTML = labs.map(lab => {
            const buckets = getLabSettlementBuckets(lab);
            const status = getSettlementRowStatus(lab);
            const labId = String(lab.labId || '');
            const isSelected = String(DashboardState.selectedCollectLabId || '') === labId;
            const pending = `${formatLabTokenRaw(buckets.previewPending)} credits`;
            const claimed = `${formatLabTokenRaw(buckets.claimed)} credits`;
            const received = `${formatLabTokenRaw(buckets.received)} credits`;
            const name = lab.name || lab.label || `Lab #${labId}`;
            const closures = buckets.pendingClosures.toString();
            const rowTitle = lab.operatorReviewOnly ? 'Operator review only' : 'Click to inspect this lab';

            return `
                <tr data-lab-id="${escapeHtml(labId)}" class="${isSelected ? 'selected' : ''}" title="${escapeHtml(rowTitle)}">
                    <td class="settlement-lab-name">${escapeHtml(name)}</td>
                    <td>${escapeHtml(pending)}</td>
                    <td>${escapeHtml(claimed)}</td>
                    <td>${escapeHtml(received)}</td>
                    <td>${escapeHtml(closures)}</td>
                    <td><span class="settlement-status-chip ${escapeHtml(status.tone)}">${escapeHtml(status.label)}</span></td>
                </tr>
            `;
        }).join('');
    }

    function providerIncomeRawAmount(row, field) {
        const rawValue = String(row[`${field}Raw`] ?? '');
        if (/^\d+$/.test(rawValue)) return BigInt(rawValue);

        const displayValue = String(row[field] ?? '0');
        const match = displayValue.match(/^(\d+)(?:\.(\d{0,7}))?$/);
        if (!match) return 0n;
        const fractional = (match[2] || '').padEnd(7, '0');
        return BigInt(match[1]) * 10000000n + BigInt(fractional || '0');
    }

    function formatProviderIncomeRawAmount(rawAmount) {
        const whole = rawAmount / 10000000n;
        const fractional = (rawAmount % 10000000n).toString().padStart(7, '0');
        return `${whole}.${fractional}`;
    }

    function summarizeProviderIncomeByGateway(rows) {
        const amountFields = ['potentialProviderShare', 'accrued', 'unbatched', 'queued', 'inProcess', 'paid'];
        const groups = new Map();

        rows.forEach(row => {
            const gatewayId = row.gatewayId || '__unassigned__';
            const departmentName = String(row.departmentName || '').trim();
            const groupKey = departmentName
                ? `department:${departmentName.toLowerCase()}`
                : `gateway:${gatewayId}`;
            let summary = groups.get(groupKey);
            if (!summary) {
                summary = {
                    groupKey,
                    gatewayLabel: departmentName || row.gatewayLabel || 'Gateway unassigned',
                    gatewayIds: new Set(),
                    accessUris: new Set(),
                    labIds: new Set(),
                    confirmedReservations: 0,
                    amounts: Object.fromEntries(amountFields.map(field => [field, 0n]))
                };
                groups.set(groupKey, summary);
            }

            if (row.gatewayId) summary.gatewayIds.add(String(row.gatewayId));
            if (row.accessUri) summary.accessUris.add(String(row.accessUri));
            summary.labIds.add(row.labId ? String(row.labId) : 'unknown');
            summary.confirmedReservations += Number(row.confirmedReservations || 0);
            amountFields.forEach(field => {
                summary.amounts[field] += providerIncomeRawAmount(row, field);
            });
        });

        return Array.from(groups.values()).sort((left, right) =>
            left.gatewayLabel.localeCompare(right.gatewayLabel)
        );
    }

    function summarizeProviderIncomeInstitution(departmentRows) {
        const amountFields = ['potentialProviderShare', 'accrued', 'unbatched', 'queued', 'inProcess', 'paid'];
        const summary = {
            gatewayIds: new Set(),
            labIds: new Set(),
            confirmedReservations: 0,
            amounts: Object.fromEntries(amountFields.map(field => [field, 0n]))
        };

        departmentRows.forEach(department => {
            department.gatewayIds.forEach(gatewayId => summary.gatewayIds.add(gatewayId));
            department.labIds.forEach(labId => summary.labIds.add(labId));
            summary.confirmedReservations += department.confirmedReservations;
            amountFields.forEach(field => {
                summary.amounts[field] += department.amounts[field];
            });
        });
        summary.departmentCount = departmentRows.length;
        return summary;
    }

    function getProviderIncomeLabName(labId) {
        const normalizedLabId = String(labId || '').trim();
        if (!normalizedLabId) return '';

        const lab = (DashboardState.collectLabs || []).find(
            item => String(item.labId || '').trim() === normalizedLabId
        );
        const name = String(
            lab?.name || lab?.label || DashboardState.collectLabNames?.[normalizedLabId] || ''
        ).trim();
        return name && !isFallbackLabLabel(name, normalizedLabId) ? name : '';
    }

    function renderProviderIncomeReport() {
        const tableBody = document.getElementById('providerIncomeReportBody');
        const departmentBody = document.getElementById('providerIncomeGatewayReportBody');
        const institutionBody = document.getElementById('providerIncomeInstitutionReportBody');
        const noteEl = document.getElementById('providerIncomeReportNote');
        const exportButton = document.getElementById('providerIncomeExportBtn');
        if (!tableBody || !departmentBody || !institutionBody || !noteEl || !exportButton) return;

        const report = DashboardState.providerIncomeReport;
        const rows = report && Array.isArray(report.rows) ? report.rows : [];
        if (!report) {
            institutionBody.innerHTML = '<tr><td colspan="10" class="settlement-table-empty">Institution income is unavailable.</td></tr>';
            departmentBody.innerHTML = '<tr><td colspan="10" class="settlement-table-empty">Provider income history is unavailable.</td></tr>';
            tableBody.innerHTML = '<tr><td colspan="10" class="settlement-table-empty">Provider income history is unavailable.</td></tr>';
            exportButton.disabled = true;
            noteEl.textContent = DashboardState.providerIncomeReportError
                ? `Provider income report unavailable: ${DashboardState.providerIncomeReportError}`
                : 'The report needs durable database storage and canonical contract event history.';
            return;
        }

        const unresolvedCount = Number(report.unresolvedBatchCount || 0);
        const scopeMismatches = Number(report.scopeReferenceMismatchCount || 0);
        const trackingStart = report.trackingStartBlock || 'recent lookback';
        const providerWallet = report.providerAddress ? `Provider wallet: ${report.providerAddress}. ` : '';
        noteEl.textContent = `${providerWallet}Amounts are service credits. Event tracking starts at ${trackingStart}; first observed confirmation: ${report.firstObservedConfirmationBlock || 'none'}. Paid externally means a payment proof was recorded. ${unresolvedCount} batch(es) for these labs need source reconciliation (${report.unresolvedBatchAmount || '0.0000000'} credits); ${scopeMismatches} claim scope reference(s) do not match a recorded batch.`;
        exportButton.disabled = rows.length === 0;
        exportButton.onclick = downloadProviderIncomeReportCsv;

        const departmentRows = summarizeProviderIncomeByGateway(rows);
        const institution = summarizeProviderIncomeInstitution(departmentRows);
        institutionBody.innerHTML = `
            <tr>
                <td>Institution (${escapeHtml(String(institution.departmentCount))} department/group(s))</td>
                <td>${escapeHtml(String(institution.gatewayIds.size))}</td>
                <td>${escapeHtml(String(institution.labIds.size))}</td>
                <td>${escapeHtml(String(institution.confirmedReservations))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(institution.amounts.potentialProviderShare))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(institution.amounts.accrued))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(institution.amounts.unbatched))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(institution.amounts.queued))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(institution.amounts.inProcess))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(institution.amounts.paid))}</td>
            </tr>
        `;

        if (!rows.length) {
            departmentBody.innerHTML = '<tr><td colspan="10" class="settlement-table-empty">No provider income events have been indexed for this wallet during the reported coverage period.</td></tr>';
            tableBody.innerHTML = '<tr><td colspan="10" class="settlement-table-empty">No provider income events have been indexed for this wallet during the reported coverage period.</td></tr>';
            return;
        }

        departmentBody.innerHTML = departmentRows.map(department => `
            <tr>
                <td title="${escapeHtml([...department.gatewayIds, ...department.accessUris].join(', '))}">${escapeHtml(department.gatewayLabel)}</td>
                <td>${escapeHtml(String(department.gatewayIds.size))}</td>
                <td>${escapeHtml(String(department.labIds.size))}</td>
                <td>${escapeHtml(String(department.confirmedReservations))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(department.amounts.potentialProviderShare))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(department.amounts.accrued))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(department.amounts.unbatched))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(department.amounts.queued))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(department.amounts.inProcess))}</td>
                <td>${escapeHtml(formatProviderIncomeRawAmount(department.amounts.paid))}</td>
            </tr>
        `).join('');

        tableBody.innerHTML = rows.map(row => {
            const labId = String(row.labId || '').trim();
            const labName = String(row.labName || getProviderIncomeLabName(labId)).trim();
            const labLabel = labId ? `#${labId}` : 'Unknown lab';
            const labTooltip = labName || (labId ? `Lab #${labId}` : 'Unknown lab');
            return `
                <tr>
                    <td>${escapeHtml(row.gatewayLabel || 'Gateway unassigned')}</td>
                    <td>${escapeHtml(row.gatewayId || '')}</td>
                    <td title="${escapeHtml(labTooltip)}">${escapeHtml(labLabel)}</td>
                    <td>${escapeHtml(String(row.confirmedReservations || 0))}</td>
                    <td>${escapeHtml(row.potentialProviderShare || '0.0000000')}</td>
                    <td>${escapeHtml(row.accrued || '0.0000000')}</td>
                    <td>${escapeHtml(row.unbatched || '0.0000000')}</td>
                    <td>${escapeHtml(row.queued || '0.0000000')}</td>
                    <td>${escapeHtml(row.inProcess || '0.0000000')}</td>
                    <td>${escapeHtml(row.paid || '0.0000000')}</td>
                </tr>
            `;
        }).join('');
    }

    function downloadProviderIncomeReportCsv() {
        const report = DashboardState.providerIncomeReport;
        const rows = report && Array.isArray(report.rows) ? report.rows : [];
        if (!rows.length) return;
        const headers = [
            'gatewayId', 'departmentName', 'accessUri', 'labId', 'confirmedReservations', 'potentialProviderShareCredits',
            'accruedCredits', 'unbatchedCredits', 'queuedCredits', 'inProcessCredits', 'paidExternallyCredits',
            'invalidatedCredits'
        ];
        const values = rows.map(row => [
            row.gatewayId || '', row.departmentName || '', row.accessUri || '', row.labId || '', row.confirmedReservations || 0,
            row.potentialProviderShare || '0.0000000', row.accrued || '0.0000000', row.unbatched || '0.0000000',
            row.queued || '0.0000000', row.inProcess || '0.0000000', row.paid || '0.0000000',
            row.invalidated || '0.0000000'
        ]);
        const csvCell = value => {
            let text = String(value);
            if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
            return `"${text.replaceAll('"', '""')}"`;
        };
        const csv = [headers, ...values].map(row => row.map(csvCell).join(',')).join('\r\n');
        const objectUrl = URL.createObjectURL(new Blob([`\ufeff${csv}`], { type: 'text/csv;charset=utf-8' }));
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = `provider-income-${new Date().toISOString().slice(0, 10)}.csv`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    }

    async function loadProviderIncomeReport() {
        if (DashboardState.operatingMode !== 'provider-consumer'
            || (!DashboardState.isProvider && !DashboardState.isOperator)) {
            DashboardState.providerIncomeReport = null;
            DashboardState.providerIncomeReportError = null;
            renderProviderIncomeReport();
            return;
        }
        try {
            const report = await API.getProviderIncomeReport();
            if (!report || report.success !== true) throw new Error(report && report.error || 'Report unavailable');
            DashboardState.providerIncomeReport = report;
            DashboardState.providerIncomeReportError = null;
        } catch (error) {
            DashboardState.providerIncomeReport = null;
            DashboardState.providerIncomeReportError = error.message;
        }
        renderProviderIncomeReport();
    }

    function renderProviderGatewayDepartments() {
        const tableBody = document.getElementById('providerGatewayDepartmentsBody');
        const noteEl = document.getElementById('providerGatewayDepartmentsNote');
        if (!tableBody || !noteEl) return;

        if (DashboardState.providerGatewayDepartmentsError) {
            noteEl.textContent = `Gateway department list unavailable: ${DashboardState.providerGatewayDepartmentsError}`;
            tableBody.innerHTML = `<tr><td colspan="4" class="settlement-table-empty">${escapeHtml(DashboardState.providerGatewayDepartmentsError)}</td></tr>`;
            return;
        }

        const gateways = DashboardState.providerGatewayDepartments;
        noteEl.textContent = 'The list reflects Lite Gateways trusted by this provider backend. Saving a name changes report labels only; a blank name restores the Gateway ID.';
        if (!gateways.length) {
            tableBody.innerHTML = '<tr><td colspan="4" class="settlement-table-empty">No Lite Gateways are registered with this provider backend.</td></tr>';
            return;
        }

        tableBody.innerHTML = gateways.map(gateway => `
            <tr>
                <td>${escapeHtml(gateway.gatewayId)}</td>
                <td>${escapeHtml(gateway.accessUri)}</td>
                <td>
                    <input type="text" maxlength="120" class="gateway-department-name-input"
                        data-gateway-id="${escapeHtml(gateway.gatewayId)}"
                        aria-label="Department or group name for ${escapeHtml(gateway.gatewayId)}"
                        value="${escapeHtml(gateway.departmentName || '')}">
                </td>
                <td><button type="button" class="btn btn-primary btn-small gateway-department-save"
                    data-gateway-id="${escapeHtml(gateway.gatewayId)}">Save</button></td>
            </tr>
        `).join('');
    }

    async function loadProviderGatewayDepartments() {
        if (DashboardState.operatingMode !== 'provider-consumer' || !DashboardState.isOperator) {
            DashboardState.providerGatewayDepartments = [];
            DashboardState.providerGatewayDepartmentsError = null;
            renderProviderGatewayDepartments();
            return;
        }

        try {
            const response = await API.getProviderGatewayDepartments();
            if (!response || response.success !== true || !Array.isArray(response.gateways)) {
                throw new Error(response && response.error || 'Gateway list unavailable');
            }
            DashboardState.providerGatewayDepartments = response.gateways;
            DashboardState.providerGatewayDepartmentsError = null;
        } catch (error) {
            DashboardState.providerGatewayDepartments = [];
            DashboardState.providerGatewayDepartmentsError = error.message;
        }
        renderProviderGatewayDepartments();
    }

    function setupProviderGatewayDepartmentHandlers() {
        const refreshButton = document.getElementById('providerGatewayDepartmentsRefreshBtn');
        refreshButton?.addEventListener('click', loadProviderGatewayDepartments);

        const tableBody = document.getElementById('providerGatewayDepartmentsBody');
        tableBody?.addEventListener('click', async event => {
            const button = event.target.closest('[data-gateway-id].gateway-department-save');
            if (!button || button.disabled) return;
            const gatewayId = button.dataset.gatewayId;
            const input = button.closest('tr')?.querySelector('.gateway-department-name-input');
            if (!input) return;

            button.disabled = true;
            try {
                const response = await API.updateProviderGatewayDepartment(gatewayId, input.value.trim());
                if (!response || response.success !== true || !response.gateway) {
                    throw new Error(response && response.error || 'Unable to save department name');
                }
                DashboardState.providerGatewayDepartments = DashboardState.providerGatewayDepartments.map(gateway =>
                    gateway.gatewayId === response.gateway.gatewayId ? response.gateway : gateway
                );
                renderProviderGatewayDepartments();
                await loadProviderIncomeReport();
                showToast(response.gateway.departmentName
                    ? `Saved department name for ${gatewayId}`
                    : `Department name cleared for ${gatewayId}`, 'success');
            } catch (error) {
                button.disabled = false;
                showToast(`Unable to save department name: ${error.message}`, 'error');
            }
        });
    }

    async function loadCollectLabs() {
        const selectEl = document.getElementById('collectLabSelect');
        const pendingEl = document.getElementById('collectPendingTotal');
        if (!selectEl || !pendingEl) {
            return;
        }

        // Standalone consumer-only institutions do not own provider labs and must
        // not probe provider settlement endpoints on every dashboard refresh.
        if (DashboardState.operatingMode !== 'provider-consumer'
            || (!DashboardState.isProvider && !DashboardState.isOperator)) {
            DashboardState.collectLabs = [];
            DashboardState.selectedCollectLabId = null;
            DashboardState.collectAggregates = null;
            DashboardState.collectCanExecute = false;
            DashboardState.collectLoadingStatus = false;
            selectEl.disabled = true;
            selectEl.innerHTML = '<option value="">Provider settlement unavailable</option>';
            pendingEl.textContent = '--';
            setCollectPreviewMetrics(null);
            setCollectStatusText('Not applicable to this institution', 'info');
            setCollectPanelCompact(true);
            updateCollectDetailVisibility();
            renderCollectSettlementOverview();
            loadProviderIncomeReport();
            return;
        }

        loadCollectLabNameCache();
        clearCollectLabsRetryTimer();
        const previousLabs = Array.isArray(DashboardState.collectLabs)
            ? DashboardState.collectLabs.slice()
            : [];
        const previousSelection = DashboardState.selectedCollectLabId;

        DashboardState.collectOffset = 0;
        DashboardState.collectHasMore = false;
        DashboardState.collectTotalLabs = 0;
        DashboardState.collectLoadingStatus = true;
        DashboardState.collectCanExecute = false;
        DashboardState.collectAggregates = null;
        DashboardState.selectedCollectLabId = null;
        updateCollectDetailVisibility();
        updateCollectButtonState();
        renderCollectSettlementOverview();
        setCollectStatusText('Loading labs...');
        setCollectPanelCompact(false);
        pendingEl.textContent = '--';
        setCollectPreviewMetrics(null);
        selectEl.disabled = true;
        selectEl.innerHTML = '<option value="">Loading labs...</option>';

        try {
            const data = await API.getProviderLabs({
                offset: 0,
                limit: DashboardState.collectPageSize,
                includeSummary: true
            });
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
                    DashboardState.collectOffset = previousLabs.length;
                    DashboardState.collectHasMore = false;
                    DashboardState.collectTotalLabs = previousLabs.length;
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
                DashboardState.collectAggregates = null;
                selectEl.innerHTML = retryScheduled
                    ? '<option value="">Checking labs...</option>'
                    : '<option value="">No labs available</option>';
                pendingEl.textContent = '0 credits';
                setCollectPreviewMetrics(null);
                if (!retryScheduled) {
                    setCollectStatusText('Not available', 'warning');
                }
                setCollectPanelCompact(true);
                updateCollectDetailVisibility();
                renderCollectSettlementOverview();
                if (!retryScheduled) {
                    resetCollectLabsRetryState();
                }
                return;
            }

            resetCollectLabsRetryState();
            DashboardState.collectLabs = labs;
            DashboardState.collectOffset = labs.length;
            DashboardState.collectHasMore = data.hasMore === true;
            DashboardState.collectTotalLabs = Number.isFinite(Number(data.totalLabs)) ? Number(data.totalLabs) : labs.length;
            DashboardState.collectAggregates = parseCollectSummary(data.summary);
            DashboardState.selectedCollectLabId = renderCollectLabOptions(
                selectEl,
                labs,
                previousSelection
            );
            selectEl.disabled = false;
            setCollectPanelCompact(false);
            updateCollectDetailVisibility();
            renderCollectSettlementOverview();

            await loadCollectStatusForSelectedLab();
        } catch (error) {
            const retryScheduled = scheduleCollectLabsRetry(error);
            if (previousLabs.length) {
                DashboardState.collectLabs = previousLabs;
                DashboardState.collectOffset = previousLabs.length;
                DashboardState.collectHasMore = false;
                DashboardState.collectTotalLabs = previousLabs.length;
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
            DashboardState.collectOffset = 0;
            DashboardState.collectHasMore = false;
            DashboardState.collectTotalLabs = 0;
            DashboardState.collectAggregates = null;
            DashboardState.collectCanExecute = false;
            selectEl.innerHTML = '<option value="">Failed to load labs</option>';
            pendingEl.textContent = '--';
            setCollectPreviewMetrics(null);
            setCollectStatusText('Unavailable', 'error');
            setCollectPanelCompact(true);
            updateCollectDetailVisibility();
            renderCollectSettlementOverview();
            if (!retryScheduled) {
                resetCollectLabsRetryState();
            }
        } finally {
            DashboardState.collectLoadingStatus = false;
            updateCollectButtonState();
            loadProviderIncomeReport();
        }
    }

    async function loadMoreCollectLabs() {
        if (DashboardState.collectLoadingStatus || DashboardState.collectHasMore !== true) {
            return;
        }

        const selectEl = document.getElementById('collectLabSelect');
        if (!selectEl) {
            return;
        }

        const previousSelection = DashboardState.selectedCollectLabId;
        DashboardState.collectLoadingStatus = true;
        renderCollectSettlementOverview();

        try {
            const data = await API.getProviderLabs({
                offset: DashboardState.collectOffset,
                limit: DashboardState.collectPageSize,
                includeSummary: false
            });
            if (!data.success) {
                throw new Error(data.error || 'Failed to load additional labs');
            }

            const nextLabs = enrichCollectLabsWithCachedNames(Array.isArray(data.labs) ? data.labs : []);
            DashboardState.collectLabs = DashboardState.collectLabs.concat(nextLabs);
            DashboardState.collectOffset += nextLabs.length;
            DashboardState.collectHasMore = data.hasMore === true;
            DashboardState.collectTotalLabs = Number.isFinite(Number(data.totalLabs))
                ? Number(data.totalLabs)
                : DashboardState.collectLabs.length;
            DashboardState.selectedCollectLabId = renderCollectLabOptions(
                selectEl,
                DashboardState.collectLabs,
                previousSelection
            );
            renderCollectSettlementOverview();
        } catch (error) {
            showToast(`Failed to load more labs: ${error.message}`, 'error');
            renderCollectSettlementOverview();
        } finally {
            DashboardState.collectLoadingStatus = false;
            updateCollectButtonState();
            renderCollectSettlementOverview();
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
        renderCollectSettlementOverview();
        if (!selectedLabId) {
            DashboardState.collectCanExecute = false;
            pendingEl.textContent = '0 credits';
            setCollectPreviewMetrics(null);
            setCollectStatusText('Select a lab', 'warning');
            setCollectLifecycleSummaryText('');
            updateCollectButtonState();
            return;
        }

        DashboardState.collectLoadingStatus = true;
        DashboardState.collectCanExecute = false;
        updateCollectDetailVisibility();
        pendingEl.textContent = '--';
        setCollectPreviewMetrics(null);
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

            DashboardState.settlementLatestBatchId = data.latestSettlementBatchId || null;
            const batchInput = document.getElementById('providerSettlementBatchIdInput');
            if (batchInput && data.latestSettlementBatchId && !batchInput.value.trim()) {
                batchInput.value = data.latestSettlementBatchId;
            }
            const latestBatchAmountRaw = data.latestSettlementBatchRemainingRaw;
            const latestBatchAmountLab = data.latestSettlementBatchRemainingLab;
            const creditAmountInput = document.getElementById('providerSettlementAmountInput');
            if (creditAmountInput && latestBatchAmountLab && !creditAmountInput.value.trim()) {
                creditAmountInput.value = latestBatchAmountLab;
            }
            const eurAmountInput = document.getElementById('providerSettlementEurAmountInput');
            if (eurAmountInput && latestBatchAmountRaw && !eurAmountInput.value.trim()) {
                eurAmountInput.value = formatSettlementEurFromCreditRaw(latestBatchAmountRaw);
            }
            await loadProviderSettlementInvoices();

            const totalLab = data.totalReceivableLab || formatLabTokenRaw(data.totalReceivableRaw);
            pendingEl.textContent = `${totalLab} credits`;
            setCollectPreviewMetrics(data);
            const pendingClosuresRaw = data.pendingGraceReservationCount ?? '0';

            // Keep the selected lab row in sync after a payout request so the table reflects
            // the latest pending closures count immediately.
            if (selectedLab) {
                selectedLab.pendingGraceReservationCount = pendingClosuresRaw;
                selectedLab.attestedSessionPayoutRaw = data.attestedSessionPayoutRaw;
                selectedLab.potentialNoShowFeeRaw = data.potentialNoShowFeeRaw;
                selectedLab.existingAccruedReceivableRaw = data.existingAccruedReceivableRaw;
                DashboardState.collectAggregates = null;
            }

            setCollectLifecycleSummaryText(buildCollectLifecycleSummary(data));

            let hasPendingClosures = false;
            let hasClaimablePayout = false;
            let pendingGraceReservationCount = 0n;
            try {
                pendingGraceReservationCount = BigInt(pendingClosuresRaw.toString());
                hasPendingClosures = pendingGraceReservationCount > 0n;
                const claimablePayoutRaw = BigInt((data.accruedReceivableRaw ?? '0').toString())
                    + BigInt((data.attestedSessionPayoutRaw ?? '0').toString())
                    + BigInt((data.potentialNoShowFeeRaw ?? '0').toString());
                hasClaimablePayout = claimablePayoutRaw > 0n;
            } catch (error) {
                hasPendingClosures = false;
                hasClaimablePayout = false;
                pendingGraceReservationCount = 0n;
            }

            DashboardState.collectCanExecute = DashboardState.operatingMode === 'provider-consumer'
                && DashboardState.isProvider
                && payoutEnabledForSelectedLab
                && data.canRequestPayout === true
                && hasClaimablePayout;
            renderCollectSettlementOverview();
            updateCollectDetailVisibility();

            if (hasPendingClosures && !hasClaimablePayout) {
                const count = pendingGraceReservationCount.toString();
                const reservationLabel = pendingGraceReservationCount === 1n ? 'reservation' : 'reservations';
                setCollectStatusText(
                    'Awaiting',
                    'info',
                    `Awaiting session attestation for ${count} ${reservationLabel}`
                );
            } else if (DashboardState.collectCanExecute && hasClaimablePayout) {
                setCollectStatusText('Ready for request', 'success');
            } else if (DashboardState.operatingMode === 'provider-consumer'
                && DashboardState.isProvider && !payoutEnabledForSelectedLab) {
                setCollectStatusText('Payout requests are limited to this provider wallet\'s labs', 'warning');
            } else if (DashboardState.operatingMode === 'provider-consumer'
                && !DashboardState.isProvider && DashboardState.isOperator && operatorReviewOnly) {
                setCollectStatusText('Operator review only', 'info');
            } else if (DashboardState.operatingMode === 'provider-consumer'
                && !DashboardState.isProvider && DashboardState.isOperator && data.canRequestPayout === true
                && hasClaimablePayout) {
                setCollectStatusText('Payout available for owning provider', 'info');
            } else if (data.payoutRequestReason) {
                setCollectStatusText(data.payoutRequestReason, 'warning');
            } else {
                setCollectStatusText('Not available', 'warning');
            }

        } catch (error) {
            DashboardState.collectCanExecute = false;
            pendingEl.textContent = '--';
            setCollectPreviewMetrics(null);
            setCollectStatusText('Status unavailable', 'error');
            setCollectLifecycleSummaryText('');
            renderCollectSettlementOverview();
            updateCollectDetailVisibility();
        } finally {
            DashboardState.collectLoadingStatus = false;
            updateCollectButtonState();
        }
    }

    async function loadProviderSettlementInvoices() {
        if (!API.listProviderReceivables) return;
        try {
            const [submitted, approved] = await Promise.all([
                API.listProviderReceivables('SUBMITTED'),
                API.listProviderReceivables('APPROVED')
            ]);
            const records = [
                ...(Array.isArray(submitted) ? submitted : []),
                ...(Array.isArray(approved) ? approved : [])
            ];
            const selectedLabId = String(DashboardState.selectedCollectLabId || '');
            DashboardState.settlementInvoices = records.filter((invoice) => (
                !selectedLabId || String(invoice.labId) === selectedLabId
            ));
            const datalist = document.getElementById('providerSettlementInvoiceOptions');
            if (datalist) {
                datalist.innerHTML = DashboardState.settlementInvoices.map((invoice) => {
                    const label = `${invoice.id} · ${invoice.status || 'invoice'} · ${invoice.claimId || ''}`;
                    return `<option value="${escapeHtml(String(invoice.id))}">${escapeHtml(label)}</option>`;
                }).join('');
            }
        } catch (error) {
            console.warn('Unable to load provider settlement invoices:', error.message);
            DashboardState.settlementInvoices = [];
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
                } catch {
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

    function updateProviderSettlementOperationFields() {
        const operation = document.getElementById('providerSettlementOperationSelect')?.value || 'submit';
        const submitFields = document.getElementById('providerSettlementSubmitFields');
        const invoiceFields = document.getElementById('providerSettlementInvoiceFields');
        const objectFields = document.getElementById('providerSettlementObjectFields');
        const eurAmountField = document.getElementById('providerSettlementEurAmountField');
        const approvalRefField = document.getElementById('providerSettlementApprovalRefField');
        const paymentFields = document.getElementById('providerSettlementPaymentFields');
        const paymentAmountFields = document.getElementById('providerSettlementPaymentAmountFields');
        const isSubmit = operation === 'submit';
        const isApprove = operation === 'approve';
        const isPay = operation === 'pay';
        const isObjectAction = operation === 'dispute-batch'
            || operation === 'reverse-batch'
            || operation === 'dispute-claim'
            || operation === 'reverse-claim';

        submitFields?.classList.toggle('hidden', !isSubmit);
        invoiceFields?.classList.toggle('hidden', !isApprove && !isPay);
        objectFields?.classList.toggle('hidden', !isObjectAction);
        eurAmountField?.classList.toggle('hidden', isObjectAction);
        approvalRefField?.classList.toggle('hidden', !isApprove);
        paymentFields?.classList.toggle('hidden', !isPay);
        paymentAmountFields?.classList.toggle('hidden', !isPay);
    }

    function settlementInputValue(id) {
        return document.getElementById(id)?.value?.trim() || '';
    }

    function requireSettlementInput(id, label) {
        const value = settlementInputValue(id);
        if (!value) {
            throw new Error(`${label} is required`);
        }
        return value;
    }

    function describeSettlementOperation(operation) {
        return {
            submit: 'submit the queued batch as an invoice claim',
            approve: 'approve the submitted settlement claim',
            pay: 'record payment proof for the approved claim',
            'dispute-batch': 'dispute the settlement batch',
            'reverse-batch': 'reverse the settlement batch',
            'dispute-claim': 'dispute the settlement claim',
            'reverse-claim': 'reverse the settlement claim'
        }[operation] || 'apply the settlement action';
    }

    async function handleProviderSettlementTransition(event) {
        event.preventDefault();

        const labId = DashboardState.selectedCollectLabId;
        if (!labId) {
            showToast('Select a lab first', 'error');
            return;
        }

        const operation = document.getElementById('providerSettlementOperationSelect')?.value || 'submit';
        let payload;
        let action;
        try {
            if (operation === 'submit') {
                const creditAmount = requireSettlementInput('providerSettlementAmountInput', 'Credit amount');
                decimalToRawUnits(creditAmount, CREDIT_DECIMALS);
                payload = {
                    claimId: requireSettlementInput('providerSettlementClaimIdInput', 'Claim ID'),
                    batchId: requireSettlementInput('providerSettlementBatchIdInput', 'Settlement batch ID'),
                    invoiceRef: requireSettlementInput('providerSettlementInvoiceRefInput', 'Invoice reference'),
                    eurAmount: requireSettlementInput('providerSettlementEurAmountInput', 'Invoice amount (EUR)'),
                    creditAmount
                };
                action = () => API.submitProviderInvoice(labId, payload);
            } else if (operation === 'approve') {
                payload = {
                    approvalRef: requireSettlementInput('providerSettlementApprovalRefInput', 'Approval reference'),
                    eurAmount: requireSettlementInput('providerSettlementEurAmountInput', 'Invoice amount (EUR)')
                };
                action = () => API.approveProviderInvoice(
                    requireSettlementInput('providerSettlementInvoiceIdInput', 'Invoice record ID'),
                    payload
                );
            } else if (operation === 'pay') {
                const creditAmount = settlementInputValue('providerSettlementPaymentCreditAmountInput');
                if (creditAmount) decimalToRawUnits(creditAmount, CREDIT_DECIMALS);
                payload = {
                    eurAmount: requireSettlementInput('providerSettlementEurAmountInput', 'Payment amount (EUR)'),
                    ...(creditAmount ? { creditAmount } : {}),
                    paymentRef: requireSettlementInput('providerSettlementPaymentRefInput', 'Payment reference'),
                    paymentAttestation: requireSettlementInput('providerSettlementPaymentAttestationInput', 'Payment attestation'),
                    bankRef: settlementInputValue('providerSettlementBankRefInput'),
                    eurcTxHash: settlementInputValue('providerSettlementEurcTxHashInput'),
                    usdcTxHash: settlementInputValue('providerSettlementUsdcTxHashInput')
                };
                action = () => API.recordProviderPayout(
                    requireSettlementInput('providerSettlementInvoiceIdInput', 'Invoice record ID'),
                    payload
                );
            } else {
                const objectId = requireSettlementInput('providerSettlementObjectIdInput', 'Batch or claim ID');
                const reference = requireSettlementInput('providerSettlementReferenceInput', 'Resolution reference');
                action = () => {
                    if (operation === 'dispute-batch') return API.disputeSettlementBatch(objectId, reference);
                    if (operation === 'reverse-batch') return API.reverseSettlementBatch(objectId, reference);
                    if (operation === 'dispute-claim') return API.disputeSettlementClaim(objectId, reference);
                    return API.reverseSettlementClaim(objectId, reference);
                };
            }
        } catch (error) {
            showToast(error.message, 'error');
            return;
        }

        const collectTarget = getCollectTargetLabel();
        const confirmed = await showConfirmModal(
            'Confirm canonical settlement action',
            `Confirm that you want to ${describeSettlementOperation(operation)} for ${collectTarget}?`,
            {
                icon: 'file-invoice-dollar',
                confirmText: 'Submit action',
                confirmButtonClass: 'btn-secondary'
            }
        );
        if (!confirmed) return;

        try {
            const result = await action();
            if (result && result.success === false) {
                throw new Error(result.message || result.error || 'Settlement action failed');
            }
            const invoiceId = result?.id ?? result?.invoiceRecordId;
            if (invoiceId) {
                const invoiceInput = document.getElementById('providerSettlementInvoiceIdInput');
                if (invoiceInput) invoiceInput.value = String(invoiceId);
            }
            showToast(`Canonical settlement action completed for ${collectTarget}.`, 'success');
            await Promise.allSettled([
                loadRecentTransactions(),
                loadCollectStatusForSelectedLab()
            ]);
        } catch (error) {
            showToast('Canonical settlement action failed: ' + error.message, 'error');
        }
    }




    window.WalletDashboardProviderSettlement = Object.freeze({
        clearCollectLabsRetryTimer,
        handleCollectLabPayout,
        handleProviderSettlementTransition,
        loadCollectLabs,
        loadCollectStatusForSelectedLab,
        loadMoreCollectLabs,
        loadProviderGatewayDepartments,
        setupProviderGatewayDepartmentHandlers,
        updateProviderSettlementOperationFields
    });
})();
