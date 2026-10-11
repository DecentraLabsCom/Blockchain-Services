package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.GatewayIdentity;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

/** Durable AP provider income attribution and settlement reconciliation. */
@Service
@Slf4j
public class ProviderIncomeAccountingService {

    private static final int CREDIT_DECIMALS = 7;
    private final JdbcTemplate jdbcTemplate;
    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final ProviderGatewayDepartmentService providerGatewayDepartmentService;
    private volatile BigInteger cachedChainId;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${contract.event.start.block:latest}")
    private String trackingStartBlock;

    public ProviderIncomeAccountingService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        WalletService walletService,
        InstitutionalWalletService institutionalWalletService,
        ProviderGatewayDepartmentService providerGatewayDepartmentService
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.walletService = walletService;
        this.institutionalWalletService = institutionalWalletService;
        this.providerGatewayDepartmentService = providerGatewayDepartmentService;
    }

    public void resetNetworkContext() {
        cachedChainId = null;
    }

    public boolean isAvailable() {
        return jdbcTemplate != null && contractAddress != null && !contractAddress.isBlank();
    }

    /** Snapshot the actual lab Gateway and provider allocation at generation confirmation. */
    @Transactional
    public void recordConfirmedGeneration(String reservationId, String reservationKey, BigInteger eventLabId, Log log) {
        if (!isAvailable()) return;
        requirePersistence();
        requireLogIdentity(log);
        try {
            Web3j web3j = walletService.getWeb3jInstance();
            BigInteger chainId = currentChainId();
            Diamond diamond = Diamond.load(
                contractAddress,
                web3j,
                new ReadonlyTransactionManager(web3j, contractAddress),
                new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
            );
            byte[] idBytes = bytes32(reservationId);
            Diamond.Reservation reservation = diamond.getReservationByIdAtBlock(idBytes, log.getBlockNumber()).send();
            Diamond.Lab lab = diamond.getLabAtBlock(eventLabId, log.getBlockNumber()).send();
            String historicalLabOwner = diamond.ownerOfAtBlock(eventLabId, log.getBlockNumber()).send();
            if (reservation == null || lab == null || lab.base == null
                || !eventLabId.equals(reservation.labId) || !eventLabId.equals(lab.labId)
                || !historicalLabOwner.equalsIgnoreCase(reservation.labProvider)) {
                throw new IllegalStateException("Historical confirmation state did not match event lab " + eventLabId);
            }

            String accessUri = lab.base.accessURI;
            String gatewayId = gatewayIdFromAccessUri(accessUri);
            String normalizedContract = normalizeContract(contractAddress);
            String signature = eventSignature(log);
            jdbcTemplate.update(
                """
                INSERT INTO provider_income_reservations (
                    chain_id, contract_address, reservation_id, reservation_key, lab_id, provider_address,
                    access_uri, gateway_id, price_raw, provider_share_raw, transaction_hash, log_index,
                    block_number, block_hash, transaction_index, event_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    reservation_key=VALUES(reservation_key), lab_id=VALUES(lab_id),
                    provider_address=VALUES(provider_address), access_uri=VALUES(access_uri),
                    gateway_id=VALUES(gateway_id), price_raw=VALUES(price_raw),
                    provider_share_raw=VALUES(provider_share_raw), transaction_hash=VALUES(transaction_hash),
                    log_index=VALUES(log_index), block_number=VALUES(block_number), block_hash=VALUES(block_hash),
                    transaction_index=VALUES(transaction_index), event_signature=VALUES(event_signature),
                    updated_at=CURRENT_TIMESTAMP
                """,
                chainId,
                normalizedContract,
                normalizeBytes32(reservationId),
                normalizeBytes32(reservationKey),
                eventLabId.toString(),
                reservation.labProvider.toLowerCase(Locale.ROOT),
                accessUri,
                gatewayId,
                reservation.price.toString(),
                reservation.providerShare.toString(),
                normalizeHash(log.getTransactionHash()),
                log.getLogIndex(),
                log.getBlockNumber(),
                normalizeHash(log.getBlockHash()),
                transactionIndex(log),
                signature
            );
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to persist historical provider income attribution", ex);
        }
    }

    @Transactional
    public void recordAccrual(BigInteger labId, String reservationId, BigInteger amount, Log log) {
        if (!isAvailable()) return;
        requirePersistence();
        requireLogIdentity(log);
        BigInteger chainId = currentChainId();
        jdbcTemplate.update(
            """
            INSERT INTO provider_income_accruals (
                chain_id, contract_address, transaction_hash, log_index, block_number, block_hash,
                transaction_index, event_signature, lab_id, reservation_id, amount_raw
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE lab_id=VALUES(lab_id), reservation_id=VALUES(reservation_id),
                amount_raw=VALUES(amount_raw), event_signature=VALUES(event_signature)
            """,
            chainId, normalizeContract(contractAddress), normalizeHash(log.getTransactionHash()), log.getLogIndex(),
            log.getBlockNumber(), normalizeHash(log.getBlockHash()), transactionIndex(log), eventSignature(log),
            labId.toString(), normalizeBytes32(reservationId), amount.toString()
        );
    }

    @Transactional
    public void recordBatchCreated(String batchId, BigInteger labId, BigInteger amount, String scopeRoot, Log log) {
        if (!isAvailable()) return;
        requirePersistence();
        requireLogIdentity(log);
        BigInteger chainId = currentChainId();
        jdbcTemplate.update(
            """
            INSERT INTO provider_income_batches (
                chain_id, contract_address, batch_id, lab_id, amount_raw, scope_root, transaction_hash,
                log_index, block_number, block_hash, transaction_index, event_signature, source_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
            ON DUPLICATE KEY UPDATE lab_id=VALUES(lab_id), amount_raw=VALUES(amount_raw),
                scope_root=VALUES(scope_root), transaction_hash=VALUES(transaction_hash),
                log_index=VALUES(log_index), block_number=VALUES(block_number), block_hash=VALUES(block_hash),
                transaction_index=VALUES(transaction_index), event_signature=VALUES(event_signature), source_status='PENDING'
            """,
            chainId, normalizeContract(contractAddress), normalizeBytes32(batchId), labId.toString(), amount.toString(),
            normalizeBytes32(scopeRoot), normalizeHash(log.getTransactionHash()), log.getLogIndex(), log.getBlockNumber(),
            normalizeHash(log.getBlockHash()), transactionIndex(log), eventSignature(log)
        );
    }

    @Transactional
    public void recordSettlementActivity(
        String activity,
        String batchId,
        String claimId,
        BigInteger labId,
        BigInteger amount,
        String scopeRoot,
        Integer targetStatus,
        Log log
    ) {
        if (!isAvailable()) return;
        requirePersistence();
        requireLogIdentity(log);
        jdbcTemplate.update(
            """
            INSERT INTO provider_income_settlement_events (
                chain_id, contract_address, transaction_hash, log_index, block_number, block_hash,
                transaction_index, event_signature, activity, batch_id, claim_id, lab_id,
                amount_raw, scope_root, target_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE activity=VALUES(activity), batch_id=VALUES(batch_id),
                claim_id=VALUES(claim_id), lab_id=VALUES(lab_id), amount_raw=VALUES(amount_raw),
                scope_root=VALUES(scope_root), target_status=VALUES(target_status), event_signature=VALUES(event_signature)
            """,
            currentChainId(), normalizeContract(contractAddress), normalizeHash(log.getTransactionHash()),
            log.getLogIndex(), log.getBlockNumber(), normalizeHash(log.getBlockHash()), transactionIndex(log),
            eventSignature(log), activity, nullableBytes32(batchId), nullableBytes32(claimId),
            labId == null ? null : labId.toString(), amount == null ? null : amount.toString(),
            nullableBytes32(scopeRoot), targetStatus
        );
    }

    /** Periodically rebuild source links from the canonical accrual and batch event stream. */
    @Scheduled(fixedDelayString = "${billing.provider-income.reconcile.interval.ms:300000}")
    @Transactional
    public void reconcileBatchSources() {
        if (jdbcTemplate == null || contractAddress == null || contractAddress.isBlank()) {
            return;
        }
        BigInteger chainId;
        try {
            chainId = currentChainId();
        } catch (RuntimeException ex) {
            log.warn("Provider income source reconciliation skipped: {}", ex.getMessage());
            return;
        }
        String contract = normalizeContract(contractAddress);
        jdbcTemplate.update(
            "DELETE FROM provider_income_batch_sources WHERE chain_id=? AND contract_address=?", chainId, contract
        );
        List<AccrualRow> accruals = loadCanonicalAccruals(chainId, contract);
        List<BatchRow> batches = loadCanonicalBatches(chainId, contract);
        List<StreamEntry> stream = new ArrayList<>(accruals.size() + batches.size());
        accruals.forEach(row -> stream.add(new StreamEntry(row.order(), row.labId(), row, null)));
        batches.forEach(row -> stream.add(new StreamEntry(row.order(), row.labId(), null, row)));
        stream.sort((left, right) -> left.order().compareTo(right.order()));

        Map<String, SourceAccumulator> byLab = new HashMap<>();
        for (StreamEntry item : stream) {
            SourceAccumulator accumulator = byLab.computeIfAbsent(item.labId(), ignored -> new SourceAccumulator());
            if (item.accrual() != null) {
                accumulator.append(item.accrual());
                continue;
            }
            BatchRow batch = item.batch();
            if (accumulator.matches(batch)) {
                for (AccrualRow source : accumulator.sources) {
                    jdbcTemplate.update(
                        """
                        INSERT INTO provider_income_batch_sources (
                            chain_id, contract_address, batch_id, accrual_transaction_hash,
                            accrual_block_hash, accrual_log_index, reservation_id, amount_raw
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        chainId, contract, batch.batchId(), source.transactionHash(), source.blockHash(),
                        source.logIndex(), source.reservationId(), source.amountRaw()
                    );
                }
                jdbcTemplate.update(
                    "UPDATE provider_income_batches SET source_status='MATCHED' WHERE chain_id=? AND contract_address=? AND batch_id=?",
                    chainId, contract, batch.batchId()
                );
            } else {
                jdbcTemplate.update(
                    "UPDATE provider_income_batches SET source_status='UNRESOLVED' WHERE chain_id=? AND contract_address=? AND batch_id=?",
                    chainId, contract, batch.batchId()
                );
                log.warn("Unable to reconcile provider settlement batch scope for lab {} / batch {}", batch.labId(), batch.batchId());
            }
            // The contract starts a fresh rolling root whenever a batch is created.
            accumulator.reset();
        }
    }

    @Transactional
    public Map<String, Object> getReport() {
        return buildReport(null, true);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getReportForGateway(String gatewayId) {
        String normalizedGatewayId = GatewayIdentity.normalizeGatewayId(gatewayId);
        if (normalizedGatewayId == null) {
            throw new IllegalArgumentException("Authenticated Gateway scope is required");
        }
        return buildReport(normalizedGatewayId, false);
    }

    private Map<String, Object> buildReport(String gatewayId, boolean reconcileSources) {
        requirePersistence();
        String providerAddress = configuredProviderAddress();
        if (reconcileSources) {
            reconcileBatchSources();
        }
        BigInteger chainId = currentChainId();
        String contract = normalizeContract(contractAddress);
        Map<String, Snapshot> snapshots = loadCanonicalSnapshots(chainId, contract, providerAddress, gatewayId);
        Set<String> providerLabIds = snapshots.values().stream()
            .map(snapshot -> snapshot.labId())
            .collect(Collectors.toSet());
        List<AccrualRow> accruals = loadCanonicalAccruals(chainId, contract, providerAddress, gatewayId);
        List<BatchRow> batches = loadCanonicalBatches(chainId, contract, providerLabIds);
        Set<String> providerBatchIds = batches.stream()
            .map(batch -> batch.batchId())
            .collect(java.util.stream.Collectors.toSet());
        List<ActivityRow> activities = loadCanonicalActivities(chainId, contract, providerBatchIds);
        Map<String, String> batchStatuses = settlementStatuses(batches, activities);
        Map<String, BatchRow> batchesById = new HashMap<>();
        batches.forEach(batch -> batchesById.put(batch.batchId(), batch));
        int scopeReferenceMismatchCount = 0;
        for (ActivityRow activity : activities) {
            if (!"SCOPE_REFERENCED".equals(activity.activity())) continue;
            BatchRow batch = batchesById.get(activity.batchId());
            if (batch == null || !batch.labId().equals(activity.labId())
                || !batch.amountRaw().equals(activity.amountRaw())
                || !batch.scopeRoot().equalsIgnoreCase(activity.scopeRoot())) {
                scopeReferenceMismatchCount++;
            }
        }

        Map<GroupKey, IncomeGroup> groups = new TreeMap<>();
        Map<String, AccrualRow> accrualByIdentity = new HashMap<>();
        for (AccrualRow accrual : accruals) {
            accrualByIdentity.put(accrual.identity(), accrual);
            Snapshot snapshot = snapshots.get(accrual.reservationId());
            if (snapshot == null) continue;
            IncomeGroup group = group(groups, snapshot, accrual.labId());
            BigInteger amount = new BigInteger(accrual.amountRaw());
            group.accrued = group.accrued.add(amount);
        }

        for (Snapshot snapshot : snapshots.values()) {
            IncomeGroup group = group(groups, snapshot, snapshot.labId());
            group.reservations++;
            group.potential = group.potential.add(new BigInteger(snapshot.providerShareRaw()));
        }

        Set<String> batchedAccruals = new HashSet<>();
        Map<String, List<SourceRow>> sourcesByBatch = new HashMap<>();
        if (!providerBatchIds.isEmpty()) {
            List<String> scopedBatchIds = new ArrayList<>(providerBatchIds);
            String batchPlaceholders = String.join(",", java.util.Collections.nCopies(scopedBatchIds.size(), "?"));
            String sourceSql = """
                SELECT s.batch_id, s.accrual_transaction_hash, s.accrual_block_hash,
                       s.accrual_log_index, s.reservation_id, s.amount_raw
                FROM provider_income_batch_sources s
                JOIN provider_income_batches b ON b.chain_id=s.chain_id AND b.contract_address=s.contract_address
                    AND b.batch_id=s.batch_id AND b.source_status='MATCHED'
                WHERE s.chain_id=? AND s.contract_address=? AND s.batch_id IN (%s)
                """.formatted(batchPlaceholders);
            jdbcTemplate.query(sourceSql, ps -> {
                int parameterIndex = 1;
                ps.setBigDecimal(parameterIndex++, new BigDecimal(chainId));
                ps.setString(parameterIndex++, contract);
                for (String batchId : scopedBatchIds) {
                    ps.setString(parameterIndex++, batchId);
                }
            }, rs -> {
                SourceRow source = new SourceRow(
                    rs.getString("batch_id"), rs.getString("accrual_transaction_hash"),
                    rs.getString("accrual_block_hash"), rs.getBigDecimal("accrual_log_index").toBigIntegerExact(),
                    rs.getString("reservation_id"), rs.getString("amount_raw")
                );
                sourcesByBatch.computeIfAbsent(source.batchId(), ignored -> new ArrayList<>()).add(source);
                batchedAccruals.add(source.identity());
            });
        }

        for (AccrualRow accrual : accruals) {
            if (batchedAccruals.contains(accrual.identity())) continue;
            Snapshot snapshot = snapshots.get(accrual.reservationId());
            if (snapshot == null) continue;
            IncomeGroup group = group(groups, snapshot, accrual.labId());
            group.unbatched = group.unbatched.add(new BigInteger(accrual.amountRaw()));
        }

        BigInteger unresolvedAmount = BigInteger.ZERO;
        int unresolvedCount = 0;
        for (BatchRow batch : batches) {
            if (!"MATCHED".equals(batch.sourceStatus())) {
                unresolvedCount++;
                unresolvedAmount = unresolvedAmount.add(new BigInteger(batch.amountRaw()));
                continue;
            }
            String status = batchStatuses.getOrDefault(batch.batchId(), "QUEUED");
            for (SourceRow source : sourcesByBatch.getOrDefault(batch.batchId(), List.of())) {
                AccrualRow sourceAccrual = accrualByIdentity.get(source.identity());
                Snapshot snapshot = sourceAccrual == null ? snapshots.get(source.reservationId()) : snapshots.get(sourceAccrual.reservationId());
                if (snapshot == null) continue;
                IncomeGroup group = group(groups, snapshot, batch.labId());
                BigInteger amount = new BigInteger(source.amountRaw());
                switch (status) {
                    case "QUEUED" -> group.queued = group.queued.add(amount);
                    case "CLAIMED", "APPROVED" -> group.inProcess = group.inProcess.add(amount);
                    case "PAID" -> group.paid = group.paid.add(amount);
                    case "INVALIDATED" -> group.invalidated = group.invalidated.add(amount);
                    default -> group.queued = group.queued.add(amount);
                }
            }
        }

        Map<String, String> departmentNames = providerGatewayDepartmentService.departmentNames();
        List<Map<String, Object>> rows = new ArrayList<>(groups.size());
        for (IncomeGroup group : groups.values()) {
            String departmentName = group.gatewayId == null ? null : departmentNames.get(group.gatewayId);
            rows.add(group.asMap(departmentName));
        }
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("success", true);
        report.put("chainId", chainId.toString());
        report.put("contractAddress", contract);
        if (gatewayId == null) {
            report.put("providerAddress", providerAddress);
        } else {
            String departmentName = departmentNames.get(gatewayId);
            report.put("gatewayId", gatewayId);
            report.put("departmentName", departmentName);
            report.put("gatewayLabel", departmentName == null || departmentName.isBlank()
                ? gatewayId
                : departmentName);
        }
        report.put("trackingStartBlock", trackingStartBlock);
        report.put("firstObservedConfirmationBlock", firstObservedConfirmationBlock(
            chainId, contract, providerAddress, gatewayId
        ));
        report.put("generatedAt", Instant.now().toString());
        report.put("unresolvedBatchCount", unresolvedCount);
        report.put("unresolvedBatchAmountRaw", unresolvedAmount.toString());
        report.put("unresolvedBatchAmount", credits(unresolvedAmount));
        report.put("scopeReferenceMismatchCount", scopeReferenceMismatchCount);
        report.put("rows", rows);
        return report;
    }

    private Map<String, Snapshot> loadCanonicalSnapshots(
        BigInteger chainId, String contract, String providerAddress, String gatewayId
    ) {
        String gatewayFilter = gatewayId == null ? "" : " AND a.gateway_id=?";
        String sql = """
            SELECT a.reservation_id, a.lab_id, a.gateway_id, a.access_uri, a.provider_share_raw, a.price_raw
            FROM provider_income_reservations a
            JOIN contract_event_journal j ON j.chain_id=a.chain_id AND j.contract_address=a.contract_address
                AND j.event_signature=a.event_signature AND j.transaction_hash=a.transaction_hash
                AND j.log_index=a.log_index AND j.block_number=a.block_number AND j.block_hash=a.block_hash
                AND j.status='DONE' AND j.canonical_status='CANONICAL'
            WHERE a.chain_id=? AND a.contract_address=? AND a.provider_address=?
            %s
            """.formatted(gatewayFilter);
        return jdbcTemplate.query(sql, ps -> {
            ps.setBigDecimal(1, new BigDecimal(chainId));
            ps.setString(2, contract);
            ps.setString(3, providerAddress);
            if (gatewayId != null) {
                ps.setString(4, gatewayId);
            }
        }, rs -> {
            Map<String, Snapshot> values = new HashMap<>();
            while (rs.next()) {
                Snapshot row = new Snapshot(
                    rs.getString("reservation_id"), rs.getString("lab_id"), rs.getString("gateway_id"),
                    rs.getString("access_uri"), rs.getString("provider_share_raw"), rs.getString("price_raw")
                );
                values.put(row.reservationId(), row);
            }
            return values;
        });
    }

    private List<AccrualRow> loadCanonicalAccruals(BigInteger chainId, String contract) {
        return loadCanonicalAccruals(chainId, contract, null, null);
    }

    private List<AccrualRow> loadCanonicalAccruals(
        BigInteger chainId, String contract, String providerAddress, String gatewayId
    ) {
        String providerReservationJoin = providerAddress == null && gatewayId == null ? "" : """
            JOIN provider_income_reservations r ON r.chain_id=a.chain_id
                AND r.contract_address=a.contract_address AND r.reservation_id=a.reservation_id
                %s
            """;
        if (providerAddress != null || gatewayId != null) {
            String reservationScope = (providerAddress == null ? "" : "AND r.provider_address=? ")
                + (gatewayId == null ? "" : "AND r.gateway_id=?");
            providerReservationJoin = providerReservationJoin.formatted(reservationScope);
        }
        String sql = """
            SELECT a.transaction_hash, a.log_index, a.block_number, a.block_hash, a.transaction_index,
                   a.lab_id, a.reservation_id, a.amount_raw
            FROM provider_income_accruals a
            %s
            JOIN contract_event_journal j ON j.chain_id=a.chain_id AND j.contract_address=a.contract_address
                AND j.event_signature=a.event_signature AND j.transaction_hash=a.transaction_hash
                AND j.log_index=a.log_index AND j.block_number=a.block_number AND j.block_hash=a.block_hash
                AND j.status='DONE' AND j.canonical_status='CANONICAL'
            WHERE a.chain_id=? AND a.contract_address=?
            """.formatted(providerReservationJoin);
        return jdbcTemplate.query(sql, ps -> {
                int parameterIndex = 1;
                if (providerAddress != null) {
                    ps.setString(parameterIndex++, providerAddress);
                }
                if (gatewayId != null) {
                    ps.setString(parameterIndex++, gatewayId);
                }
                ps.setBigDecimal(parameterIndex++, new BigDecimal(chainId));
                ps.setString(parameterIndex, contract);
            },
            (rs, rowNum) -> accrualRow(rs)
        );
    }

    private List<BatchRow> loadCanonicalBatches(BigInteger chainId, String contract) {
        return loadCanonicalBatches(chainId, contract, null);
    }

    private List<BatchRow> loadCanonicalBatches(
        BigInteger chainId, String contract, Set<String> labIds
    ) {
        if (labIds != null && labIds.isEmpty()) {
            return List.of();
        }
        List<String> scopedLabIds = labIds == null ? List.of() : new ArrayList<>(labIds);
        String labFilter = labIds == null ? "" : " AND a.lab_id IN ("
            + String.join(",", java.util.Collections.nCopies(scopedLabIds.size(), "?")) + ")";
        String sql = """
            SELECT a.batch_id, a.lab_id, a.amount_raw, a.scope_root, a.source_status,
                   a.block_number, a.transaction_index, a.log_index
            FROM provider_income_batches a
            JOIN contract_event_journal j ON j.chain_id=a.chain_id AND j.contract_address=a.contract_address
                AND j.event_signature=a.event_signature AND j.transaction_hash=a.transaction_hash
                AND j.log_index=a.log_index AND j.block_number=a.block_number AND j.block_hash=a.block_hash
                AND j.status='DONE' AND j.canonical_status='CANONICAL'
            WHERE a.chain_id=? AND a.contract_address=?%s
            ORDER BY a.block_number, a.transaction_index, a.log_index
            """.formatted(labFilter);
        return jdbcTemplate.query(
            sql,
            ps -> {
                int parameterIndex = 1;
                ps.setBigDecimal(parameterIndex++, new BigDecimal(chainId));
                ps.setString(parameterIndex++, contract);
                for (String labId : scopedLabIds) {
                    ps.setString(parameterIndex++, labId);
                }
            },
            (rs, rowNum) -> new BatchRow(
                rs.getString("batch_id"), rs.getString("lab_id"), rs.getString("amount_raw"),
                rs.getString("scope_root"), rs.getString("source_status"),
                new EventOrder(rs.getBigDecimal("block_number").toBigIntegerExact(),
                    rs.getBigDecimal("transaction_index").toBigIntegerExact(),
                    rs.getBigDecimal("log_index").toBigIntegerExact())
            )
        );
    }

    private List<ActivityRow> loadCanonicalActivities(
        BigInteger chainId, String contract, Set<String> batchIds
    ) {
        if (batchIds != null && batchIds.isEmpty()) {
            return List.of();
        }
        List<String> scopedBatchIds = batchIds == null ? List.of() : new ArrayList<>(batchIds);
        String batchPlaceholders = batchIds == null
            ? ""
            : String.join(",", java.util.Collections.nCopies(scopedBatchIds.size(), "?"));
        String batchFilter = batchIds == null ? "" : " AND (a.batch_id IN (" + batchPlaceholders
            + ") OR a.claim_id IN (SELECT e.claim_id FROM provider_income_settlement_events e"
            + " WHERE e.chain_id=? AND e.contract_address=? AND e.batch_id IN (" + batchPlaceholders
            + ") AND e.claim_id IS NOT NULL))";
        String sql = """
            SELECT a.activity, a.batch_id, a.claim_id, a.lab_id, a.amount_raw, a.scope_root,
                   a.target_status, a.block_number,
                   a.transaction_index, a.log_index
            FROM provider_income_settlement_events a
            JOIN contract_event_journal j ON j.chain_id=a.chain_id AND j.contract_address=a.contract_address
                AND j.event_signature=a.event_signature AND j.transaction_hash=a.transaction_hash
                AND j.log_index=a.log_index AND j.block_number=a.block_number AND j.block_hash=a.block_hash
                AND j.status='DONE' AND j.canonical_status='CANONICAL'
            WHERE a.chain_id=? AND a.contract_address=?%s
            ORDER BY a.block_number, a.transaction_index, a.log_index
            """.formatted(batchFilter);
        return jdbcTemplate.query(
            sql,
            ps -> {
                int parameterIndex = 1;
                ps.setBigDecimal(parameterIndex++, new BigDecimal(chainId));
                ps.setString(parameterIndex++, contract);
                for (String batchId : scopedBatchIds) {
                    ps.setString(parameterIndex++, batchId);
                }
                if (batchIds != null) {
                    ps.setBigDecimal(parameterIndex++, new BigDecimal(chainId));
                    ps.setString(parameterIndex++, contract);
                    for (String batchId : scopedBatchIds) {
                        ps.setString(parameterIndex++, batchId);
                    }
                }
            },
            (rs, rowNum) -> new ActivityRow(
                rs.getString("activity"), rs.getString("batch_id"), rs.getString("claim_id"),
                rs.getString("lab_id"), rs.getString("amount_raw"), rs.getString("scope_root"),
                (Integer) rs.getObject("target_status"),
                new EventOrder(rs.getBigDecimal("block_number").toBigIntegerExact(),
                    rs.getBigDecimal("transaction_index").toBigIntegerExact(),
                    rs.getBigDecimal("log_index").toBigIntegerExact())
            )
        );
    }

    private Map<String, String> settlementStatuses(List<BatchRow> batches, List<ActivityRow> activities) {
        Map<String, String> statuses = new HashMap<>();
        Map<String, String> claimBatches = new HashMap<>();
        Map<String, String> claimStatuses = new HashMap<>();
        batches.forEach(batch -> statuses.put(batch.batchId(), "QUEUED"));
        for (ActivityRow event : activities) {
            switch (event.activity()) {
                case "CLAIM_SUBMITTED" -> {
                    if (event.claimId() != null && event.batchId() != null) claimBatches.put(event.claimId(), event.batchId());
                    if (event.claimId() != null) claimStatuses.put(event.claimId(), "CLAIMED");
                    if (event.batchId() != null) statuses.put(event.batchId(), "CLAIMED");
                }
                case "CLAIM_APPROVED" -> {
                    if (event.claimId() != null) claimStatuses.put(event.claimId(), "APPROVED");
                    setClaimStatus(statuses, claimBatches, event.claimId(), "APPROVED");
                }
                case "CLAIM_PAID" -> {
                    if (event.claimId() != null) claimStatuses.put(event.claimId(), "PAID");
                    setClaimStatus(statuses, claimBatches, event.claimId(), "PAID");
                }
                case "BATCH_INVALIDATED", "CLAIM_INVALIDATED" -> {
                    if (event.batchId() != null) statuses.put(event.batchId(), "INVALIDATED");
                    else setClaimStatus(statuses, claimBatches, event.claimId(), "INVALIDATED");
                }
                case "SCOPE_REFERENCED" -> {
                    if (event.batchId() != null && event.claimId() != null) {
                        claimBatches.put(event.claimId(), event.batchId());
                        String claimStatus = claimStatuses.get(event.claimId());
                        if (claimStatus != null) statuses.put(event.batchId(), claimStatus);
                    }
                }
                default -> { }
            }
        }
        return statuses;
    }

    private void setClaimStatus(Map<String, String> statuses, Map<String, String> claimBatches, String claimId, String status) {
        String batchId = claimBatches.get(claimId);
        if (batchId != null) statuses.put(batchId, status);
    }

    private String firstObservedConfirmationBlock(
        BigInteger chainId, String contract, String providerAddress, String gatewayId
    ) {
        String gatewayFilter = gatewayId == null ? "" : " AND a.gateway_id=?";
        String sql = """
            SELECT MIN(a.block_number) FROM provider_income_reservations a
            JOIN contract_event_journal j ON j.chain_id=a.chain_id AND j.contract_address=a.contract_address
                AND j.event_signature=a.event_signature AND j.transaction_hash=a.transaction_hash
                AND j.log_index=a.log_index AND j.block_number=a.block_number AND j.block_hash=a.block_hash
                AND j.status='DONE' AND j.canonical_status='CANONICAL'
            WHERE a.chain_id=? AND a.contract_address=? AND a.provider_address=?%s
            """.formatted(gatewayFilter);
        List<BigInteger> blocks = jdbcTemplate.query(
            sql,
            ps -> {
                ps.setBigDecimal(1, new BigDecimal(chainId));
                ps.setString(2, contract);
                ps.setString(3, providerAddress);
                if (gatewayId != null) {
                    ps.setString(4, gatewayId);
                }
            },
            (rs, rowNum) -> rs.getBigDecimal(1) == null ? null : rs.getBigDecimal(1).toBigIntegerExact()
        );
        return blocks.isEmpty() || blocks.get(0) == null ? null : blocks.get(0).toString();
    }

    private IncomeGroup group(Map<GroupKey, IncomeGroup> groups, Snapshot snapshot, String labId) {
        String gateway = snapshot == null ? null : snapshot.gatewayId();
        String accessUri = snapshot == null ? null : snapshot.accessUri();
        GroupKey key = new GroupKey(gateway == null ? "~" : gateway, labId == null ? "" : labId);
        IncomeGroup group = groups.computeIfAbsent(key, ignored -> new IncomeGroup(gateway, accessUri, labId));
        if (group.accessUri == null && accessUri != null) group.accessUri = accessUri;
        return group;
    }

    private BigInteger currentChainId() {
        BigInteger cached = cachedChainId;
        if (cached != null) return cached;
        try {
            BigInteger resolved = walletService.getWeb3jInstance().ethChainId().send().getChainId();
            cachedChainId = resolved;
            return resolved;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to read current blockchain chain id", ex);
        }
    }

    private void requirePersistence() {
        if (jdbcTemplate == null) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Durable provider income reporting is unavailable");
        }
        if (contractAddress == null || contractAddress.isBlank()) {
            throw new IllegalStateException("Diamond contract address is not configured");
        }
    }

    private String configuredProviderAddress() {
        String address = institutionalWalletService.getInstitutionalWalletAddress();
        if (address == null || address.isBlank()) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Institutional provider wallet is not configured"
            );
        }
        String normalized = address.trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("^0x[0-9a-f]{40}$")) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Institutional provider wallet is invalid"
            );
        }
        return normalized;
    }

    private static void requireLogIdentity(Log eventLog) {
        if (eventLog == null || eventLog.getTransactionHash() == null || eventLog.getBlockNumber() == null
            || eventLog.getBlockHash() == null || eventLog.getLogIndex() == null || eventLog.getTopics() == null
            || eventLog.getTopics().isEmpty()) {
            throw new IllegalArgumentException("Provider accounting event is missing canonical log identity");
        }
    }

    private static BigInteger transactionIndex(Log log) {
        return log.getTransactionIndex() == null ? BigInteger.ZERO : log.getTransactionIndex();
    }

    private static String eventSignature(Log log) {
        return normalizeBytes32(log.getTopics().get(0));
    }

    private static String normalizeContract(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeHash(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Event hash is required");
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.startsWith("0x") ? normalized : "0x" + normalized;
    }

    private static String normalizeBytes32(String value) {
        String normalized = normalizeHash(value);
        if (normalized.length() != 66) throw new IllegalArgumentException("Expected a bytes32 value");
        return normalized;
    }

    private static String nullableBytes32(String value) {
        return value == null || value.isBlank() ? null : normalizeBytes32(value);
    }

    private static byte[] bytes32(String value) {
        byte[] bytes = Numeric.hexStringToByteArray(normalizeBytes32(value));
        if (bytes.length != 32) throw new IllegalArgumentException("Expected a bytes32 value");
        return bytes;
    }

    private static String gatewayIdFromAccessUri(String accessUri) {
        if (accessUri == null || accessUri.isBlank()) return null;
        try {
            URI uri = URI.create(accessUri.trim());
            if (uri.getHost() == null) return null;
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            if (host.contains(":")) host = "[" + host + "]";
            String scheme = uri.getScheme() == null ? "https" : uri.getScheme().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            boolean defaultPort = port < 0 || ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
            return defaultPort ? host : host + ":" + port;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String credits(BigInteger raw) {
        return new BigDecimal(raw, CREDIT_DECIMALS).toPlainString();
    }

    private static AccrualRow accrualRow(ResultSet rs) throws SQLException {
        return new AccrualRow(
            rs.getString("transaction_hash"), rs.getString("block_hash"),
            rs.getBigDecimal("log_index").toBigIntegerExact(),
            new EventOrder(rs.getBigDecimal("block_number").toBigIntegerExact(),
                rs.getBigDecimal("transaction_index").toBigIntegerExact(),
                rs.getBigDecimal("log_index").toBigIntegerExact()),
            rs.getString("lab_id"), rs.getString("reservation_id"), rs.getString("amount_raw")
        );
    }

    private static String word(BigInteger value) {
        if (value.signum() < 0 || value.bitLength() > 256) throw new IllegalArgumentException("Value is outside uint256 range");
        return String.format(Locale.ROOT, "%064x", value);
    }

    private static String wordBytes32(String value) {
        return normalizeBytes32(value).substring(2);
    }

    private record EventOrder(BigInteger block, BigInteger transaction, BigInteger log) implements Comparable<EventOrder> {
        @Override public int compareTo(EventOrder other) {
            int result = block.compareTo(other.block);
            if (result == 0) result = transaction.compareTo(other.transaction);
            if (result == 0) result = log.compareTo(other.log);
            return result;
        }
    }

    private record Snapshot(String reservationId, String labId, String gatewayId, String accessUri, String providerShareRaw, String priceRaw) { }
    private record AccrualRow(String transactionHash, String blockHash, BigInteger logIndex, EventOrder order,
                              String labId, String reservationId, String amountRaw) {
        String identity() { return transactionHash + ":" + blockHash + ":" + logIndex; }
    }
    private record BatchRow(String batchId, String labId, String amountRaw, String scopeRoot, String sourceStatus, EventOrder order) { }
    private record ActivityRow(String activity, String batchId, String claimId, String labId,
                               String amountRaw, String scopeRoot, Integer targetStatus, EventOrder order) { }
    private record SourceRow(String batchId, String transactionHash, String blockHash, BigInteger logIndex,
                             String reservationId, String amountRaw) {
        String identity() { return transactionHash + ":" + blockHash + ":" + logIndex; }
    }
    private record StreamEntry(EventOrder order, String labId, AccrualRow accrual, BatchRow batch) { }
    private record GroupKey(String gateway, String labId) implements Comparable<GroupKey> {
        @Override public int compareTo(GroupKey other) {
            int result = gateway.compareTo(other.gateway);
            return result == 0 ? labId.compareTo(other.labId) : result;
        }
    }

    private static final class SourceAccumulator {
        private final List<AccrualRow> sources = new ArrayList<>();
        private BigInteger amount = BigInteger.ZERO;
        private byte[] root = new byte[32];

        void append(AccrualRow row) {
            BigInteger labId = new BigInteger(row.labId());
            byte[] leaf = Hash.sha3(Numeric.hexStringToByteArray(
                "0x" + word(labId) + wordBytes32(row.reservationId()) + word(new BigInteger(row.amountRaw()))
            ));
            root = Hash.sha3(concat(root, leaf));
            amount = amount.add(new BigInteger(row.amountRaw()));
            sources.add(row);
        }

        boolean matches(BatchRow batch) {
            return !sources.isEmpty()
                && amount.equals(new BigInteger(batch.amountRaw()))
                && Numeric.toHexString(root).equalsIgnoreCase(batch.scopeRoot());
        }

        void reset() {
            sources.clear();
            amount = BigInteger.ZERO;
            root = new byte[32];
        }

        private static byte[] concat(byte[] left, byte[] right) {
            byte[] bytes = new byte[left.length + right.length];
            System.arraycopy(left, 0, bytes, 0, left.length);
            System.arraycopy(right, 0, bytes, left.length, right.length);
            return bytes;
        }
    }

    private static final class IncomeGroup {
        private final String gatewayId;
        private String accessUri;
        private final String labId;
        private int reservations;
        private BigInteger potential = BigInteger.ZERO;
        private BigInteger accrued = BigInteger.ZERO;
        private BigInteger unbatched = BigInteger.ZERO;
        private BigInteger queued = BigInteger.ZERO;
        private BigInteger inProcess = BigInteger.ZERO;
        private BigInteger paid = BigInteger.ZERO;
        private BigInteger invalidated = BigInteger.ZERO;

        private IncomeGroup(String gatewayId, String accessUri, String labId) {
            this.gatewayId = gatewayId;
            this.accessUri = accessUri;
            this.labId = labId;
        }

        private Map<String, Object> asMap(String departmentName) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("gatewayId", gatewayId);
            row.put("departmentName", departmentName);
            row.put("gatewayLabel", departmentName == null || departmentName.isBlank()
                ? (gatewayId == null ? "Sin atribución de Gateway" : gatewayId)
                : departmentName);
            row.put("accessUri", accessUri);
            row.put("labId", labId);
            row.put("confirmedReservations", reservations);
            putAmount(row, "potentialProviderShare", potential);
            putAmount(row, "accrued", accrued);
            putAmount(row, "unbatched", unbatched);
            putAmount(row, "queued", queued);
            putAmount(row, "inProcess", inProcess);
            putAmount(row, "paid", paid);
            putAmount(row, "invalidated", invalidated);
            return row;
        }

        private static void putAmount(Map<String, Object> row, String name, BigInteger raw) {
            row.put(name + "Raw", raw.toString());
            row.put(name, credits(raw));
        }
    }
}
