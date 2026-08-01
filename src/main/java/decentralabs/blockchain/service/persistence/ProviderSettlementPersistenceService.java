package decentralabs.blockchain.service.persistence;

import decentralabs.blockchain.domain.ProviderApproval;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderPayout;
import decentralabs.blockchain.domain.ProviderSettlementOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.sql.*;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Persistence for provider settlement lifecycle:
 * invoice records, approvals, and completed payouts.
 */
@Service
@Slf4j
public class ProviderSettlementPersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final AtomicBoolean tableMissing = new AtomicBoolean(false);

    public ProviderSettlementPersistenceService(ObjectProvider<JdbcTemplate> provider) {
        this.jdbcTemplate = provider.getIfAvailable();
    }

    // ── Provider Invoice Records ────────────────────────────────────────

    private static final RowMapper<ProviderInvoiceRecord> INVOICE_MAPPER = (rs, rowNum) ->
        ProviderInvoiceRecord.builder()
            .id(rs.getLong("id"))
            .labId(rs.getString("lab_id"))
            .providerAddress(rs.getString("provider_address"))
            .claimId(rs.getString("claim_id"))
            .batchId(rs.getString("reservation_hash"))
            .invoiceRef(rs.getString("invoice_ref"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .creditAmount(rs.getBigDecimal("credit_amount"))
            .submittedAt(toInstant(rs.getTimestamp("submitted_at")))
            .status(ProviderInvoiceRecord.Status.valueOf(rs.getString("status")))
            .updatedAt(toInstant(rs.getTimestamp("updated_at")))
            .build();

    @Transactional
    public ProviderInvoiceRecord createInvoiceRecord(ProviderInvoiceRecord record) {
        if (jdbcTemplate == null) return record;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO provider_invoice_records
                        (lab_id, provider_address, claim_id, reservation_hash, invoice_ref, eur_amount, credit_amount, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setString(1, record.getLabId());
                ps.setString(2, record.getProviderAddress());
                ps.setString(3, record.getClaimId());
                ps.setString(4, record.getBatchId());
                ps.setString(5, record.getInvoiceRef());
                ps.setBigDecimal(6, record.getEurAmount());
                ps.setBigDecimal(7, record.getCreditAmount());
                ps.setString(8, record.getStatus().name());
                return ps;
            }, keyHolder);
            record.setId(keyHolder.getKey().longValue());
            return record;
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
            return record;
        }
    }

    @Transactional
    public void updateInvoiceStatus(long id, ProviderInvoiceRecord.Status status) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update(
                "UPDATE provider_invoice_records SET status = ? WHERE id = ?",
                status.name(), id);
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
        }
    }

    public List<ProviderInvoiceRecord> findInvoicesByProvider(String providerAddress) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM provider_invoice_records WHERE provider_address = ? ORDER BY submitted_at DESC",
                INVOICE_MAPPER, providerAddress);
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
            return List.of();
        }
    }

    public List<ProviderInvoiceRecord> findInvoicesByStatus(ProviderInvoiceRecord.Status status) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM provider_invoice_records WHERE status = ? ORDER BY submitted_at DESC",
                INVOICE_MAPPER, status.name());
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
            return List.of();
        }
    }

    public Optional<ProviderInvoiceRecord> findInvoiceById(long id) {
        if (jdbcTemplate == null) return Optional.empty();
        try {
            List<ProviderInvoiceRecord> results = jdbcTemplate.query(
                "SELECT * FROM provider_invoice_records WHERE id = ?", INVOICE_MAPPER, id);
            return results.stream().findFirst();
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
            return Optional.empty();
        }
    }

    public boolean existsClaimId(String claimId) {
        if (jdbcTemplate == null) return false;
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM provider_invoice_records WHERE claim_id = ?",
                Integer.class,
                claimId
            );
            return count != null && count > 0;
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
            return false;
        }
    }

    public boolean existsInvoiceRef(String invoiceRef) {
        if (jdbcTemplate == null) return false;
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM provider_invoice_records WHERE invoice_ref = ?",
                Integer.class,
                invoiceRef
            );
            return count != null && count > 0;
        } catch (DataAccessException ex) {
            logMissing("provider_invoice_records", ex);
            return false;
        }
    }

    // ── Provider Approvals ──────────────────────────────────────────────

    @Transactional
    public ProviderApproval createApproval(ProviderApproval approval) {
        if (jdbcTemplate == null) return approval;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO provider_approvals (invoice_record_id, approved_by, approval_ref, eur_amount)
                    VALUES (?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setLong(1, approval.getInvoiceRecordId());
                ps.setString(2, approval.getApprovedBy());
                ps.setString(3, approval.getApprovalRef());
                ps.setBigDecimal(4, approval.getEurAmount());
                return ps;
            }, keyHolder);
            approval.setId(keyHolder.getKey().longValue());
            return approval;
        } catch (DataAccessException ex) {
            logMissing("provider_approvals", ex);
            return approval;
        }
    }

    // ── Provider Payouts ────────────────────────────────────────────────

    private static final RowMapper<ProviderPayout> PAYOUT_MAPPER = (rs, rowNum) ->
        ProviderPayout.builder()
            .id(rs.getLong("id"))
            .invoiceRecordId(rs.getLong("invoice_record_id"))
            .labId(rs.getString("lab_id"))
            .providerAddress(rs.getString("provider_address"))
            .claimId(rs.getString("claim_id"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .creditAmount(rs.getBigDecimal("credit_amount"))
            .paidAt(toInstant(rs.getTimestamp("paid_at")))
            .paidBy(rs.getString("paid_by"))
            .paymentRef(rs.getString("payment_ref"))
            .paymentAttestation(rs.getString("payment_attestation"))
            .bankRef(rs.getString("bank_ref"))
            .eurcTxHash(rs.getString("eurc_tx_hash"))
            .usdcTxHash(rs.getString("usdc_tx_hash"))
            .build();

    @Transactional
    public ProviderPayout createPayout(ProviderPayout payout) {
        if (jdbcTemplate == null) return payout;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO provider_payouts
                        (invoice_record_id, lab_id, provider_address, claim_id, eur_amount, credit_amount,
                         paid_by, payment_ref, payment_attestation, bank_ref, eurc_tx_hash, usdc_tx_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setLong(1, payout.getInvoiceRecordId());
                ps.setString(2, payout.getLabId());
                ps.setString(3, payout.getProviderAddress());
                ps.setString(4, payout.getClaimId());
                ps.setBigDecimal(5, payout.getEurAmount());
                ps.setBigDecimal(6, payout.getCreditAmount());
                ps.setString(7, payout.getPaidBy());
                ps.setString(8, payout.getPaymentRef());
                ps.setString(9, payout.getPaymentAttestation());
                ps.setString(10, payout.getBankRef());
                ps.setString(11, payout.getEurcTxHash());
                ps.setString(12, payout.getUsdcTxHash());
                return ps;
            }, keyHolder);
            payout.setId(keyHolder.getKey().longValue());
            return payout;
        } catch (DataAccessException ex) {
            logMissing("provider_payouts", ex);
            return payout;
        }
    }

    public boolean existsApprovalRef(String approvalRef) {
        if (jdbcTemplate == null) return false;
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM provider_approvals WHERE approval_ref = ?",
                Integer.class,
                approvalRef
            );
            return count != null && count > 0;
        } catch (DataAccessException ex) {
            logMissing("provider_approvals", ex);
            return false;
        }
    }

    public boolean existsPaymentRef(String paymentRef) {
        if (jdbcTemplate == null) return false;
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM provider_payouts WHERE payment_ref = ?",
                Integer.class,
                paymentRef
            );
            return count != null && count > 0;
        } catch (DataAccessException ex) {
            logMissing("provider_payouts", ex);
            return false;
        }
    }

    public Optional<ProviderApproval> findApprovalByInvoiceId(long invoiceId) {
        if (jdbcTemplate == null) return Optional.empty();
        return jdbcTemplate.query(
            "SELECT * FROM provider_approvals WHERE invoice_record_id = ? ORDER BY approved_at DESC",
            (rs, rowNum) -> ProviderApproval.builder()
                .id(rs.getLong("id"))
                .invoiceRecordId(rs.getLong("invoice_record_id"))
                .approvedBy(rs.getString("approved_by"))
                .approvalRef(rs.getString("approval_ref"))
                .eurAmount(rs.getBigDecimal("eur_amount"))
                .approvedAt(toInstant(rs.getTimestamp("approved_at")))
                .build(),
            invoiceId
        ).stream().findFirst();
    }

    public Optional<ProviderPayout> findPayoutByInvoiceId(long invoiceId) {
        if (jdbcTemplate == null) return Optional.empty();
        return jdbcTemplate.query(
            "SELECT * FROM provider_payouts WHERE invoice_record_id = ? ORDER BY paid_at DESC",
            PAYOUT_MAPPER,
            invoiceId
        ).stream().findFirst();
    }

    public List<ProviderPayout> findPayoutsByProvider(String providerAddress) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM provider_payouts WHERE provider_address = ? ORDER BY paid_at DESC",
                PAYOUT_MAPPER, providerAddress);
        } catch (DataAccessException ex) {
            logMissing("provider_payouts", ex);
            return List.of();
        }
    }

    /**
     * Reserves a domain operation before broadcasting its transaction. The
     * unique operation key is the shared idempotency boundary for SQL and the
     * institutional transaction outbox.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ProviderSettlementOperation createOrLoadSettlementOperation(ProviderSettlementOperation operation) {
        if (jdbcTemplate == null) {
            return operation;
        }
        Optional<ProviderSettlementOperation> existing = findSettlementOperation(operation.getOperationKey());
        if (existing.isPresent()) {
            assertSameOperation(existing.get(), operation);
            return existing.get();
        }
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbcTemplate.update(con -> {
            PreparedStatement ps = con.prepareStatement(
                """
                INSERT INTO provider_settlement_operations (
                    operation_key, action, status, claim_id, claim_id_hash, invoice_record_id,
                    lab_id, provider_address, reservation_hash, invoice_ref, invoice_reference_hash,
                    approval_ref, approval_reference_hash, payment_ref, payment_reference_hash,
                    payment_attestation, payment_attestation_hash, eur_amount, credit_amount,
                    bank_ref, eurc_tx_hash, usdc_tx_hash, requested_by_principal
                ) VALUES (?, ?, 'PREPARED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                new String[]{"id"}
            );
            int i = 1;
            ps.setString(i++, operation.getOperationKey());
            ps.setString(i++, operation.getAction().name());
            ps.setString(i++, operation.getClaimId());
            ps.setString(i++, operation.getClaimIdHash());
            if (operation.getInvoiceRecordId() == null) ps.setNull(i++, Types.BIGINT); else ps.setLong(i++, operation.getInvoiceRecordId());
            ps.setString(i++, operation.getLabId());
            ps.setString(i++, operation.getProviderAddress());
                ps.setString(i++, operation.getBatchId());
            ps.setString(i++, operation.getInvoiceRef());
            ps.setString(i++, operation.getInvoiceReferenceHash());
            ps.setString(i++, operation.getApprovalRef());
            ps.setString(i++, operation.getApprovalReferenceHash());
            ps.setString(i++, operation.getPaymentRef());
            ps.setString(i++, operation.getPaymentReferenceHash());
            ps.setString(i++, operation.getPaymentAttestation());
            ps.setString(i++, operation.getPaymentAttestationHash());
            ps.setBigDecimal(i++, operation.getEurAmount());
            ps.setBigDecimal(i++, operation.getCreditAmount());
            ps.setString(i++, operation.getBankRef());
            ps.setString(i++, operation.getEurcTxHash());
            ps.setString(i++, operation.getUsdcTxHash());
            ps.setString(i, operation.getRequestedByPrincipal());
            return ps;
        }, keyHolder);
        operation.setId(keyHolder.getKey().longValue());
        return operation;
    }

    public Optional<ProviderSettlementOperation> findSettlementOperation(String operationKey) {
        if (jdbcTemplate == null) return Optional.empty();
        return jdbcTemplate.query(
            "SELECT * FROM provider_settlement_operations WHERE operation_key = ?",
            SETTLEMENT_OPERATION_MAPPER,
            operationKey
        ).stream().findFirst();
    }

    public List<ProviderSettlementOperation> findPendingSettlementOperations(int limit) {
        if (jdbcTemplate == null) return List.of();
        return jdbcTemplate.query(
            "SELECT * FROM provider_settlement_operations WHERE status NOT IN ('PROJECTED', 'REJECTED') ORDER BY updated_at ASC LIMIT ?",
            SETTLEMENT_OPERATION_MAPPER,
            Math.max(1, limit)
        );
    }

    @Transactional
    public void markSettlementClaimInvalidated(String claimIdHash, ProviderInvoiceRecord.Status status) {
        if (jdbcTemplate == null) return;
        jdbcTemplate.update(
            """
            UPDATE provider_invoice_records invoice
            JOIN provider_settlement_operations operation ON operation.invoice_record_id = invoice.id
            SET invoice.status = ?, invoice.updated_at = CURRENT_TIMESTAMP
            WHERE operation.claim_id_hash = ?
            """,
            status.name(), claimIdHash
        );
        jdbcTemplate.update(
            """
            UPDATE provider_settlement_operations
            SET status='REJECTED', last_error='Claim was disputed or reversed'
            WHERE claim_id_hash=? AND status <> 'PROJECTED'
            """,
            claimIdHash
        );
    }

    @Transactional
    public void markSettlementBatchInvalidated(String batchId) {
        if (jdbcTemplate == null) return;
        jdbcTemplate.update(
            """
            UPDATE provider_settlement_operations
            SET status='REJECTED', last_error='Settlement batch was disputed or reversed'
            WHERE reservation_hash=? AND status <> 'PROJECTED'
            """,
            batchId
        );
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markSettlementMined(
        String operationKey,
        String transactionHash,
        BigInteger blockNumber,
        String blockHash,
        String chainActor
    ) {
        if (jdbcTemplate == null) return;
        jdbcTemplate.update(
            """
            UPDATE provider_settlement_operations
            SET status='MINED', transaction_hash=?, block_number=?, block_hash=?, chain_actor=?, last_error=NULL
            WHERE operation_key=? AND status <> 'PROJECTED'
            """,
            transactionHash, blockNumber, blockHash, chainActor, operationKey
        );
    }

    /** Projects a mined on-chain operation into the SQL read model idempotently. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void projectSettlementOperation(
        String operationKey,
        String chainActor,
        String transactionHash,
        BigInteger blockNumber,
        String blockHash
    ) {
        if (jdbcTemplate == null) return;
        ProviderSettlementOperation operation = findSettlementOperation(operationKey)
            .orElseThrow(() -> new IllegalArgumentException("Settlement operation not found: " + operationKey));
        if (operation.getStatus() == ProviderSettlementOperation.Status.PROJECTED) return;

        markSettlementMined(operationKey, transactionHash, blockNumber, blockHash, chainActor);
        switch (operation.getAction()) {
            case SUBMIT -> projectSubmit(operation);
            case APPROVE -> projectApproval(operation, chainActor);
            case PAY -> projectPayment(operation, chainActor);
        }
        jdbcTemplate.update(
            "UPDATE provider_settlement_operations SET status='PROJECTED', updated_at=CURRENT_TIMESTAMP WHERE operation_key=?",
            operationKey
        );
    }

    /** Records a chain event so the normal reconciler can complete projection. */
    @Transactional
    public void markSettlementEvent(
        ProviderSettlementOperation.Action action,
        String claimIdHash,
        String referenceHash,
        String transactionHash,
        BigInteger blockNumber,
        String blockHash,
        String chainActor
    ) {
        if (jdbcTemplate == null) return;
        String sql = switch (action) {
            case SUBMIT -> "UPDATE provider_settlement_operations SET status='MINED', transaction_hash=?, block_number=?, block_hash=?, chain_actor=? WHERE action='SUBMIT' AND claim_id_hash=? AND status <> 'PROJECTED'";
            case APPROVE -> "UPDATE provider_settlement_operations SET status='MINED', transaction_hash=?, block_number=?, block_hash=?, chain_actor=? WHERE action='APPROVE' AND claim_id_hash=? AND approval_reference_hash=? AND status <> 'PROJECTED'";
            case PAY -> "UPDATE provider_settlement_operations SET status='MINED', transaction_hash=?, block_number=?, block_hash=?, chain_actor=? WHERE action='PAY' AND claim_id_hash=? AND payment_reference_hash=? AND status <> 'PROJECTED'";
        };
        jdbcTemplate.update(sql, transactionHash, blockNumber, blockHash, chainActor, claimIdHash, referenceHash);
    }

    public Optional<ProviderInvoiceRecord> findInvoiceByClaimId(String claimId) {
        if (jdbcTemplate == null) return Optional.empty();
        return jdbcTemplate.query(
            "SELECT * FROM provider_invoice_records WHERE claim_id = ?",
            INVOICE_MAPPER,
            claimId
        ).stream().findFirst();
    }

    private void projectSubmit(ProviderSettlementOperation operation) {
        ProviderInvoiceRecord invoice = findInvoiceByClaimId(operation.getClaimId()).orElseGet(() ->
            createInvoiceRecord(ProviderInvoiceRecord.builder()
                .labId(operation.getLabId())
                .providerAddress(operation.getProviderAddress())
                .claimId(operation.getClaimId())
                .batchId(operation.getBatchId())
                .invoiceRef(operation.getInvoiceRef())
                .eurAmount(operation.getEurAmount())
                .creditAmount(operation.getCreditAmount())
                .status(ProviderInvoiceRecord.Status.SUBMITTED)
                .build())
        );
        if (invoice.getId() == null) throw new IllegalStateException("Unable to persist the on-chain settlement invoice projection");
        jdbcTemplate.update(
            "UPDATE provider_settlement_operations SET invoice_record_id=? WHERE operation_key=?",
            invoice.getId(), operation.getOperationKey()
        );
    }

    private void projectApproval(ProviderSettlementOperation operation, String chainActor) {
        long invoiceId = requireInvoiceId(operation);
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM provider_approvals WHERE invoice_record_id = ?",
            Integer.class,
            invoiceId
        );
        if (count == null || count == 0) {
            ProviderApproval approval = createApproval(ProviderApproval.builder()
                .invoiceRecordId(invoiceId)
                .approvedBy(chainActor)
                .approvalRef(operation.getApprovalRef())
                .eurAmount(operation.getEurAmount())
                .build());
            if (approval.getId() == null) throw new IllegalStateException("Unable to persist the on-chain settlement approval projection");
        }
        updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.APPROVED);
    }

    private void projectPayment(ProviderSettlementOperation operation, String chainActor) {
        long invoiceId = requireInvoiceId(operation);
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM provider_payouts WHERE invoice_record_id = ?",
            Integer.class,
            invoiceId
        );
        if (count == null || count == 0) {
            ProviderInvoiceRecord invoice = findInvoiceById(invoiceId).orElseThrow();
            ProviderPayout payout = createPayout(ProviderPayout.builder()
                .invoiceRecordId(invoiceId)
                .labId(invoice.getLabId())
                .providerAddress(invoice.getProviderAddress())
                .claimId(invoice.getClaimId())
                .eurAmount(operation.getEurAmount())
                .creditAmount(operation.getCreditAmount())
                .paidBy(chainActor)
                .paymentRef(operation.getPaymentRef())
                .paymentAttestation(operation.getPaymentAttestation())
                .bankRef(operation.getBankRef())
                .eurcTxHash(operation.getEurcTxHash())
                .usdcTxHash(operation.getUsdcTxHash())
                .build());
            if (payout.getId() == null) throw new IllegalStateException("Unable to persist the on-chain settlement payment projection");
        }
        updateInvoiceStatus(invoiceId, ProviderInvoiceRecord.Status.PAID);
    }

    private long requireInvoiceId(ProviderSettlementOperation operation) {
        if (operation.getInvoiceRecordId() == null) {
            throw new IllegalStateException("Settlement operation has no projected invoice: " + operation.getOperationKey());
        }
        return operation.getInvoiceRecordId();
    }

    private void assertSameOperation(ProviderSettlementOperation existing, ProviderSettlementOperation requested) {
        if (existing.getAction() != requested.getAction()
            || !java.util.Objects.equals(existing.getClaimIdHash(), requested.getClaimIdHash())
            || !java.util.Objects.equals(existing.getLabId(), requested.getLabId())
            || !java.util.Objects.equals(existing.getProviderAddress(), requested.getProviderAddress())
            || !java.util.Objects.equals(existing.getBatchId(), requested.getBatchId())
            || !java.util.Objects.equals(existing.getInvoiceReferenceHash(), requested.getInvoiceReferenceHash())
            || !java.util.Objects.equals(existing.getApprovalReferenceHash(), requested.getApprovalReferenceHash())
            || !java.util.Objects.equals(existing.getPaymentReferenceHash(), requested.getPaymentReferenceHash())
            || !sameAmount(existing.getEurAmount(), requested.getEurAmount())
            || !sameAmount(existing.getCreditAmount(), requested.getCreditAmount())) {
            throw new IllegalArgumentException("Settlement idempotency key was reused with a different payload");
        }
    }

    private boolean sameAmount(java.math.BigDecimal existing, java.math.BigDecimal requested) {
        return existing == null ? requested == null : requested != null && existing.compareTo(requested) == 0;
    }

    private static final RowMapper<ProviderSettlementOperation> SETTLEMENT_OPERATION_MAPPER = (rs, rowNum) ->
        ProviderSettlementOperation.builder()
            .id(rs.getLong("id"))
            .operationKey(rs.getString("operation_key"))
            .action(ProviderSettlementOperation.Action.valueOf(rs.getString("action")))
            .status(ProviderSettlementOperation.Status.valueOf(rs.getString("status")))
            .claimId(rs.getString("claim_id"))
            .claimIdHash(rs.getString("claim_id_hash"))
            .invoiceRecordId((Long) rs.getObject("invoice_record_id"))
            .labId(rs.getString("lab_id"))
            .providerAddress(rs.getString("provider_address"))
            .batchId(rs.getString("reservation_hash"))
            .invoiceRef(rs.getString("invoice_ref"))
            .invoiceReferenceHash(rs.getString("invoice_reference_hash"))
            .approvalRef(rs.getString("approval_ref"))
            .approvalReferenceHash(rs.getString("approval_reference_hash"))
            .paymentRef(rs.getString("payment_ref"))
            .paymentReferenceHash(rs.getString("payment_reference_hash"))
            .paymentAttestation(rs.getString("payment_attestation"))
            .paymentAttestationHash(rs.getString("payment_attestation_hash"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .creditAmount(rs.getBigDecimal("credit_amount"))
            .bankRef(rs.getString("bank_ref"))
            .eurcTxHash(rs.getString("eurc_tx_hash"))
            .usdcTxHash(rs.getString("usdc_tx_hash"))
            .requestedByPrincipal(rs.getString("requested_by_principal"))
            .transactionHash(rs.getString("transaction_hash"))
            .blockNumber(Optional.ofNullable(rs.getBigDecimal("block_number")).map(value -> value.toBigInteger()).orElse(null))
            .blockHash(rs.getString("block_hash"))
            .chainActor(rs.getString("chain_actor"))
            .updatedAt(toInstant(rs.getTimestamp("updated_at")))
            .build();

    // ── Helpers ─────────────────────────────────────────────────────────

    private static Instant toInstant(Timestamp ts) {
        return ts != null ? ts.toInstant() : null;
    }

    private void logMissing(String table, DataAccessException ex) {
        if (tableMissing.compareAndSet(false, true)) {
            log.warn("{} persistence skipped (table or schema missing): {}", table, ex.getMessage());
        }
    }
}
