package decentralabs.blockchain.service.persistence;

import decentralabs.blockchain.domain.ProviderApproval;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderPayout;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
                    INSERT INTO provider_invoice_records (lab_id, provider_address, invoice_ref, eur_amount, credit_amount, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setString(1, record.getLabId());
                ps.setString(2, record.getProviderAddress());
                ps.setString(3, record.getInvoiceRef());
                ps.setBigDecimal(4, record.getEurAmount());
                ps.setBigDecimal(5, record.getCreditAmount());
                ps.setString(6, record.getStatus().name());
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

    // ── Provider Approvals ──────────────────────────────────────────────

    private static final RowMapper<ProviderApproval> APPROVAL_MAPPER = (rs, rowNum) ->
        ProviderApproval.builder()
            .id(rs.getLong("id"))
            .invoiceRecordId(rs.getLong("invoice_record_id"))
            .approvedBy(rs.getString("approved_by"))
            .approvalRef(rs.getString("approval_ref"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .approvedAt(toInstant(rs.getTimestamp("approved_at")))
            .build();

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
            .labId(rs.getString("lab_id"))
            .providerAddress(rs.getString("provider_address"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .creditAmount(rs.getBigDecimal("credit_amount"))
            .paidAt(toInstant(rs.getTimestamp("paid_at")))
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
                    INSERT INTO provider_payouts (lab_id, provider_address, eur_amount, credit_amount, bank_ref, eurc_tx_hash, usdc_tx_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setString(1, payout.getLabId());
                ps.setString(2, payout.getProviderAddress());
                ps.setBigDecimal(3, payout.getEurAmount());
                ps.setBigDecimal(4, payout.getCreditAmount());
                ps.setString(5, payout.getBankRef());
                ps.setString(6, payout.getEurcTxHash());
                ps.setString(7, payout.getUsdcTxHash());
                return ps;
            }, keyHolder);
            payout.setId(keyHolder.getKey().longValue());
            return payout;
        } catch (DataAccessException ex) {
            logMissing("provider_payouts", ex);
            return payout;
        }
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
