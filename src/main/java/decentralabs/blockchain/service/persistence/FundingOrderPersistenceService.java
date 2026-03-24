package decentralabs.blockchain.service.persistence;

import decentralabs.blockchain.domain.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.sql.*;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Persistence service for the funding lifecycle: funding orders, invoices,
 * and payment reconciliations.
 */
@Service
@Slf4j
public class FundingOrderPersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final AtomicBoolean tableMissing = new AtomicBoolean(false);

    public FundingOrderPersistenceService(ObjectProvider<JdbcTemplate> provider) {
        this.jdbcTemplate = provider.getIfAvailable();
    }

    // ── Funding Orders ──────────────────────────────────────────────────

    private static final RowMapper<FundingOrder> FUNDING_ORDER_MAPPER = (rs, rowNum) -> FundingOrder.builder()
            .id(rs.getLong("id"))
            .institutionAddress(rs.getString("institution_address"))
            .eurGrossAmount(rs.getBigDecimal("eur_gross_amount"))
            .creditAmount(rs.getBigDecimal("credit_amount"))
            .status(FundingOrder.Status.valueOf(rs.getString("status")))
            .reference(rs.getString("reference"))
            .createdAt(toInstant(rs.getTimestamp("created_at")))
            .updatedAt(toInstant(rs.getTimestamp("updated_at")))
            .expiresAt(toInstant(rs.getTimestamp("expires_at")))
            .build();

    @Transactional
    public FundingOrder createFundingOrder(FundingOrder order) {
        if (jdbcTemplate == null) return order;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO funding_orders (institution_address, eur_gross_amount, credit_amount, status, reference, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setString(1, order.getInstitutionAddress());
                ps.setBigDecimal(2, order.getEurGrossAmount());
                ps.setBigDecimal(3, order.getCreditAmount());
                ps.setString(4, order.getStatus().name());
                ps.setString(5, order.getReference());
                ps.setTimestamp(6, toTimestamp(order.getExpiresAt()));
                return ps;
            }, keyHolder);
            order.setId(keyHolder.getKey().longValue());
            return order;
        } catch (DataAccessException ex) {
            logMissing("funding_orders", ex);
            return order;
        }
    }

    @Transactional
    public void updateFundingOrderStatus(long orderId, FundingOrder.Status status) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update("UPDATE funding_orders SET status = ? WHERE id = ?", status.name(), orderId);
        } catch (DataAccessException ex) {
            logMissing("funding_orders", ex);
        }
    }

    public Optional<FundingOrder> findFundingOrderById(long id) {
        if (jdbcTemplate == null) return Optional.empty();
        try {
            List<FundingOrder> results = jdbcTemplate.query(
                "SELECT * FROM funding_orders WHERE id = ?", FUNDING_ORDER_MAPPER, id);
            return results.stream().findFirst();
        } catch (DataAccessException ex) {
            logMissing("funding_orders", ex);
            return Optional.empty();
        }
    }

    public List<FundingOrder> findFundingOrdersByInstitution(String institutionAddress) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM funding_orders WHERE institution_address = ? ORDER BY created_at DESC",
                FUNDING_ORDER_MAPPER, institutionAddress);
        } catch (DataAccessException ex) {
            logMissing("funding_orders", ex);
            return List.of();
        }
    }

    public List<FundingOrder> findFundingOrdersByStatus(FundingOrder.Status status) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM funding_orders WHERE status = ? ORDER BY created_at DESC",
                FUNDING_ORDER_MAPPER, status.name());
        } catch (DataAccessException ex) {
            logMissing("funding_orders", ex);
            return List.of();
        }
    }

    // ── Funding Invoices ────────────────────────────────────────────────

    private static final RowMapper<FundingInvoice> FUNDING_INVOICE_MAPPER = (rs, rowNum) -> FundingInvoice.builder()
            .id(rs.getLong("id"))
            .fundingOrderId(rs.getLong("funding_order_id"))
            .invoiceNumber(rs.getString("invoice_number"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .issuedAt(toInstant(rs.getTimestamp("issued_at")))
            .dueAt(toInstant(rs.getTimestamp("due_at")))
            .status(FundingInvoice.Status.valueOf(rs.getString("status")))
            .build();

    @Transactional
    public FundingInvoice createFundingInvoice(FundingInvoice invoice) {
        if (jdbcTemplate == null) return invoice;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO funding_invoices (funding_order_id, invoice_number, eur_amount, due_at, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setLong(1, invoice.getFundingOrderId());
                ps.setString(2, invoice.getInvoiceNumber());
                ps.setBigDecimal(3, invoice.getEurAmount());
                ps.setTimestamp(4, toTimestamp(invoice.getDueAt()));
                ps.setString(5, invoice.getStatus().name());
                return ps;
            }, keyHolder);
            invoice.setId(keyHolder.getKey().longValue());
            return invoice;
        } catch (DataAccessException ex) {
            logMissing("funding_invoices", ex);
            return invoice;
        }
    }

    public List<FundingInvoice> findInvoicesByOrder(long orderId) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM funding_invoices WHERE funding_order_id = ?",
                FUNDING_INVOICE_MAPPER, orderId);
        } catch (DataAccessException ex) {
            logMissing("funding_invoices", ex);
            return List.of();
        }
    }

    // ── Payment Reconciliations ─────────────────────────────────────────

    private static final RowMapper<PaymentReconciliation> RECONCILIATION_MAPPER = (rs, rowNum) -> PaymentReconciliation.builder()
            .id(rs.getLong("id"))
            .fundingOrderId(rs.getLong("funding_order_id"))
            .paymentRef(rs.getString("payment_ref"))
            .eurAmount(rs.getBigDecimal("eur_amount"))
            .paymentMethod(rs.getString("payment_method"))
            .reconciledAt(toInstant(rs.getTimestamp("reconciled_at")))
            .build();

    @Transactional
    public PaymentReconciliation createReconciliation(PaymentReconciliation recon) {
        if (jdbcTemplate == null) return recon;
        try {
            KeyHolder keyHolder = new GeneratedKeyHolder();
            jdbcTemplate.update(con -> {
                PreparedStatement ps = con.prepareStatement(
                    """
                    INSERT INTO payment_reconciliations (funding_order_id, payment_ref, eur_amount, payment_method)
                    VALUES (?, ?, ?, ?)
                    """,
                    new String[]{"id"}
                );
                ps.setLong(1, recon.getFundingOrderId());
                ps.setString(2, recon.getPaymentRef());
                ps.setBigDecimal(3, recon.getEurAmount());
                ps.setString(4, recon.getPaymentMethod());
                return ps;
            }, keyHolder);
            recon.setId(keyHolder.getKey().longValue());
            return recon;
        } catch (DataAccessException ex) {
            logMissing("payment_reconciliations", ex);
            return recon;
        }
    }

    public List<PaymentReconciliation> findReconciliationsByOrder(long orderId) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM payment_reconciliations WHERE funding_order_id = ?",
                RECONCILIATION_MAPPER, orderId);
        } catch (DataAccessException ex) {
            logMissing("payment_reconciliations", ex);
            return List.of();
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static Instant toInstant(Timestamp ts) {
        return ts != null ? ts.toInstant() : null;
    }

    private static Timestamp toTimestamp(Instant instant) {
        return instant != null ? Timestamp.from(instant) : null;
    }

    private void logMissing(String table, DataAccessException ex) {
        if (tableMissing.compareAndSet(false, true)) {
            log.warn("{} persistence skipped (table or schema missing): {}", table, ex.getMessage());
        }
    }
}
