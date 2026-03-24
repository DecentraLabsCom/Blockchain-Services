package decentralabs.blockchain.service.persistence;

import decentralabs.blockchain.domain.CreditAccount;
import decentralabs.blockchain.domain.CreditLot;
import decentralabs.blockchain.domain.CreditMovement;
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
 * Persistence for off-chain credit account projections,
 * credit lots, and movement audit trail.
 */
@Service
@Slf4j
public class CreditAccountPersistenceService {

    private final JdbcTemplate jdbcTemplate;
    private final AtomicBoolean tableMissing = new AtomicBoolean(false);

    public CreditAccountPersistenceService(ObjectProvider<JdbcTemplate> provider) {
        this.jdbcTemplate = provider.getIfAvailable();
    }

    // ── Credit Accounts ─────────────────────────────────────────────────

    private static final RowMapper<CreditAccount> ACCOUNT_MAPPER = (rs, rowNum) -> CreditAccount.builder()
            .id(rs.getLong("id"))
            .accountAddress(rs.getString("account_address"))
            .available(rs.getBigDecimal("available"))
            .locked(rs.getBigDecimal("locked"))
            .consumed(rs.getBigDecimal("consumed"))
            .adjusted(rs.getBigDecimal("adjusted"))
            .expired(rs.getBigDecimal("expired"))
            .updatedAt(toInstant(rs.getTimestamp("updated_at")))
            .build();

    @Transactional
    public void upsertCreditAccount(CreditAccount account) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update(
                """
                INSERT INTO credit_accounts (account_address, available, locked, consumed, adjusted, expired)
                VALUES (?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    available=VALUES(available), locked=VALUES(locked), consumed=VALUES(consumed),
                    adjusted=VALUES(adjusted), expired=VALUES(expired), updated_at=CURRENT_TIMESTAMP
                """,
                account.getAccountAddress(),
                account.getAvailable(), account.getLocked(), account.getConsumed(),
                account.getAdjusted(), account.getExpired()
            );
        } catch (DataAccessException ex) {
            logMissing("credit_accounts", ex);
        }
    }

    public Optional<CreditAccount> findCreditAccount(String address) {
        if (jdbcTemplate == null) return Optional.empty();
        try {
            List<CreditAccount> results = jdbcTemplate.query(
                "SELECT * FROM credit_accounts WHERE account_address = ?",
                ACCOUNT_MAPPER, address);
            return results.stream().findFirst();
        } catch (DataAccessException ex) {
            logMissing("credit_accounts", ex);
            return Optional.empty();
        }
    }

    // ── Credit Lots ─────────────────────────────────────────────────────

    private static final RowMapper<CreditLot> LOT_MAPPER = (rs, rowNum) -> CreditLot.builder()
            .id(rs.getLong("id"))
            .accountAddress(rs.getString("account_address"))
            .lotIndex(rs.getInt("lot_index"))
            .fundingOrderId(rs.getObject("funding_order_id") != null ? rs.getLong("funding_order_id") : null)
            .eurGrossAmount(rs.getBigDecimal("eur_gross_amount"))
            .creditAmount(rs.getBigDecimal("credit_amount"))
            .remaining(rs.getBigDecimal("remaining"))
            .issuedAt(toInstant(rs.getTimestamp("issued_at")))
            .expiresAt(toInstant(rs.getTimestamp("expires_at")))
            .expired(rs.getBoolean("expired"))
            .build();

    @Transactional
    public void upsertCreditLot(CreditLot lot) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update(
                """
                INSERT INTO credit_lots (account_address, lot_index, funding_order_id, eur_gross_amount, credit_amount, remaining, issued_at, expires_at, expired)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    remaining=VALUES(remaining), expired=VALUES(expired)
                """,
                lot.getAccountAddress(), lot.getLotIndex(), lot.getFundingOrderId(),
                lot.getEurGrossAmount(), lot.getCreditAmount(), lot.getRemaining(),
                toTimestamp(lot.getIssuedAt()), toTimestamp(lot.getExpiresAt()), lot.isExpired()
            );
        } catch (DataAccessException ex) {
            logMissing("credit_lots", ex);
        }
    }

    public List<CreditLot> findCreditLots(String address) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM credit_lots WHERE account_address = ? ORDER BY lot_index ASC",
                LOT_MAPPER, address);
        } catch (DataAccessException ex) {
            logMissing("credit_lots", ex);
            return List.of();
        }
    }

    public List<CreditLot> findExpiringLots(Instant before) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                """
                SELECT * FROM credit_lots
                WHERE expired = FALSE AND expires_at IS NOT NULL AND expires_at <= ?
                ORDER BY expires_at ASC
                """,
                LOT_MAPPER, Timestamp.from(before));
        } catch (DataAccessException ex) {
            logMissing("credit_lots", ex);
            return List.of();
        }
    }

    // ── Credit Movements ────────────────────────────────────────────────

    private static final RowMapper<CreditMovement> MOVEMENT_MAPPER = (rs, rowNum) -> CreditMovement.builder()
            .id(rs.getLong("id"))
            .accountAddress(rs.getString("account_address"))
            .lotIndex(rs.getObject("lot_index") != null ? rs.getInt("lot_index") : null)
            .movementType(CreditMovement.Type.valueOf(rs.getString("movement_type")))
            .amount(rs.getBigDecimal("amount"))
            .reservationRef(rs.getString("reservation_ref"))
            .reference(rs.getString("reference"))
            .createdAt(toInstant(rs.getTimestamp("created_at")))
            .build();

    @Transactional
    public void recordMovement(CreditMovement movement) {
        if (jdbcTemplate == null) return;
        try {
            jdbcTemplate.update(
                """
                INSERT INTO credit_movements (account_address, lot_index, movement_type, amount, reservation_ref, reference)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                movement.getAccountAddress(), movement.getLotIndex(),
                movement.getMovementType().name(), movement.getAmount(),
                movement.getReservationRef(), movement.getReference()
            );
        } catch (DataAccessException ex) {
            logMissing("credit_movements", ex);
        }
    }

    public List<CreditMovement> findMovements(String address, int limit) {
        if (jdbcTemplate == null) return List.of();
        try {
            return jdbcTemplate.query(
                "SELECT * FROM credit_movements WHERE account_address = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                MOVEMENT_MAPPER, address, limit);
        } catch (DataAccessException ex) {
            logMissing("credit_movements", ex);
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
