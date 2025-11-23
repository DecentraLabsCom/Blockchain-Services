package decentralabs.blockchain.service.persistence;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Minimal persistence helper to mirror on-chain reservation lifecycle into MySQL.
 * Designed to fail gracefully when JDBC is not configured or the table is absent.
 */
@Service
@Slf4j
public class ReservationPersistenceService {

    private final JdbcTemplate jdbcTemplate; // May be null if no datasource provided

    private final AtomicBoolean tableMissing = new AtomicBoolean(false);

    public ReservationPersistenceService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    /**
     * Upserts reservation row and links to auth_users by wallet address (creating it if needed).
     */
    @Transactional
    public void upsertReservation(String txHash, String walletAddress, String labId, Instant start, Instant end, String status) {
        if (jdbcTemplate == null) {
            log.debug("Skipping reservation persistence (no JdbcTemplate/data source)");
            return;
        }
        if (txHash == null || txHash.isBlank()) {
            return;
        }
        if (walletAddress == null || walletAddress.isBlank()) {
            log.debug("Skipping reservation persistence for {} (missing wallet)", txHash);
            return;
        }
        try {
            Long userId = findOrCreateUser(walletAddress);
            jdbcTemplate.update(
                """
                INSERT INTO lab_reservations (transaction_hash, user_id, wallet_address, lab_id, start_time, end_time, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    user_id=VALUES(user_id),
                    wallet_address=VALUES(wallet_address),
                    lab_id=VALUES(lab_id),
                    start_time=IFNULL(VALUES(start_time), start_time),
                    end_time=IFNULL(VALUES(end_time), end_time),
                    status=VALUES(status),
                    updated_at=CURRENT_TIMESTAMP
                """,
                txHash,
                userId,
                walletAddress,
                labId,
                start != null ? Timestamp.from(start) : null,
                end != null ? Timestamp.from(end) : null,
                status
            );
        } catch (DataAccessException ex) {
            if (tableMissing.compareAndSet(false, true)) {
                log.warn("lab_reservations persistence skipped (table or schema missing): {}", ex.getMessage());
            }
        } catch (Exception ex) {
            log.warn("Failed to upsert reservation {}: {}", txHash, ex.getMessage());
        }
    }

    private Long findOrCreateUser(String walletAddress) {
        if (walletAddress == null || walletAddress.isBlank()) {
            return null;
        }
        try {
            Long existing = jdbcTemplate.query(
                "SELECT id FROM auth_users WHERE wallet_address = ? LIMIT 1",
                ps -> ps.setString(1, walletAddress),
                rs -> rs.next() ? rs.getLong(1) : null
            );
            if (existing != null) {
                return existing;
            }
            jdbcTemplate.update(
                "INSERT INTO auth_users (wallet_address, created_at, updated_at, is_active) VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)",
                walletAddress
            );
            return jdbcTemplate.query(
                "SELECT id FROM auth_users WHERE wallet_address = ? LIMIT 1",
                ps -> ps.setString(1, walletAddress),
                rs -> rs.next() ? rs.getLong(1) : null
            );
        } catch (DataAccessException ex) {
            if (tableMissing.compareAndSet(false, true)) {
                log.warn("auth_users/lab_reservations tables not available; skipping persistence: {}", ex.getMessage());
            }
            return null;
        }
    }
}
