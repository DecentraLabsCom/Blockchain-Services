package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.util.LogSanitizer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class InstitutionalCheckInOutboxService {
    private static final long PROCESSING_STALE_AFTER_SECONDS = 15 * 60;

    private final JdbcTemplate jdbcTemplate;

    public InstitutionalCheckInOutboxService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    public InstitutionalCheckInOutboxRecord enqueueAccessGranted(
        String reservationKey,
        String labId,
        String institutionalWallet,
        String pucHash,
        String accessSessionId
    ) {
        requireConfigured();
        if (!hasText(reservationKey) || !hasText(institutionalWallet) || !hasText(pucHash)) {
            throw new IllegalArgumentException("Missing required check-in outbox fields");
        }
        jdbcTemplate.update(
            """
            INSERT INTO institutional_checkin_outbox (
                reservation_key, lab_id, institutional_wallet, wallet_address, puc_hash, access_session_id,
                status, attempts, next_attempt_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE
                reservation_key = VALUES(reservation_key)
            """,
            reservationKey,
            labId,
            institutionalWallet,
            institutionalWallet,
            pucHash,
            accessSessionId
        );
        return findByReservationKey(reservationKey);
    }

    public InstitutionalCheckInOutboxRecord findByReservationKey(String reservationKey) {
        requireConfigured();
        return jdbcTemplate.queryForObject(
            """
            SELECT id, reservation_key, lab_id, institutional_wallet, puc_hash,
                   access_session_id, status, attempts, next_attempt_at, tx_hash, wallet_address, chain_id, nonce, submitted_at, version
            FROM institutional_checkin_outbox WHERE reservation_key = ?
            """,
            (rs, rowNum) -> mapRow(rs),
            reservationKey
        );
    }

    public InstitutionalCheckInOutboxRecord findById(long id) {
        requireConfigured();
        return jdbcTemplate.queryForObject(
            """
            SELECT id, reservation_key, lab_id, institutional_wallet, puc_hash,
                   access_session_id, status, attempts, next_attempt_at, tx_hash, wallet_address, chain_id, nonce, submitted_at, version
            FROM institutional_checkin_outbox WHERE id = ?
            """,
            (rs, rowNum) -> mapRow(rs),
            id
        );
    }

    /**
     * Starts a new check-in generation only after the caller has revalidated
     * the reservation. It never reuses a transaction hash or nonce from a
     * terminal generation.
     */
    public InstitutionalCheckInOutboxRecord restartTerminalFailure(long id) {
        requireConfigured();
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'PENDING',
                attempts = 0,
                next_attempt_at = CURRENT_TIMESTAMP,
                tx_hash = NULL,
                chain_id = NULL,
                nonce = NULL,
                submitted_at = NULL,
                mined_at = NULL,
                last_error = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('MINED_FAILED', 'FAILED')
            """,
            id
        );
        return findById(id);
    }

    public List<InstitutionalCheckInOutboxRecord> findDue(Instant now, int limit) {
        if (jdbcTemplate == null || now == null || limit <= 0) {
            return List.of();
        }
        try {
            Instant staleProcessingCutoff = now.minusSeconds(PROCESSING_STALE_AFTER_SECONDS);
            return jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, wallet_address, chain_id, nonce, submitted_at, version
                FROM institutional_checkin_outbox
                WHERE (status IN ('PENDING', 'RETRY') AND next_attempt_at <= ?)
                   OR (status = 'SUBMITTING' AND updated_at <= ?)
                ORDER BY next_attempt_at ASC, id ASC
                LIMIT ?
                """,
                (rs, rowNum) -> mapRow(rs),
                Timestamp.from(now),
                Timestamp.from(staleProcessingCutoff),
                limit
            );
        } catch (Exception ex) {
            log.warn("Institutional check-in outbox lookup skipped: {}", LogSanitizer.sanitize(ex.getMessage()));
            return List.of();
        }
    }

    public boolean claim(long id) {
        if (jdbcTemplate == null) {
            return false;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTING', version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND (
                status IN ('PENDING', 'RETRY')
                OR (status = 'SUBMITTING' AND updated_at <= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 15 MINUTE))
              )
            """,
            id
        );
        return updated > 0;
    }

    /**
     * Allocates a unique nonce while the caller holds the database transaction
     * that serializes this wallet's signing and broadcast section.
     */
    public BigInteger reserveNextNonce(BigInteger chainId, String walletAddress, BigInteger nodePendingNonce) {
        requireConfigured();
        if (chainId == null || chainId.signum() <= 0 || !hasText(walletAddress)
                || nodePendingNonce == null || nodePendingNonce.signum() < 0) {
            throw new IllegalArgumentException("Missing chain, wallet address or pending nonce");
        }
        jdbcTemplate.update(
            "INSERT INTO institutional_wallet_nonce (chain_id, wallet_address, next_nonce) VALUES (?, ?, ?) "
                + "ON DUPLICATE KEY UPDATE wallet_address = VALUES(wallet_address)",
            chainId,
            walletAddress,
            nodePendingNonce
        );
        BigInteger storedNext = jdbcTemplate.queryForObject(
            "SELECT next_nonce FROM institutional_wallet_nonce WHERE chain_id = ? AND wallet_address = ? FOR UPDATE",
            BigInteger.class,
            chainId,
            walletAddress
        );
        BigInteger nonce = storedNext.max(nodePendingNonce);
        jdbcTemplate.update(
            "UPDATE institutional_wallet_nonce SET next_nonce = ?, updated_at = CURRENT_TIMESTAMP "
                + "WHERE chain_id = ? AND wallet_address = ?",
            nonce.add(BigInteger.ONE),
            chainId,
            walletAddress
        );
        return nonce;
    }

    public void markNonceReserved(long id, String walletAddress, BigInteger chainId, BigInteger nonce) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            "UPDATE institutional_checkin_outbox SET wallet_address = ?, chain_id = ?, nonce = ?, "
                + "version = version + 1, updated_at = CURRENT_TIMESTAMP "
                + "WHERE id = ? AND status = 'SUBMITTING'",
            walletAddress,
            chainId,
            nonce,
            id
        );
    }

    public List<InstitutionalCheckInOutboxRecord> findSubmitted(Instant now, int limit) {
        if (jdbcTemplate == null || now == null || limit <= 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, wallet_address, chain_id, nonce, submitted_at, version
                FROM institutional_checkin_outbox
                WHERE status = 'SUBMITTED'
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                (rs, rowNum) -> mapRow(rs),
                limit
            );
        } catch (Exception ex) {
            log.warn("Institutional check-in receipt lookup skipped: {}", LogSanitizer.sanitize(ex.getMessage()));
            return List.of();
        }
    }

    public List<InstitutionalCheckInOutboxRecord> findStuckUnknown(int limit) {
        if (jdbcTemplate == null || limit <= 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, wallet_address, chain_id, nonce, submitted_at, version
                FROM institutional_checkin_outbox
                WHERE status = 'STUCK_UNKNOWN'
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                (rs, rowNum) -> mapRow(rs),
                limit
            );
        } catch (Exception ex) {
            log.warn("Institutional check-in reconciliation lookup skipped: {}", LogSanitizer.sanitize(ex.getMessage()));
            return List.of();
        }
    }

    public void markSubmitted(long id, String txHash) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTED',
                tx_hash = ?,
                submitted_at = CURRENT_TIMESTAMP,
                last_error = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
            """,
            txHash,
            id
        );
    }

    public void markMinedSuccess(long id, String txHash) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_SUCCESS',
                tx_hash = COALESCE(?, tx_hash),
                mined_at = CURRENT_TIMESTAMP,
                last_error = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('SUBMITTING', 'SUBMITTED')
            """,
            txHash,
            id
        );
    }

    public void markMinedFailed(long id, String error) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_FAILED',
                mined_at = CURRENT_TIMESTAMP,
                last_error = ?,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED'
            """,
            truncate(error),
            id
        );
    }

    public void markRetry(long id, int attempts, Instant nextAttemptAt, String error) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'RETRY',
                attempts = ?,
                next_attempt_at = ?,
                last_error = ?,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
            """,
            attempts,
            Timestamp.from(nextAttemptAt),
            truncate(error),
            id
        );
    }

    public void markFailed(long id, int attempts, String error) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'FAILED',
                attempts = ?,
                last_error = ?,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
            """,
            attempts,
            truncate(error),
            id
        );
    }

    public void markBroadcastUncertain(long id, int attempts, String error) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'STUCK_UNKNOWN',
                attempts = ?,
                submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP),
                last_error = ?,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
            """,
            attempts,
            truncate(error),
            id
        );
    }

    private InstitutionalCheckInOutboxRecord mapRow(ResultSet rs) throws SQLException {
        Timestamp nextAttempt = rs.getTimestamp("next_attempt_at");
        return new InstitutionalCheckInOutboxRecord(
            rs.getLong("id"),
            rs.getString("reservation_key"),
            rs.getString("lab_id"),
            rs.getString("institutional_wallet"),
            rs.getString("puc_hash"),
            rs.getString("access_session_id"),
            rs.getString("status"),
            rs.getInt("attempts"),
            nextAttempt != null ? nextAttempt.toInstant() : null,
            rs.getString("tx_hash"),
            rs.getString("wallet_address"),
            rs.getObject("chain_id", BigInteger.class),
            rs.getObject("nonce", BigInteger.class),
            rs.getTimestamp("submitted_at") != null ? rs.getTimestamp("submitted_at").toInstant() : null,
            rs.getLong("version")
        );
    }

    public boolean markSubmittedMinedSuccess(InstitutionalCheckInOutboxRecord record) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_SUCCESS', mined_at = CURRENT_TIMESTAMP, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markSubmittedMinedFailed(InstitutionalCheckInOutboxRecord record, String error) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_FAILED', mined_at = CURRENT_TIMESTAMP, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            truncate(error), record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markSubmittedRetry(
        InstitutionalCheckInOutboxRecord record, int attempts, Instant nextAttemptAt, String error
    ) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'RETRY', attempts = ?, next_attempt_at = ?, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            attempts, Timestamp.from(nextAttemptAt), truncate(error), record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markStuckUnknown(InstitutionalCheckInOutboxRecord record, int attempts, String error) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'STUCK_UNKNOWN', attempts = ?, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            attempts, truncate(error), record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markUnknownMinedSuccess(InstitutionalCheckInOutboxRecord record) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_SUCCESS', mined_at = CURRENT_TIMESTAMP, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markUnknownMinedFailed(InstitutionalCheckInOutboxRecord record, String error) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_FAILED', mined_at = CURRENT_TIMESTAMP, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            truncate(error), record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markUnknownRetry(
        InstitutionalCheckInOutboxRecord record, Instant nextAttemptAt, String reason
    ) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'RETRY', attempts = GREATEST(attempts - 1, 0), next_attempt_at = ?,
                last_error = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            Timestamp.from(nextAttemptAt), truncate(reason), record.id(), record.txHash(), record.version()
        ) == 1;
    }

    private void requireConfigured() {
        if (jdbcTemplate == null) {
            throw new IllegalStateException("Institutional check-in outbox requires a configured datasource");
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 2000 ? value : value.substring(0, 2000);
    }
}
