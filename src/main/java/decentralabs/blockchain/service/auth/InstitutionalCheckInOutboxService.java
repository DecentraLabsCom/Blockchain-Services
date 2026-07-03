package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.util.LogSanitizer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
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

    public void enqueueAccessGranted(
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
                reservation_key, lab_id, institutional_wallet, puc_hash, access_session_id,
                status, attempts, next_attempt_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'PENDING', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE
                lab_id = VALUES(lab_id),
                institutional_wallet = VALUES(institutional_wallet),
                puc_hash = VALUES(puc_hash),
                access_session_id = VALUES(access_session_id),
                status = IF(institutional_checkin_outbox.status = 'SUCCEEDED', institutional_checkin_outbox.status, 'PENDING'),
                attempts = IF(institutional_checkin_outbox.status = 'SUCCEEDED', institutional_checkin_outbox.attempts, 0),
                next_attempt_at = IF(institutional_checkin_outbox.status = 'SUCCEEDED', institutional_checkin_outbox.next_attempt_at, CURRENT_TIMESTAMP),
                last_error = IF(institutional_checkin_outbox.status = 'SUCCEEDED', institutional_checkin_outbox.last_error, NULL),
                updated_at = CURRENT_TIMESTAMP
            """,
            reservationKey,
            labId,
            institutionalWallet,
            pucHash,
            accessSessionId
        );
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
                       access_session_id, status, attempts, next_attempt_at
                FROM institutional_checkin_outbox
                WHERE (status IN ('PENDING', 'RETRY') AND next_attempt_at <= ?)
                   OR (status = 'PROCESSING' AND updated_at <= ?)
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
            SET status = 'PROCESSING', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND (
                status IN ('PENDING', 'RETRY')
                OR (status = 'PROCESSING' AND updated_at <= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 15 MINUTE))
              )
            """,
            id
        );
        return updated > 0;
    }

    public void markSucceeded(long id, String txHash) {
        if (jdbcTemplate == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUCCEEDED',
                tx_hash = ?,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            txHash,
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
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
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
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
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
            nextAttempt != null ? nextAttempt.toInstant() : null
        );
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
