package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.util.LogSanitizer;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SessionStartedOnChainPublisherService {

    private final JdbcTemplate jdbcTemplate;
    private final SessionStartedOnChainClient onChainClient;

    @Value("${session.attestation.publisher.enabled:true}")
    private boolean enabled;

    @Value("${session.attestation.publisher.batch-size:10}")
    private int batchSize;

    @Value("${session.attestation.publisher.lock-timeout-seconds:300}")
    private long lockTimeoutSeconds;

    @Value("${session.attestation.publisher.max-attempts:5}")
    private int maxAttempts;

    public SessionStartedOnChainPublisherService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        SessionStartedOnChainClient onChainClient
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.onChainClient = onChainClient;
    }

    @Scheduled(fixedDelayString = "${session.attestation.publisher.interval-ms:15000}")
    public void publishPendingScheduled() {
        publishPending();
    }

    int publishPending() {
        if (!enabled || jdbcTemplate == null) {
            return 0;
        }
        return publishPending(Math.max(1, batchSize));
    }

    int publishPending(int limit) {
        List<SessionStartedOnChainSubmission> pending;
        try {
            pending = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature
                FROM session_started_attestations
                WHERE onchain_published_at IS NULL
                  AND onchain_publish_attempts < ?
                  AND (
                    onchain_publish_locked_at IS NULL
                    OR onchain_publish_locked_at < ?
                  )
                ORDER BY created_at ASC, id ASC
                LIMIT ?
                """,
                rowMapper(),
                maxPublishAttempts(),
                lockThreshold(),
                Math.max(1, limit)
            );
        } catch (BadSqlGrammarException ex) {
            log.debug("SessionStarted on-chain publisher skipped: migration not available yet");
            return 0;
        }

        int published = 0;
        for (SessionStartedOnChainSubmission submission : pending) {
            if (publish(submission)) {
                published++;
            }
        }
        return published;
    }

    private boolean publish(SessionStartedOnChainSubmission submission) {
        if (!claim(submission.id())) {
            return false;
        }

        try {
            if (onChainClient.hasSessionStarted(submission.reservationKey())) {
                markAlreadyRecorded(submission.id());
                return true;
            }

            String txHash = onChainClient.markSessionStarted(submission);
            markSucceeded(submission.id(), txHash);
            log.info(
                "Published SessionStarted on-chain for reservation {} tx={}",
                LogSanitizer.sanitize(submission.reservationKey()),
                LogSanitizer.sanitize(txHash)
            );
            return true;
        } catch (Exception ex) {
            markFailed(submission.id(), ex);
            return false;
        }
    }

    private boolean claim(long id) {
        int updated = jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_publish_locked_at = CURRENT_TIMESTAMP,
                onchain_publish_attempts = onchain_publish_attempts + 1,
                onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND onchain_published_at IS NULL
              AND onchain_publish_attempts < ?
              AND (
                onchain_publish_locked_at IS NULL
                OR onchain_publish_locked_at < ?
              )
            """,
            id,
            maxPublishAttempts(),
            lockThreshold()
        );
        return updated == 1;
    }

    private void markSucceeded(long id, String txHash) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = ?,
                onchain_published_at = CURRENT_TIMESTAMP,
                onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            txHash,
            id
        );
    }

    private void markAlreadyRecorded(long id) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_published_at = CURRENT_TIMESTAMP,
                onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            id
        );
    }

    private void markFailed(long id, Exception ex) {
        String error = LogSanitizer.sanitize(ex.getMessage());
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            error,
            id
        );
        log.warn("SessionStarted on-chain publication failed for attestation {}: {}", id, error);
    }

    private Timestamp lockThreshold() {
        long seconds = Math.max(1L, lockTimeoutSeconds);
        return Timestamp.from(Instant.now().minusSeconds(seconds));
    }

    private int maxPublishAttempts() {
        return Math.max(1, maxAttempts);
    }

    private RowMapper<SessionStartedOnChainSubmission> rowMapper() {
        return (rs, rowNum) -> new SessionStartedOnChainSubmission(
            rs.getLong("id"),
            rs.getString("reservation_key"),
            rs.getString("lab_id"),
            rs.getString("puc_hash"),
            rs.getString("signer_address"),
            rs.getString("gateway_id"),
            rs.getString("session_id"),
            rs.getString("access_type"),
            rs.getTimestamp("started_at").toInstant().getEpochSecond(),
            rs.getString("nonce"),
            rs.getString("credential_hash"),
            rs.getString("client_proof_hash"),
            rs.getString("signature")
        );
    }
}
