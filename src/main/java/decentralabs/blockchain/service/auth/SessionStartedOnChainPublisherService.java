package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.util.LogSanitizer;
import java.sql.Timestamp;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class SessionStartedOnChainPublisherService {

    private final JdbcTemplate jdbcTemplate;
    private final SessionStartedOnChainClient onChainClient;
    private final InstitutionalWalletTransactionDispatcher transactionDispatcher;

    @Value("${session.attestation.publisher.enabled:true}")
    private boolean enabled;

    @Value("${session.attestation.publisher.batch-size:10}")
    private int batchSize;

    @Value("${session.attestation.publisher.lock-timeout-seconds:300}")
    private long lockTimeoutSeconds;

    @Value("${session.attestation.publisher.max-attempts:5}")
    private int maxAttempts;

    @Value("${session.attestation.publisher.stuck-transaction-ms:30000}")
    private long stuckTransactionMs;

    public SessionStartedOnChainPublisherService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        SessionStartedOnChainClient onChainClient,
        InstitutionalWalletTransactionDispatcher transactionDispatcher
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.onChainClient = onChainClient;
        this.transactionDispatcher = transactionDispatcher;
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
        int reconciled = reconcileUnknown(Math.max(1, limit));
        int mined = monitorSubmitted(Math.max(1, limit));
        List<SessionStartedTransactionRecord> pending;
        try {
            pending = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature, onchain_status, onchain_publish_attempts,
                       onchain_wallet_address, onchain_nonce, onchain_tx_hash, onchain_submitted_at
                FROM session_started_attestations
                WHERE onchain_published_at IS NULL
                  AND onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING')
                  AND onchain_publish_attempts < ?
                  AND (
                    onchain_publish_locked_at IS NULL
                    OR onchain_publish_locked_at < ?
                  )
                ORDER BY created_at ASC, id ASC
                LIMIT ?
                """,
                transactionRowMapper(),
                maxPublishAttempts(),
                lockThreshold(),
                Math.max(1, limit)
            );
        } catch (BadSqlGrammarException ex) {
            log.debug("SessionStarted on-chain publisher skipped: migration not available yet");
            return 0;
        }

        int submitted = 0;
        for (SessionStartedTransactionRecord record : pending) {
            if (publish(record)) {
                submitted++;
            }
        }
        return reconciled + mined + submitted;
    }

    private boolean publish(SessionStartedTransactionRecord record) {
        SessionStartedOnChainSubmission submission = record.submission();
        if (!claim(submission.id())) {
            return false;
        }

        try {
            if (onChainClient.hasSessionStarted(submission.reservationKey())) {
                markAlreadyRecorded(submission.id());
                return true;
            }

            String walletAddress = onChainClient.signerAddress();
            BigInteger existingNonce = walletAddress.equalsIgnoreCase(record.walletAddress())
                ? record.transactionNonce() : null;
            String txHash = transactionDispatcher.dispatch(
                walletAddress,
                existingNonce,
                nonce -> markNonceReserved(submission.id(), walletAddress, nonce),
                nonce -> onChainClient.markSessionStarted(submission, nonce, record.attempts()),
                hash -> markSubmitted(submission.id(), hash)
            );
            log.info(
                "Submitted SessionStarted on-chain for reservation {} tx={}",
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
        try {
            int updated = jdbcTemplate.update(
                """
                UPDATE session_started_attestations
                SET onchain_publish_locked_at = CURRENT_TIMESTAMP,
                    onchain_publish_attempts = onchain_publish_attempts + 1,
                    onchain_status = 'SUBMITTING',
                    onchain_reservation_guard = reservation_key,
                    onchain_publish_last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND onchain_published_at IS NULL
                  AND onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING')
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
        } catch (DataIntegrityViolationException ex) {
            markSuperseded(id);
            return false;
        }
    }

    private void markSuperseded(long id) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = 'SUPERSEDED', onchain_publish_locked_at = NULL,
                onchain_publish_last_error = 'Another attestation owns the reservation on-chain publication',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING')
            """,
            id
        );
    }

    private void markNonceReserved(long id, String walletAddress, BigInteger nonce) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_wallet_address = ?,
                onchain_nonce = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            walletAddress,
            nonce,
            id
        );
    }

    private void markSubmitted(long id, String txHash) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = ?,
                onchain_status = 'SUBMITTED',
                onchain_submitted_at = CURRENT_TIMESTAMP,
                onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
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
                onchain_status = 'MINED_SUCCESS',
                onchain_mined_at = CURRENT_TIMESTAMP,
                onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
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
                onchain_status = CASE
                    WHEN onchain_publish_attempts >= ? THEN 'FAILED'
                    ELSE 'RETRY'
                END,
                onchain_reservation_guard = CASE
                    WHEN onchain_publish_attempts >= ? THEN NULL
                    ELSE onchain_reservation_guard
                END,
                onchain_publish_last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            maxPublishAttempts(),
            maxPublishAttempts(),
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

    private int monitorSubmitted(int limit) {
        List<SessionStartedTransactionRecord> submitted;
        try {
            submitted = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature, onchain_status, onchain_publish_attempts,
                       onchain_wallet_address, onchain_nonce, onchain_tx_hash, onchain_submitted_at
                FROM session_started_attestations
                WHERE onchain_status = 'SUBMITTED'
                ORDER BY onchain_submitted_at ASC, id ASC
                LIMIT ?
                """,
                transactionRowMapper(),
                limit
            );
        } catch (BadSqlGrammarException ex) {
            return 0;
        }
        int mined = 0;
        for (SessionStartedTransactionRecord record : submitted) {
            try {
                SessionStartedOnChainClient.TransactionState state =
                    onChainClient.transactionState(record.transactionHash());
                if (state == SessionStartedOnChainClient.TransactionState.SUCCEEDED) {
                    markMinedSuccess(record.submission().id(), record.transactionHash());
                    mined++;
                } else if (state == SessionStartedOnChainClient.TransactionState.FAILED) {
                    markMinedFailed(record.submission().id(), record.transactionHash(), "SessionStarted transaction reverted on-chain");
                } else if (isStuck(record)) {
                    markPendingRetry(record);
                }
            } catch (RuntimeException ex) {
                log.warn("Unable to monitor SessionStarted attestation {}: {}", record.submission().id(), ex.getMessage());
            }
        }
        return mined;
    }

    private int reconcileUnknown(int limit) {
        List<SessionStartedTransactionRecord> unknown;
        try {
            unknown = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature, onchain_status, onchain_publish_attempts,
                       onchain_wallet_address, onchain_nonce, onchain_tx_hash, onchain_submitted_at
                FROM session_started_attestations
                WHERE onchain_status = 'STUCK_UNKNOWN'
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                transactionRowMapper(),
                limit
            );
        } catch (BadSqlGrammarException ex) {
            return 0;
        }
        int reconciled = 0;
        for (SessionStartedTransactionRecord record : unknown) {
            try {
                if (onChainClient.hasSessionStarted(record.submission().reservationKey())) {
                    markUnknownMinedSuccess(record.submission().id());
                    reconciled++;
                    continue;
                }
                SessionStartedOnChainClient.TransactionState state =
                    onChainClient.transactionStateStrict(record.transactionHash());
                if (state == SessionStartedOnChainClient.TransactionState.SUCCEEDED) {
                    markUnknownMinedSuccess(record.submission().id());
                    reconciled++;
                } else if (state == SessionStartedOnChainClient.TransactionState.FAILED) {
                    markUnknownMinedFailed(record, "SessionStarted transaction reverted on-chain");
                } else if (record.transactionNonce() != null && record.walletAddress() != null
                        && !onChainClient.transactionVisible(record.transactionHash())
                        && onChainClient.pendingNonce(record.walletAddress()).compareTo(record.transactionNonce()) <= 0) {
                    markUnknownRetry(record);
                }
            } catch (RuntimeException ex) {
                log.warn(
                    "Unable to reconcile SessionStarted attestation {}: {}",
                    record.submission().id(), LogSanitizer.sanitize(ex.getMessage())
                );
            }
        }
        return reconciled;
    }

    private void markUnknownMinedSuccess(long id) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = 'MINED_SUCCESS', onchain_published_at = CURRENT_TIMESTAMP,
                onchain_mined_at = CURRENT_TIMESTAMP, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN'
            """,
            id
        );
    }

    private void markUnknownMinedFailed(SessionStartedTransactionRecord record, String error) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = 'MINED_FAILED', onchain_mined_at = CURRENT_TIMESTAMP,
                onchain_reservation_guard = NULL, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN' AND onchain_tx_hash = ?
            """,
            error, record.submission().id(), record.transactionHash()
        );
    }

    private void markUnknownRetry(SessionStartedTransactionRecord record) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = 'RETRY',
                onchain_publish_attempts = GREATEST(onchain_publish_attempts - 1, 0),
                onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN' AND onchain_tx_hash = ?
            """,
            "Reconciler proved the transaction absent and its nonce unconsumed; retrying the same nonce",
            record.submission().id(), record.transactionHash()
        );
    }

    private void markMinedSuccess(long id, String txHash) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = ?, onchain_status = 'MINED_SUCCESS',
                onchain_published_at = CURRENT_TIMESTAMP, onchain_mined_at = CURRENT_TIMESTAMP,
                onchain_publish_locked_at = NULL, onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTED' AND onchain_tx_hash = ?
            """,
            txHash,
            id,
            txHash
        );
    }

    private void markMinedFailed(long id, String txHash, String error) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = 'MINED_FAILED', onchain_mined_at = CURRENT_TIMESTAMP,
                onchain_reservation_guard = NULL,
                onchain_publish_locked_at = NULL, onchain_publish_last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTED' AND onchain_tx_hash = ?
            """,
            error,
            id,
            txHash
        );
    }

    private void markPendingRetry(SessionStartedTransactionRecord record) {
        boolean exhausted = record.attempts() >= maxPublishAttempts();
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = ?, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTED' AND onchain_tx_hash = ?
            """,
            exhausted ? "STUCK_UNKNOWN" : "RETRY",
            exhausted
                ? "SessionStarted transaction remained pending after maximum broadcasts"
                : "SessionStarted transaction is pending; retrying the same nonce with higher gas",
            record.submission().id(),
            record.transactionHash()
        );
    }

    private boolean isStuck(SessionStartedTransactionRecord record) {
        return record.submittedAt() != null
            && record.submittedAt().plusMillis(Math.max(1L, stuckTransactionMs)).isBefore(Instant.now());
    }

    private RowMapper<SessionStartedTransactionRecord> transactionRowMapper() {
        return (rs, rowNum) -> new SessionStartedTransactionRecord(new SessionStartedOnChainSubmission(
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
        ),
            rs.getString("onchain_status"),
            rs.getInt("onchain_publish_attempts"),
            rs.getString("onchain_wallet_address"),
            rs.getObject("onchain_nonce") != null ? rs.getBigDecimal("onchain_nonce").toBigIntegerExact() : null,
            rs.getString("onchain_tx_hash"),
            rs.getTimestamp("onchain_submitted_at") != null
                ? rs.getTimestamp("onchain_submitted_at").toInstant() : null
        );
    }
}
