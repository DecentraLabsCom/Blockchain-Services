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

    private record ActiveWalletContext(BigInteger chainId, String walletAddress) { }

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
        ActiveWalletContext context;
        try {
            context = new ActiveWalletContext(onChainClient.connectedChainId(), onChainClient.signerAddress());
            if (context.chainId() == null || context.chainId().signum() <= 0
                    || context.walletAddress() == null || context.walletAddress().isBlank()) {
                throw new IllegalStateException("Active SessionStarted chain/wallet context is incomplete");
            }
        } catch (RuntimeException ex) {
            log.warn("SessionStarted publisher context unavailable: {}", ex.getMessage());
            return 0;
        }

        int reconciled = reconcileUnknown(Math.max(1, limit), context);
        int mined = monitorSubmitted(Math.max(1, limit), context);
        List<SessionStartedTransactionRecord> pending;
        try {
            pending = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature, onchain_status, onchain_publish_attempts,
                       onchain_wallet_address, onchain_chain_id, onchain_nonce, onchain_tx_hash,
                       onchain_signed_raw_transaction, onchain_original_gas_price,
                       onchain_current_gas_price, onchain_submitted_at, onchain_version
                FROM session_started_attestations
                WHERE onchain_published_at IS NULL
                  AND (
                    (onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING', 'REPLACEMENT_PENDING')
                     AND onchain_publish_attempts < ?)
                    OR (onchain_status = 'FAILED'
                        AND onchain_tx_hash IS NULL
                        AND onchain_signed_raw_transaction IS NULL)
                  )
                  AND (
                    onchain_status = 'FAILED'
                    OR onchain_publish_locked_at IS NULL
                    OR onchain_publish_locked_at < ?
                  )
                  AND (
                    (onchain_chain_id = ? AND LOWER(onchain_wallet_address) = LOWER(?))
                    OR (onchain_chain_id IS NULL
                        AND onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING', 'FAILED')
                        AND LOWER(signer_address) = LOWER(?))
                  )
                ORDER BY created_at ASC, id ASC
                LIMIT ?
                """,
                transactionRowMapper(),
                maxPublishAttempts(),
                lockThreshold(),
                context.chainId(),
                context.walletAddress(),
                context.walletAddress(),
                Math.max(1, limit)
            );
        } catch (BadSqlGrammarException ex) {
            log.debug("SessionStarted on-chain publisher skipped: migration not available yet");
            return 0;
        }

        int submitted = 0;
        for (SessionStartedTransactionRecord record : pending) {
            if (matchesContext(record, context) && publish(record, context)) {
                submitted++;
            }
        }
        return reconciled + mined + submitted;
    }

    private boolean publish(SessionStartedTransactionRecord record, ActiveWalletContext context) {
        SessionStartedOnChainSubmission submission = record.submission();
        if (!claim(submission.id())) {
            return false;
        }

        try {
            if (onChainClient.hasSessionStarted(submission.reservationKey())) {
                markAlreadyRecorded(submission.id());
                return true;
            }

            if ("REPLACEMENT_PENDING".equals(record.status())) {
                return publishReplacement(record);
            }

            if (hasPersistedMaterial(record)) {
                return resumePersistedSubmission(record);
            }

            String walletAddress = context.walletAddress();
            BigInteger existingNonce = walletAddress.equalsIgnoreCase(record.walletAddress())
                ? record.transactionNonce() : null;
            String txHash = transactionDispatcher.dispatchPrepared(
                walletAddress,
                record.chainId(),
                existingNonce,
                (chainId, nonce) -> markNonceReserved(submission.id(), walletAddress, chainId, nonce),
                nonce -> onChainClient.prepareSessionStarted(submission, nonce, preparationAttempts(record)),
                prepared -> markPrepared(submission.id(), prepared),
                hash -> markSubmitted(submission.id(), hash)
            );
            log.info(
                "Submitted SessionStarted on-chain for reservation {} tx={}",
                LogSanitizer.sanitize(submission.reservationKey()),
                LogSanitizer.sanitize(txHash)
            );
            return true;
        } catch (InstitutionalWalletDispatchException ex) {
            switch (ex.outcome()) {
                case PRE_BROADCAST_BLOCKED -> markPreBroadcastBlocked(submission.id());
                case PRE_BROADCAST_TRANSIENT -> markPreBroadcastTransient(submission.id(), ex);
                case PRE_BROADCAST_PERMANENT -> markPreBroadcastPermanent(submission.id(), ex);
                case BROADCAST_OUTCOME_UNKNOWN -> markBroadcastUncertain(submission.id(), ex);
            }
            return false;
        } catch (Exception ex) {
            markPreBroadcastTransient(submission.id(), ex);
            return false;
        }
    }

    private boolean matchesContext(SessionStartedTransactionRecord record, ActiveWalletContext context) {
        if (record == null || context == null) {
            return false;
        }
        if (record.chainId() != null || record.walletAddress() != null) {
            if (record.chainId() == null || record.walletAddress() == null) {
                return false;
            }
            return context.chainId().equals(record.chainId())
                && context.walletAddress().equalsIgnoreCase(record.walletAddress());
        }
        String status = record.status();
        return ("QUEUED".equals(status) || "RETRY".equals(status)
                || "SUBMITTING".equals(status) || "FAILED".equals(status))
            && context.walletAddress().equalsIgnoreCase(record.submission().signerAddress());
    }

    private boolean claim(long id) {
        try {
            int updated = jdbcTemplate.update(
                """
                UPDATE session_started_attestations
                SET onchain_publish_locked_at = CURRENT_TIMESTAMP,
                    onchain_publish_attempts = CASE
                        WHEN onchain_status = 'FAILED' THEN 1
                    ELSE onchain_publish_attempts + 1
                    END,
                    onchain_status = 'SUBMITTING',
                    onchain_reservation_guard = reservation_key,
                    onchain_version = onchain_version + 1,
                    onchain_publish_last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND onchain_published_at IS NULL
                  AND (
                    (onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING', 'REPLACEMENT_PENDING')
                     AND onchain_publish_attempts < ?)
                    OR (onchain_status = 'FAILED'
                        AND onchain_tx_hash IS NULL
                        AND onchain_signed_raw_transaction IS NULL)
                  )
                  AND (
                    onchain_status = 'FAILED'
                    OR onchain_publish_locked_at IS NULL
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
            WHERE id = ? AND onchain_status IN ('QUEUED', 'RETRY', 'SUBMITTING', 'FAILED')
            """,
            id
        );
    }

    private void markNonceReserved(long id, String walletAddress, BigInteger chainId, BigInteger nonce) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_wallet_address = ?,
                onchain_chain_id = ?,
                onchain_nonce = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            walletAddress,
            chainId,
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

    private void markPrepared(long id, String rawTransaction, String txHash) {
        int updated = jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_signed_raw_transaction = ?, onchain_tx_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            rawTransaction,
            txHash,
            id
        );
        if (updated != 1) {
            throw new IllegalStateException("SessionStarted signed transaction could not be persisted before broadcast");
        }
    }

    private void markPrepared(
        long id,
        InstitutionalWalletTransactionDispatcher.PreparedTransaction prepared
    ) {
        markPrepared(id, prepared.rawTransaction(), prepared.transactionHash());
        if (prepared.gasPrice() != null) {
            jdbcTemplate.update(
                """
                UPDATE session_started_attestations
                SET onchain_original_gas_price = COALESCE(onchain_original_gas_price, ?),
                    onchain_current_gas_price = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND onchain_status = 'SUBMITTING' AND onchain_tx_hash = ?
                """,
                prepared.gasPrice(), prepared.gasPrice(), id, prepared.transactionHash()
            );
        }
    }

    private boolean publishReplacement(SessionStartedTransactionRecord record)
        throws InstitutionalWalletDispatchException {
        if (record.transactionHash() == null || record.transactionNonce() == null
            || record.walletAddress() == null || record.chainId() == null) {
            throw new InstitutionalWalletDispatchException(
                "SessionStarted replacement is missing its durable nonce or previous hash",
                InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT,
                new IllegalStateException("replacement material is incomplete")
            );
        }
        String txHash = transactionDispatcher.dispatchPrepared(
            onChainClient.signerAddress(),
            record.chainId(),
            record.transactionNonce(),
            (chainId, nonce) -> { },
            nonce -> onChainClient.prepareSessionStarted(
                record.submission(), nonce, Math.max(1, record.attempts()), record.originalGasPrice()
            ),
            prepared -> markReplacementPrepared(record, prepared),
            hash -> markReplacementSubmitted(record, hash)
        );
        log.info(
            "Submitted SessionStarted replacement for reservation {} tx={}",
            LogSanitizer.sanitize(record.submission().reservationKey()),
            LogSanitizer.sanitize(txHash)
        );
        return true;
    }

    private void markReplacementPrepared(
        SessionStartedTransactionRecord record,
        InstitutionalWalletTransactionDispatcher.PreparedTransaction prepared
    ) {
        BigInteger gasPrice = prepared.gasPrice() != null ? prepared.gasPrice() : record.currentGasPrice();
        if (gasPrice == null) {
            throw new IllegalStateException("SessionStarted replacement gas price is missing");
        }
        jdbcTemplate.update(
            """
            INSERT INTO session_started_attestation_hash_history
                (attestation_id, tx_hash, gas_price, replaced_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE gas_price = VALUES(gas_price)
            """,
            record.submission().id(), record.transactionHash(),
            record.currentGasPrice() != null ? record.currentGasPrice() : gasPrice
        );
        int updated = jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_signed_raw_transaction = ?, onchain_tx_hash = ?,
                onchain_current_gas_price = ?,
                onchain_original_gas_price = COALESCE(onchain_original_gas_price, ?),
                onchain_status = 'SUBMITTING', onchain_publish_last_error = NULL,
                onchain_version = onchain_version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
              AND onchain_tx_hash = ? AND onchain_version = ?
            """,
            prepared.rawTransaction(), prepared.transactionHash(), gasPrice,
            record.originalGasPrice() != null ? record.originalGasPrice() : gasPrice,
            record.submission().id(), record.transactionHash(), record.version() + 1
        );
        if (updated != 1) {
            throw new IllegalStateException("SessionStarted replacement lost its fencing claim");
        }
    }

    private void markReplacementSubmitted(SessionStartedTransactionRecord record, String txHash) {
        int updated = jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = ?, onchain_status = 'SUBMITTED',
                onchain_submitted_at = CURRENT_TIMESTAMP,
                onchain_publish_locked_at = NULL, onchain_publish_last_error = NULL,
                onchain_version = onchain_version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
              AND onchain_tx_hash = ? AND onchain_version = ?
            """,
            txHash, record.submission().id(), txHash, record.version() + 2
        );
        if (updated != 1) {
            throw new IllegalStateException("SessionStarted replacement submission lost its fencing claim");
        }
    }

    private boolean hasPersistedMaterial(SessionStartedTransactionRecord record) {
        return record.signedRawTransaction() != null && !record.signedRawTransaction().isBlank()
            && record.transactionHash() != null && !record.transactionHash().isBlank();
    }

    private int preparationAttempts(SessionStartedTransactionRecord record) {
        return "FAILED".equals(record.status()) ? 0 : record.attempts();
    }

    private boolean resumePersistedSubmission(SessionStartedTransactionRecord record)
        throws InstitutionalWalletDispatchException {
        String txHash = record.transactionHash();
        try {
            SessionStartedOnChainClient.TransactionState state = onChainClient.transactionStateStrict(txHash);
            if (state == SessionStartedOnChainClient.TransactionState.SUCCEEDED) {
                markMinedSuccess(record.submission().id(), txHash);
                return true;
            }
            if (state == SessionStartedOnChainClient.TransactionState.FAILED) {
                markMinedFailed(record.submission().id(), txHash, "SessionStarted transaction reverted on-chain");
                return false;
            }
            if (onChainClient.transactionVisible(txHash)) {
                markSubmitted(record.submission().id(), txHash);
                return true;
            }
        } catch (RuntimeException ex) {
            throw new InstitutionalWalletDispatchException(
                "Persisted SessionStarted transaction outcome is uncertain",
                InstitutionalWalletDispatchException.Outcome.BROADCAST_OUTCOME_UNKNOWN,
                ex
            );
        }

        String rebroadcastHash = transactionDispatcher.rebroadcastPrepared(
            new InstitutionalWalletTransactionDispatcher.PreparedTransaction(
                record.signedRawTransaction(), txHash
            )
        );
        markSubmitted(record.submission().id(), rebroadcastHash);
        log.info(
            "Rebroadcast persisted SessionStarted transaction for reservation {} tx={}",
            LogSanitizer.sanitize(record.submission().reservationKey()),
            LogSanitizer.sanitize(rebroadcastHash)
        );
        return true;
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

    private void markPreBroadcastBlocked(long id) {
        updatePreBroadcastStatus(
            id,
            "RETRY",
            "SessionStarted publication is blocked by another institutional wallet transaction; retrying",
            true
        );
        log.info("SessionStarted publication remains queued behind a wallet blocker for attestation {}", id);
    }

    private void markPreBroadcastTransient(long id, Exception ex) {
        updateExhaustiblePreBroadcastRetry(id, LogSanitizer.sanitize(ex.getMessage()));
        log.warn(
            "SessionStarted pre-broadcast publication will be retried or require manual intervention for attestation {}: {}",
            id, ex.getMessage()
        );
    }

    private void markPreBroadcastPermanent(long id, Exception ex) {
        updatePreBroadcastStatus(
            id,
            "MANUAL_INTERVENTION",
            "Permanent pre-broadcast SessionStarted failure: " + LogSanitizer.sanitize(ex.getMessage()),
            false
        );
        log.error("SessionStarted publication requires manual intervention for attestation {}: {}", id, ex.getMessage());
    }

    private void updatePreBroadcastStatus(long id, String status, String error, boolean refundAttempt) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_publish_locked_at = NULL,
                onchain_status = ?,
                onchain_publish_attempts = CASE WHEN ? THEN GREATEST(onchain_publish_attempts - 1, 0)
                    ELSE onchain_publish_attempts END,
                onchain_publish_last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            status,
            refundAttempt,
            error,
            id
        );
    }

    private void updateExhaustiblePreBroadcastRetry(long id, String error) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_publish_locked_at = NULL,
                onchain_status = CASE WHEN onchain_publish_attempts >= ?
                    THEN 'MANUAL_INTERVENTION' ELSE 'RETRY' END,
                onchain_publish_last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            maxPublishAttempts(), error, id
        );
    }

    private void markBroadcastUncertain(long id, InstitutionalWalletDispatchException ex) {
        String error = LogSanitizer.sanitize(ex.getMessage());
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_publish_locked_at = NULL,
                onchain_status = 'STUCK_UNKNOWN',
                onchain_submitted_at = COALESCE(onchain_submitted_at, CURRENT_TIMESTAMP),
                onchain_publish_last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTING'
            """,
            error,
            id
        );
        log.warn("SessionStarted broadcast outcome is uncertain for attestation {}: {}", id, error);
    }

    private Timestamp lockThreshold() {
        long seconds = Math.max(1L, lockTimeoutSeconds);
        return Timestamp.from(Instant.now().minusSeconds(seconds));
    }

    private int maxPublishAttempts() {
        return Math.max(1, maxAttempts);
    }

    private int monitorSubmitted(int limit, ActiveWalletContext context) {
        List<SessionStartedTransactionRecord> submitted;
        try {
            submitted = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature, onchain_status, onchain_publish_attempts,
                       onchain_wallet_address, onchain_chain_id, onchain_nonce, onchain_tx_hash,
                       onchain_signed_raw_transaction, onchain_original_gas_price,
                       onchain_current_gas_price, onchain_submitted_at, onchain_version
                FROM session_started_attestations
                WHERE onchain_status = 'SUBMITTED'
                  AND onchain_chain_id = ?
                  AND LOWER(onchain_wallet_address) = LOWER(?)
                ORDER BY onchain_submitted_at ASC, id ASC
                LIMIT ?
                """,
                transactionRowMapper(),
                context.chainId(),
                context.walletAddress(),
                limit
            );
        } catch (BadSqlGrammarException ex) {
            return 0;
        }
        int mined = 0;
        for (SessionStartedTransactionRecord record : submitted) {
            try {
                boolean resolved = false;
                for (String candidateHash : monitoredHashes(record)) {
                    SessionStartedOnChainClient.TransactionState state =
                        onChainClient.transactionStateStrict(candidateHash);
                    if (state == SessionStartedOnChainClient.TransactionState.SUCCEEDED) {
                        markMinedSuccessFromAnyHash(record, candidateHash);
                        mined++;
                        resolved = true;
                        break;
                    }
                    if (state == SessionStartedOnChainClient.TransactionState.FAILED) {
                        markMinedFailedFromAnyHash(
                            record, candidateHash, "SessionStarted transaction reverted on-chain"
                        );
                        resolved = true;
                        break;
                    }
                }
                if (!resolved && isStuck(record)) {
                    markPendingReplacement(record);
                }
            } catch (RuntimeException ex) {
                log.warn("Unable to monitor SessionStarted attestation {}: {}", record.submission().id(), ex.getMessage());
            }
        }
        return mined;
    }

    private int reconcileUnknown(int limit, ActiveWalletContext context) {
        List<SessionStartedTransactionRecord> unknown;
        try {
            unknown = jdbcTemplate.query(
                """
                SELECT id, reservation_key, lab_id, puc_hash, signer_address, gateway_id,
                       session_id, access_type, started_at, nonce, credential_hash,
                       client_proof_hash, signature, onchain_status, onchain_publish_attempts,
                       onchain_wallet_address, onchain_chain_id, onchain_nonce, onchain_tx_hash,
                       onchain_signed_raw_transaction, onchain_original_gas_price,
                       onchain_current_gas_price, onchain_submitted_at, onchain_version
                FROM session_started_attestations
                WHERE onchain_status = 'STUCK_UNKNOWN'
                  AND onchain_chain_id = ?
                  AND LOWER(onchain_wallet_address) = LOWER(?)
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                transactionRowMapper(),
                context.chainId(),
                context.walletAddress(),
                limit
            );
        } catch (BadSqlGrammarException ex) {
            return 0;
        }
        int reconciled = 0;
        for (SessionStartedTransactionRecord record : unknown) {
            try {
                if (onChainClient.hasSessionStarted(record.submission().reservationKey())) {
                    markUnknownMinedSuccess(record.submission().id(), null);
                    reconciled++;
                    continue;
                }
                boolean visible = false;
                boolean reconciledByHash = false;
                for (String candidateHash : monitoredHashes(record)) {
                    SessionStartedOnChainClient.TransactionState state =
                        onChainClient.transactionStateStrict(candidateHash);
                    if (state == SessionStartedOnChainClient.TransactionState.SUCCEEDED) {
                        markUnknownMinedSuccess(record.submission().id(), candidateHash);
                        reconciled++;
                        reconciledByHash = true;
                        break;
                    }
                    if (state == SessionStartedOnChainClient.TransactionState.FAILED) {
                        markUnknownMinedFailed(
                            record, candidateHash, "SessionStarted transaction reverted on-chain"
                        );
                        reconciledByHash = true;
                        break;
                    }
                    if (onChainClient.transactionVisible(candidateHash)) {
                        visible = true;
                        markUnknownRebroadcast(record, record.transactionHash());
                        reconciledByHash = true;
                        break;
                    }
                }
                if (reconciledByHash) {
                    continue;
                }
                if (record.transactionNonce() != null && record.walletAddress() != null
                        && !visible
                        && onChainClient.pendingNonce(record.walletAddress()).compareTo(record.transactionNonce()) <= 0) {
                    if (record.signedRawTransaction() != null && !record.signedRawTransaction().isBlank()) {
                        String rebroadcastHash = onChainClient.broadcastSignedRawTransaction(
                            record.signedRawTransaction()
                        );
                        markUnknownRebroadcast(record, rebroadcastHash);
                        continue;
                    }
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

    private void markUnknownMinedSuccess(long id, String minedTxHash) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = COALESCE(?, onchain_tx_hash),
                onchain_status = 'MINED_SUCCESS', onchain_published_at = CURRENT_TIMESTAMP,
                onchain_mined_at = CURRENT_TIMESTAMP, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN'
            """,
            minedTxHash, id
        );
    }

    private List<String> monitoredHashes(SessionStartedTransactionRecord record) {
        List<String> hashes = new java.util.ArrayList<>();
        if (record.transactionHash() != null && !record.transactionHash().isBlank()) {
            hashes.add(record.transactionHash());
        }
        try {
            List<String> history = jdbcTemplate.query(
                """
                SELECT tx_hash FROM session_started_attestation_hash_history
                WHERE attestation_id = ? ORDER BY replaced_at ASC, id ASC
                """,
                (rs, rowNum) -> rs.getString("tx_hash"), record.submission().id()
            );
            if (history != null) {
                hashes.addAll(history);
            }
        } catch (RuntimeException ignored) {
            // Keep the current hash usable while an older deployment is migrating.
        }
        return hashes.stream()
            .filter(hash -> hash != null && !hash.isBlank())
            .distinct()
            .toList();
    }

    private void markUnknownMinedFailed(
        SessionStartedTransactionRecord record,
        String minedTxHash,
        String error
    ) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = COALESCE(?, onchain_tx_hash),
                onchain_status = 'MINED_FAILED', onchain_mined_at = CURRENT_TIMESTAMP,
                onchain_reservation_guard = NULL, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN' AND onchain_tx_hash <=> ?
            """,
            minedTxHash, error, record.submission().id(), record.transactionHash()
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
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN' AND onchain_tx_hash <=> ?
            """,
            "Reconciler proved the transaction absent and its nonce unconsumed; retrying the same nonce",
            record.submission().id(), record.transactionHash()
        );
    }

    private void markUnknownRebroadcast(SessionStartedTransactionRecord record, String txHash) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = 'SUBMITTED', onchain_tx_hash = COALESCE(?, onchain_tx_hash),
                onchain_submitted_at = COALESCE(onchain_submitted_at, CURRENT_TIMESTAMP),
                onchain_publish_locked_at = NULL, onchain_publish_last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'STUCK_UNKNOWN' AND onchain_tx_hash <=> ?
            """,
            txHash, record.submission().id(), record.transactionHash()
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

    private void markPendingReplacement(SessionStartedTransactionRecord record) {
        boolean exhausted = record.attempts() >= maxPublishAttempts();
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_status = ?, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?, onchain_version = onchain_version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTED' AND onchain_tx_hash = ?
              AND onchain_version = ?
            """,
            exhausted ? "STUCK_UNKNOWN" : "REPLACEMENT_PENDING",
            exhausted
                ? "SessionStarted transaction remained pending after maximum broadcasts"
            : "SessionStarted transaction remained visible without a receipt; replacement required",
            record.submission().id(),
            record.transactionHash(),
            record.version()
        );
    }

    private void markMinedSuccessFromAnyHash(
        SessionStartedTransactionRecord record,
        String observedHash
    ) {
        if (observedHash.equalsIgnoreCase(record.transactionHash())) {
            markMinedSuccess(record.submission().id(), observedHash);
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = ?, onchain_status = 'MINED_SUCCESS', onchain_published_at = CURRENT_TIMESTAMP,
                onchain_mined_at = CURRENT_TIMESTAMP, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTED' AND onchain_version = ?
            """,
            observedHash, record.submission().id(), record.version()
        );
    }

    private void markMinedFailedFromAnyHash(
        SessionStartedTransactionRecord record,
        String observedHash,
        String error
    ) {
        jdbcTemplate.update(
            """
            UPDATE session_started_attestations
            SET onchain_tx_hash = ?, onchain_status = 'MINED_FAILED', onchain_mined_at = CURRENT_TIMESTAMP,
                onchain_reservation_guard = NULL, onchain_publish_locked_at = NULL,
                onchain_publish_last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND onchain_status = 'SUBMITTED' AND onchain_version = ?
            """,
            observedHash, error, record.submission().id(), record.version()
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
            rs.getObject("onchain_chain_id") != null ? rs.getBigDecimal("onchain_chain_id").toBigIntegerExact() : null,
            rs.getObject("onchain_nonce") != null ? rs.getBigDecimal("onchain_nonce").toBigIntegerExact() : null,
            rs.getString("onchain_tx_hash"),
            rs.getTimestamp("onchain_submitted_at") != null
                ? rs.getTimestamp("onchain_submitted_at").toInstant() : null,
            rs.getString("onchain_signed_raw_transaction"),
            rs.getObject("onchain_original_gas_price") != null
                ? rs.getBigDecimal("onchain_original_gas_price").toBigIntegerExact() : null,
            rs.getObject("onchain_current_gas_price") != null
                ? rs.getBigDecimal("onchain_current_gas_price").toBigIntegerExact() : null,
            rs.getLong("onchain_version")
        );
    }
}
