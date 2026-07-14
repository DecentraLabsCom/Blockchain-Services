package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.exception.IdempotencyKeyPayloadMismatchException;
import decentralabs.blockchain.service.auth.InstitutionalWalletNonceReservationService;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Durable ownership record for institutional transactions that are not tied to
 * the check-in or SessionStarted outboxes. A RESERVED/PREPARED/RETRYABLE,
 * SUBMITTED, REPLACEMENT_PENDING or STUCK_UNKNOWN row is a deliberate wallet
 * barrier: another operation cannot skip over it and create a permanent nonce
 * hole.
 */
@Service
public class InstitutionalTransactionOutboxService {
    private final JdbcTemplate jdbcTemplate;
    private final InstitutionalWalletNonceReservationService nonceReservationService;

    public InstitutionalTransactionOutboxService(
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider,
        InstitutionalWalletNonceReservationService nonceReservationService
    ) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
        this.nonceReservationService = nonceReservationService;
    }

    public record Attempt(
        long id,
        BigInteger chainId,
        String walletAddress,
        String operationKey,
        BigInteger nonce,
        BigInteger originalGasPrice,
        BigInteger currentGasPrice,
        BigInteger gasLimit,
        String toAddress,
        BigInteger value,
        String data,
        String status,
        String signedRawTransaction,
        String txHash,
        Instant updatedAt,
        int attempts,
        Instant createdAt,
        long version
    ) {
        public BigInteger gasPrice() {
            return currentGasPrice;
        }

        public Attempt(
            long id,
            BigInteger chainId,
            String walletAddress,
            String operationKey,
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String toAddress,
            BigInteger value,
            String data,
            String status,
            String signedRawTransaction,
            String txHash,
            Instant updatedAt,
            int attempts,
            Instant createdAt
        ) {
            this(id, chainId, walletAddress, operationKey, nonce, gasPrice, gasPrice, gasLimit,
                toAddress, value, data, status, signedRawTransaction, txHash, updatedAt, attempts, createdAt, 0L);
        }

        public Attempt(
            long id,
            BigInteger chainId,
            String walletAddress,
            String operationKey,
            BigInteger nonce,
            String status,
            String signedRawTransaction,
            String txHash
        ) {
            this(id, chainId, walletAddress, operationKey, nonce, null, null, null, null, null, null,
                status, signedRawTransaction, txHash, null, 0, null, 0L);
        }

        public Attempt(
            long id,
            BigInteger chainId,
            String walletAddress,
            String operationKey,
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String toAddress,
            BigInteger value,
            String data,
            String status,
            String signedRawTransaction,
            String txHash
        ) {
            this(id, chainId, walletAddress, operationKey, nonce, gasPrice, gasPrice, gasLimit, toAddress, value, data,
                status, signedRawTransaction, txHash, null, 0, null, 0L);
        }

        public Attempt(
            long id,
            BigInteger chainId,
            String walletAddress,
            String operationKey,
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String toAddress,
            BigInteger value,
            String data,
            String status,
            String signedRawTransaction,
            String txHash,
            Instant updatedAt
        ) {
            this(id, chainId, walletAddress, operationKey, nonce, gasPrice, gasPrice, gasLimit, toAddress, value, data,
                status, signedRawTransaction, txHash, updatedAt, 0, null, 0L);
        }

        public Attempt(
            long id,
            BigInteger chainId,
            String walletAddress,
            String operationKey,
            BigInteger nonce,
            BigInteger originalGasPrice,
            BigInteger currentGasPrice,
            BigInteger gasLimit,
            String toAddress,
            BigInteger value,
            String data,
            String status,
            String signedRawTransaction,
            String txHash,
            Instant updatedAt,
            int attempts,
            Instant createdAt
        ) {
            this(id, chainId, walletAddress, operationKey, nonce, originalGasPrice, currentGasPrice,
                gasLimit, toAddress, value, data, status, signedRawTransaction, txHash,
                updatedAt, attempts, createdAt, 0L);
        }
    }

    @Transactional
    public Attempt reserveOrLoad(
        String walletAddress,
        BigInteger chainId,
        BigInteger nodePendingNonce,
        String operationKey,
        BigInteger gasPrice,
        BigInteger gasLimit,
        String toAddress,
        BigInteger value,
        String data
    ) {
        requireConfigured();
        Attempt existing = find(walletAddress, chainId, operationKey, true);
        if (existing != null) {
            if (!samePayload(existing, toAddress, value, data)) {
                throw new IdempotencyKeyPayloadMismatchException();
            }
            return existing;
        }

        Attempt blocker = findBlockingInternal(walletAddress, chainId);
        if (blocker != null) {
            throw new TransactionBlockedException(
                "Institutional wallet has an unresolved transaction at nonce " + blocker.nonce()
            );
        }
        if (hasDedicatedPublisherBlocker(walletAddress, chainId)) {
            throw new TransactionBlockedException(
                "Institutional wallet has an unresolved check-in or SessionStarted transaction"
            );
        }

        BigInteger nonce = nonceReservationService.reserve(walletAddress, chainId, nodePendingNonce);
        jdbcTemplate.update(
            """
            INSERT INTO institutional_transaction_outbox (
                chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                to_address, value_wei, data, status, attempts, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            chainId, walletAddress, operationKey, nonce, gasPrice, gasPrice, gasLimit,
            toAddress, value, data
        );
        return find(walletAddress, chainId, operationKey, true);
    }

    private boolean samePayload(
        Attempt existing,
        String toAddress,
        BigInteger value,
        String data
    ) {
        return Objects.equals(existing.value(), value)
            && equalHex(existing.toAddress(), toAddress)
            && equalHex(existing.data(), data);
    }

    private boolean equalHex(String left, String right) {
        String normalizedLeft = left == null ? null : left.trim().toLowerCase(Locale.ROOT);
        String normalizedRight = right == null ? null : right.trim().toLowerCase(Locale.ROOT);
        return Objects.equals(normalizedLeft, normalizedRight);
    }

    public Attempt findBlocking(String walletAddress, BigInteger chainId) {
        if (jdbcTemplate == null) {
            return null;
        }
        return findBlockingInternal(walletAddress, chainId);
    }

    public void markSigned(Attempt attempt, String signedRawTransaction, String expectedTxHash) {
        markSigned(attempt, signedRawTransaction, expectedTxHash, attempt == null ? null : attempt.gasPrice());
    }

    public void markSigned(
        Attempt attempt,
        String signedRawTransaction,
        String expectedTxHash,
        BigInteger gasPrice
    ) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET signed_raw_transaction = ?, tx_hash = ?, current_gas_price = COALESCE(?, current_gas_price),
                status = 'PREPARED', version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
              AND version = ? AND tx_hash <=> ?
            """,
            signedRawTransaction, expectedTxHash, gasPrice, attempt.id(), attempt.version(), attempt.txHash()
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional signed transaction could not be persisted before broadcast");
        }
    }

    public void markSubmitted(Attempt attempt, String txHash) {
        markSubmittedAfterPreparation(attempt, txHash);
    }

    /**
     * Marks material submitted after a durable preparation write.  The caller
     * may have started from RESERVED/RETRYABLE/REPLACEMENT_PENDING, so that
     * preparation write is part of the expected version transition.
     */
    public void markSubmittedAfterPreparation(Attempt attempt, String txHash) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'SUBMITTED', tx_hash = ?, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('PREPARED', 'RETRYABLE', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
              AND tx_hash = ? AND version = ?
            """,
            txHash, attempt.id(), txHash, expectedSubmissionVersion(attempt)
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional transaction submission lost its fencing claim");
        }
    }

    /**
     * Returns already persisted material to normal SUBMITTED processing.  No
     * preparation write preceded this transition, therefore the observed
     * version itself is the fencing token.  REPLACEMENT_PENDING is deliberately
     * excluded: visibility of the old hash does not cancel a replacement.
     */
    public void markVisibleSubmitted(Attempt attempt, String txHash) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'SUBMITTED', tx_hash = ?, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('PREPARED', 'RETRYABLE', 'STUCK_UNKNOWN')
              AND tx_hash = ? AND version = ?
            """,
            txHash, attempt.id(), txHash, attempt.version()
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional visible transaction submission lost its fencing claim");
        }
    }

    /**
     * Marks a replacement submitted after markReplacementPrepared().  The
     * replacement preparation increments the source row exactly once.
     */
    public void markReplacementSubmitted(Attempt attempt, String txHash) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'SUBMITTED', tx_hash = ?, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'PREPARED'
              AND tx_hash = ? AND version = ?
            """,
            txHash, attempt.id(), txHash, attempt.version() + 1L
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional replacement submission lost its fencing claim");
        }
    }

    public void markRetryable(Attempt attempt, String error) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'RETRYABLE', attempts = attempts + 1, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
              AND version = ?
            """,
            truncate(error), attempt.id(), expectedTransitionVersion(attempt)
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional retry update lost its fencing claim");
        }
    }

    public void markMinedSuccess(Attempt attempt) {
        markMinedSuccess(attempt, null);
    }

    /**
     * Closes the operation using the hash whose receipt actually won. A
     * replacement can mine after a later hash has already been persisted as
     * the current submission, so the winning hash must be promoted for
     * status consumers and external reconciliation.
     */
    public void markMinedSuccess(Attempt attempt, String minedTxHash) {
        updateTerminal(attempt, "MINED_SUCCESS", null, minedTxHash);
    }

    public void markMinedFailed(Attempt attempt, String error) {
        markMinedFailed(attempt, null, error);
    }

    public void markMinedFailed(Attempt attempt, String minedTxHash, String error) {
        updateTerminal(attempt, "MINED_FAILED", truncate(error), minedTxHash);
    }

    public void markStuckUnknown(Attempt attempt, String error) {
        updateTerminal(attempt, "STUCK_UNKNOWN", truncate(error));
    }

    public void markReplacementPending(Attempt attempt, String error) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'REPLACEMENT_PENDING', last_error = ?, version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            truncate(error), attempt.id(), attempt.txHash(), attempt.version()
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional transaction replacement could not be claimed");
        }
    }

    /**
     * Atomically records the hash being replaced and makes the new signed
     * material durable before the replacement is broadcast.
     */
    @Transactional
    public void markReplacementPrepared(
        Attempt attempt,
        String previousTxHash,
        String signedRawTransaction,
        String replacementTxHash,
        BigInteger gasPrice
    ) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        if (previousTxHash == null || previousTxHash.isBlank()) {
            throw new IllegalArgumentException("Previous transaction hash is required for a replacement");
        }
        jdbcTemplate.update(
            """
            INSERT INTO institutional_transaction_outbox_hash_history
                (outbox_id, tx_hash, gas_price, replaced_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE gas_price = VALUES(gas_price)
            """,
            attempt.id(), previousTxHash, attempt.currentGasPrice()
        );
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET signed_raw_transaction = ?, tx_hash = ?, current_gas_price = ?,
                status = 'PREPARED', attempts = attempts + 1, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RETRYABLE', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
              AND tx_hash = ? AND version = ?
            """,
            signedRawTransaction, replacementTxHash, gasPrice, attempt.id(), previousTxHash, attempt.version()
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional replacement could not be persisted before broadcast");
        }
    }

    public List<String> findReplacedHashes(long outboxId) {
        if (jdbcTemplate == null) {
            return List.of();
        }
        return jdbcTemplate.query(
            """
            SELECT tx_hash
            FROM institutional_transaction_outbox_hash_history
            WHERE outbox_id = ?
            ORDER BY replaced_at ASC, id ASC
            """,
            (rs, rowNum) -> rs.getString("tx_hash"),
            outboxId
        );
    }

    public java.util.List<Attempt> findSubmitted(int limit) {
        return findByStatus("SUBMITTED", limit);
    }

    /**
     * Returns submitted attempts belonging to the currently selected chain and
     * wallet.  The monitor must use this scoped variant so a runtime network or
     * wallet switch cannot make it inspect historical rows with the wrong RPC.
     */
    public java.util.List<Attempt> findSubmitted(BigInteger chainId, String walletAddress, int limit) {
        return findByStatus("SUBMITTED", chainId, walletAddress, limit);
    }

    public java.util.List<Attempt> findStuckUnknown(int limit) {
        return findByStatus("STUCK_UNKNOWN", limit);
    }

    public java.util.List<Attempt> findStuckUnknown(BigInteger chainId, String walletAddress, int limit) {
        return findByStatus("STUCK_UNKNOWN", chainId, walletAddress, limit);
    }

    public java.util.List<Attempt> findRecoveryCandidates(int limit) {
        if (jdbcTemplate == null) {
            return java.util.List.of();
        }
        return jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at, version
            FROM institutional_transaction_outbox
            WHERE status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'REPLACEMENT_PENDING')
               OR (status = 'STUCK_UNKNOWN' AND tx_hash IS NULL)
            ORDER BY nonce ASC, id ASC
            LIMIT ?
            """,
            (rs, rowNum) -> mapRow(rs),
            Math.max(1, limit)
        );
    }

    /**
     * Returns recoverable attempts only for the active chain/wallet context.
     * Rows from a previous network or rotated wallet remain durable for
     * historical reconciliation but are quarantined from this monitor.
     */
    public java.util.List<Attempt> findRecoveryCandidates(
        BigInteger chainId,
        String walletAddress,
        int limit
    ) {
        if (jdbcTemplate == null || chainId == null || walletAddress == null || walletAddress.isBlank()) {
            return java.util.List.of();
        }
        return jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at, version
            FROM institutional_transaction_outbox
            WHERE chain_id = ? AND LOWER(wallet_address) = LOWER(?)
              AND (status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'REPLACEMENT_PENDING')
                   OR (status = 'STUCK_UNKNOWN' AND tx_hash IS NULL))
            ORDER BY nonce ASC, id ASC
            LIMIT ?
            """,
            (rs, rowNum) -> mapRow(rs),
            chainId, walletAddress, Math.max(1, limit)
        );
    }

    private java.util.List<Attempt> findByStatus(String status, int limit) {
        if (jdbcTemplate == null) {
            return java.util.List.of();
        }
        return jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at, version
            FROM institutional_transaction_outbox
            WHERE status = ? AND tx_hash IS NOT NULL
            ORDER BY updated_at ASC, id ASC
            LIMIT ?
            """,
            (rs, rowNum) -> mapRow(rs),
            status, Math.max(1, limit)
        );
    }

    private java.util.List<Attempt> findByStatus(
        String status,
        BigInteger chainId,
        String walletAddress,
        int limit
    ) {
        if (jdbcTemplate == null || chainId == null || walletAddress == null || walletAddress.isBlank()) {
            return java.util.List.of();
        }
        return jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at, version
            FROM institutional_transaction_outbox
            WHERE status = ? AND tx_hash IS NOT NULL
              AND chain_id = ? AND LOWER(wallet_address) = LOWER(?)
            ORDER BY updated_at ASC, id ASC
            LIMIT ?
            """,
            (rs, rowNum) -> mapRow(rs),
            status, chainId, walletAddress, Math.max(1, limit)
        );
    }

    private void updateTerminal(Attempt attempt, String status, String error) {
        updateTerminal(attempt, status, error, null);
    }

    private void updateTerminal(Attempt attempt, String status, String error, String minedTxHash) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = ?, tx_hash = COALESCE(?, tx_hash), last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'SUBMITTED', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
              AND version = ?
            """,
            status, minedTxHash, error, attempt.id(), attempt.version()
        );
    }

    private Attempt find(String walletAddress, BigInteger chainId, String operationKey, boolean forUpdate) {
        String lock = forUpdate ? " FOR UPDATE" : "";
        var rows = jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at, version
            FROM institutional_transaction_outbox
            WHERE wallet_address = ? AND chain_id = ? AND operation_key = ?
            """ + lock,
            (rs, rowNum) -> mapRow(rs),
            walletAddress, chainId, operationKey
        );
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private Attempt findBlockingInternal(String walletAddress, BigInteger chainId) {
        var rows = jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at, version
            FROM institutional_transaction_outbox
            WHERE wallet_address = ? AND chain_id = ?
              AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'SUBMITTED', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
            ORDER BY nonce ASC
            LIMIT 1
            FOR UPDATE
            """,
            (rs, rowNum) -> mapRow(rs),
            walletAddress, chainId
        );
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private Attempt mapRow(ResultSet rs) throws SQLException {
        return new Attempt(
            rs.getLong("id"),
            decimalAsBigInteger(rs.getBigDecimal("chain_id")),
            rs.getString("wallet_address"),
            rs.getString("operation_key"),
            decimalAsBigInteger(rs.getBigDecimal("nonce")),
            decimalAsBigInteger(rs.getBigDecimal("original_gas_price")),
            decimalAsBigInteger(rs.getBigDecimal("current_gas_price")),
            decimalAsBigInteger(rs.getBigDecimal("gas_limit")),
            rs.getString("to_address"),
            decimalAsBigInteger(rs.getBigDecimal("value_wei")),
            rs.getString("data"),
            rs.getString("status"),
            rs.getString("signed_raw_transaction"),
            rs.getString("tx_hash"),
            rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toInstant() : null,
            rs.getInt("attempts"),
            rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toInstant() : null,
            rs.getLong("version")
        );
    }

    private long expectedTransitionVersion(Attempt attempt) {
        boolean alreadyPersisted = "PREPARED".equals(attempt.status())
            && attempt.signedRawTransaction() != null && !attempt.signedRawTransaction().isBlank()
            && attempt.txHash() != null && !attempt.txHash().isBlank();
        return attempt.version() + (alreadyPersisted ? 0L : 1L);
    }

    private long expectedSubmissionVersion(Attempt attempt) {
        return expectedTransitionVersion(attempt);
    }

    private boolean hasDedicatedPublisherBlocker(String walletAddress, BigInteger chainId) {
        Long checkIn = jdbcTemplate.queryForObject(
            """
            SELECT COUNT(*)
            FROM institutional_checkin_outbox
            WHERE wallet_address = ? AND chain_id = ? AND nonce IS NOT NULL
              AND status IN ('SUBMITTING', 'RETRY', 'FAILED', 'STUCK_UNKNOWN')
            """,
            Long.class,
            walletAddress,
            chainId
        );
        if (checkIn != null && checkIn > 0) {
            return true;
        }
        Long sessionStarted = jdbcTemplate.queryForObject(
            """
            SELECT COUNT(*)
            FROM session_started_attestations
            WHERE onchain_wallet_address = ? AND onchain_chain_id = ? AND onchain_nonce IS NOT NULL
              AND onchain_status IN ('QUEUED', 'SUBMITTING', 'RETRY', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN', 'FAILED', 'MANUAL_INTERVENTION')
            """,
            Long.class,
            walletAddress,
            chainId
        );
        return sessionStarted != null && sessionStarted > 0;
    }

    private BigInteger decimalAsBigInteger(BigDecimal value) {
        return value == null ? null : value.toBigIntegerExact();
    }

    private void requireConfigured() {
        if (jdbcTemplate == null) {
            throw new IllegalStateException("Institutional transaction outbox requires a configured datasource");
        }
    }

    private String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= 2000 ? value : value.substring(0, 2000);
    }

    public static class TransactionBlockedException extends RuntimeException {
        public TransactionBlockedException(String message) {
            super(message);
        }
    }
}
