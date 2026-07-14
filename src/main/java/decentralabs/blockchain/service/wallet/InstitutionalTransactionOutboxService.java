package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.exception.IdempotencyKeyPayloadMismatchException;
import decentralabs.blockchain.service.auth.InstitutionalWalletNonceReservationService;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Durable ownership record for institutional transactions that are not tied to
 * the check-in or SessionStarted outboxes.  A RESERVED/PREPARED/RETRYABLE or
 * STUCK_UNKNOWN row is a deliberate wallet barrier: another operation cannot
 * skip over it and create a permanent nonce hole.
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
        Instant createdAt
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
                toAddress, value, data, status, signedRawTransaction, txHash, updatedAt, attempts, createdAt);
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
                status, signedRawTransaction, txHash, null, 0, null);
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
                status, signedRawTransaction, txHash, null, 0, null);
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
                status, signedRawTransaction, txHash, updatedAt, 0, null);
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
            if (!samePayload(existing, gasLimit, toAddress, value, data)) {
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
        BigInteger gasLimit,
        String toAddress,
        BigInteger value,
        String data
    ) {
        return Objects.equals(existing.gasLimit(), gasLimit)
            && Objects.equals(existing.value(), value)
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
                status = 'PREPARED', updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'STUCK_UNKNOWN')
            """,
            signedRawTransaction, expectedTxHash, gasPrice, attempt.id()
        );
        if (updated != 1) {
            throw new IllegalStateException("Institutional signed transaction could not be persisted before broadcast");
        }
    }

    public void markSubmitted(Attempt attempt, String txHash) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'SUBMITTED', tx_hash = ?, last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'STUCK_UNKNOWN')
            """,
            txHash, attempt.id()
        );
    }

    public void markRetryable(Attempt attempt, String error) {
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = 'RETRYABLE', attempts = attempts + 1, last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'STUCK_UNKNOWN')
            """,
            truncate(error), attempt.id()
        );
    }

    public void markMinedSuccess(Attempt attempt) {
        updateTerminal(attempt, "MINED_SUCCESS", null);
    }

    public void markMinedFailed(Attempt attempt, String error) {
        updateTerminal(attempt, "MINED_FAILED", truncate(error));
    }

    public void markStuckUnknown(Attempt attempt, String error) {
        updateTerminal(attempt, "STUCK_UNKNOWN", truncate(error));
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
                   updated_at, attempts, created_at
            FROM institutional_transaction_outbox
            WHERE status IN ('RESERVED', 'PREPARED', 'RETRYABLE')
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
                   updated_at, attempts, created_at
            FROM institutional_transaction_outbox
            WHERE chain_id = ? AND LOWER(wallet_address) = LOWER(?)
              AND (status IN ('RESERVED', 'PREPARED', 'RETRYABLE')
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
                   updated_at, attempts, created_at
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
                   updated_at, attempts, created_at
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
        if (jdbcTemplate == null || attempt == null) {
            return;
        }
        jdbcTemplate.update(
            """
            UPDATE institutional_transaction_outbox
            SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'SUBMITTED', 'STUCK_UNKNOWN')
            """,
            status, error, attempt.id()
        );
    }

    private Attempt find(String walletAddress, BigInteger chainId, String operationKey, boolean forUpdate) {
        String lock = forUpdate ? " FOR UPDATE" : "";
        var rows = jdbcTemplate.query(
            """
            SELECT id, chain_id, wallet_address, operation_key, nonce, original_gas_price, current_gas_price, gas_limit,
                   to_address, value_wei, data, status, signed_raw_transaction, tx_hash,
                   updated_at, attempts, created_at
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
                   updated_at, attempts, created_at
            FROM institutional_transaction_outbox
            WHERE wallet_address = ? AND chain_id = ?
              AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'STUCK_UNKNOWN')
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
            rs.getTimestamp("created_at") != null ? rs.getTimestamp("created_at").toInstant() : null
        );
    }

    private boolean hasDedicatedPublisherBlocker(String walletAddress, BigInteger chainId) {
        Long checkIn = jdbcTemplate.queryForObject(
            """
            SELECT COUNT(*)
            FROM institutional_checkin_outbox
            WHERE wallet_address = ? AND chain_id = ? AND nonce IS NOT NULL
              AND status IN ('SUBMITTING', 'RETRY', 'STUCK_UNKNOWN')
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
              AND onchain_status IN ('QUEUED', 'SUBMITTING', 'RETRY', 'STUCK_UNKNOWN', 'FAILED')
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
