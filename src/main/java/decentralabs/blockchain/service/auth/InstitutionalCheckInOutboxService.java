package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.util.LogSanitizer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class InstitutionalCheckInOutboxService {
    private static final long PROCESSING_STALE_AFTER_SECONDS = 15 * 60;
    private static final long DEFAULT_CLAIM_LEASE_MILLIS = 15 * 60 * 1000L;

    private final JdbcTemplate jdbcTemplate;
    private final String workerId = UUID.randomUUID().toString();

    @Value("${institutional.checkin.outbox.claim-lease-ms:900000}")
    private long claimLeaseMillis;

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
            SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                   access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                   wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
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
            SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                   access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                   wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
            FROM institutional_checkin_outbox WHERE id = ?
            """,
            (rs, rowNum) -> mapRow(rs),
            id
        );
    }

    /**
     * Starts a new check-in generation only after the caller has revalidated
     * the reservation. A FAILED row that already owns a nonce must retain that
     * nonce so a retry cannot create a permanent gap in the wallet sequence.
     * MINED_FAILED has consumed its nonce on-chain and may start with a new
     * allocation.
     */
    public InstitutionalCheckInOutboxRecord restartTerminalFailure(long id) {
        requireConfigured();
        jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET wallet_address = CASE
                    WHEN status = 'FAILED' AND nonce IS NOT NULL THEN wallet_address
                    ELSE NULL
                END,
                chain_id = CASE
                    WHEN status = 'FAILED' AND nonce IS NOT NULL THEN chain_id
                    ELSE NULL
                END,
                nonce = CASE
                    WHEN status = 'FAILED' AND nonce IS NOT NULL THEN nonce
                    ELSE NULL
                END,
                generation = CASE
                    WHEN status = 'MINED_FAILED'
                      OR (status = 'FAILED' AND nonce IS NULL) THEN generation + 1
                    ELSE generation
                END,
                status = 'PENDING',
                attempts = 0,
                next_attempt_at = CURRENT_TIMESTAMP,
                tx_hash = CASE
                    WHEN status = 'FAILED' AND nonce IS NOT NULL THEN tx_hash
                    ELSE NULL
                END,
                signed_raw_transaction = CASE
                    WHEN status = 'FAILED' AND nonce IS NOT NULL THEN signed_raw_transaction
                    ELSE NULL
                END,
                original_gas_price = CASE
                    WHEN status = 'MINED_FAILED'
                      OR (status = 'FAILED' AND nonce IS NULL) THEN NULL
                    ELSE original_gas_price
                END,
                current_gas_price = CASE
                    WHEN status = 'MINED_FAILED'
                      OR (status = 'FAILED' AND nonce IS NULL) THEN NULL
                    ELSE current_gas_price
                END,
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

    public List<InstitutionalCheckInOutboxRecord> findDue(
        BigInteger chainId, String walletAddress, Instant now, int limit
    ) {
        if (jdbcTemplate == null || chainId == null || chainId.signum() <= 0
                || !hasText(walletAddress) || now == null || limit <= 0) {
            return List.of();
        }
        try {
            Instant staleProcessingCutoff = now.minusSeconds(PROCESSING_STALE_AFTER_SECONDS);
            return jdbcTemplate.query(
                """
                SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                       wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
                FROM institutional_checkin_outbox
                WHERE (
                    (status IN ('PENDING', 'RETRY', 'REPLACEMENT_PENDING') AND next_attempt_at <= ?)
                    OR (status = 'SUBMITTING' AND updated_at <= ?)
                  )
                  AND (
                    (chain_id = ? AND LOWER(wallet_address) = LOWER(?))
                    OR (chain_id IS NULL
                        AND status IN ('PENDING', 'RETRY', 'SUBMITTING')
                        AND LOWER(institutional_wallet) = LOWER(?))
                  )
                ORDER BY next_attempt_at ASC, id ASC
                LIMIT ?
                """,
                (rs, rowNum) -> mapRow(rs),
                Timestamp.from(now),
                Timestamp.from(staleProcessingCutoff),
                chainId,
                walletAddress.trim(),
                walletAddress.trim(),
                limit
            );
        } catch (Exception ex) {
            log.warn("Institutional check-in outbox lookup skipped: {}", LogSanitizer.sanitize(ex.getMessage()));
            return List.of();
        }
    }

    /** Claims a due row and returns the exact durable ownership token. */
    public InstitutionalCheckInOutboxClaim claim(long id) {
        if (jdbcTemplate == null) {
            return null;
        }
        String claimId = UUID.randomUUID().toString();
        Timestamp claimExpiresAt = Timestamp.from(
            Instant.now().plusMillis(claimLeaseMillis > 0 ? claimLeaseMillis : DEFAULT_CLAIM_LEASE_MILLIS)
        );
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTING', claim_version = version + 1,
                version = version + 1, claim_id = ?, claimed_by = ?,
                claim_expires_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND (
                status IN ('PENDING', 'RETRY', 'REPLACEMENT_PENDING')
                OR (status = 'SUBMITTING' AND (
                    claim_expires_at IS NULL OR claim_expires_at <= CURRENT_TIMESTAMP
                ))
              )
            """,
            claimId,
            workerId,
            claimExpiresAt,
            id
        );
        if (updated != 1) {
            return null;
        }
        InstitutionalCheckInOutboxRecord record = findClaimedById(id, claimId, workerId);
        return record == null
            ? null
            : new InstitutionalCheckInOutboxClaim(record, claimId, workerId, record.version());
    }

    /** Reads a row only while the supplied durable claim still owns it. */
    public InstitutionalCheckInOutboxRecord findClaimed(InstitutionalCheckInOutboxClaim claim) {
        if (claim == null) {
            return null;
        }
        try {
            return jdbcTemplate.queryForObject(
                """
                SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                       wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
                FROM institutional_checkin_outbox
                WHERE id = ? AND claim_id = ? AND claimed_by = ? AND claim_version = ?
                  AND claim_expires_at > CURRENT_TIMESTAMP
                """,
                (rs, rowNum) -> mapRow(rs),
                claim.outboxId(), claim.claimId(), claim.claimedBy(), claim.claimVersion()
            );
        } catch (org.springframework.dao.EmptyResultDataAccessException ex) {
            return null;
        }
    }

    private InstitutionalCheckInOutboxRecord findClaimedById(long id, String claimId, String claimedBy) {
        try {
            return jdbcTemplate.queryForObject(
                """
                SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                       wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
                FROM institutional_checkin_outbox
                WHERE id = ? AND claim_id = ? AND claimed_by = ?
                  AND claim_expires_at > CURRENT_TIMESTAMP
                """,
                (rs, rowNum) -> mapRow(rs),
                id, claimId, claimedBy
            );
        } catch (org.springframework.dao.EmptyResultDataAccessException ex) {
            return null;
        }
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

    public boolean markNonceReserved(
        InstitutionalCheckInOutboxClaim claim,
        String walletAddress,
        BigInteger chainId,
        BigInteger nonce
    ) {
        if (jdbcTemplate == null || claim == null) {
            return false;
        }
        return jdbcTemplate.update(
            "UPDATE institutional_checkin_outbox SET wallet_address = ?, chain_id = ?, nonce = ?, "
                + "version = version + 1, updated_at = CURRENT_TIMESTAMP "
                + "WHERE id = ? AND status = 'SUBMITTING' AND claim_id = ? AND claimed_by = ? "
                + "AND claim_version = ? AND claim_expires_at > CURRENT_TIMESTAMP",
            walletAddress,
            chainId,
            nonce,
            claim.outboxId(),
            claim.claimId(),
            claim.claimedBy(),
            claim.claimVersion()
        ) == 1;
    }

    public List<InstitutionalCheckInOutboxRecord> findSubmitted(
        BigInteger chainId, String walletAddress, Instant now, int limit
    ) {
        if (jdbcTemplate == null || chainId == null || chainId.signum() <= 0
                || !hasText(walletAddress) || now == null || limit <= 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                       wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
                FROM institutional_checkin_outbox
                WHERE status = 'SUBMITTED'
                  AND chain_id = ?
                  AND LOWER(wallet_address) = LOWER(?)
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                (rs, rowNum) -> mapRow(rs),
                chainId,
                walletAddress.trim(),
                limit
            );
        } catch (Exception ex) {
            log.warn("Institutional check-in receipt lookup skipped: {}", LogSanitizer.sanitize(ex.getMessage()));
            return List.of();
        }
    }

    public List<InstitutionalCheckInOutboxRecord> findStuckUnknown(
        BigInteger chainId, String walletAddress, int limit
    ) {
        if (jdbcTemplate == null || chainId == null || chainId.signum() <= 0
                || !hasText(walletAddress) || limit <= 0) {
            return List.of();
        }
        try {
            return jdbcTemplate.query(
                """
                SELECT id, generation, reservation_key, lab_id, institutional_wallet, puc_hash,
                       access_session_id, status, attempts, next_attempt_at, tx_hash, signed_raw_transaction,
                       wallet_address, chain_id, nonce, submitted_at, version, original_gas_price, current_gas_price
                FROM institutional_checkin_outbox
                WHERE status = 'STUCK_UNKNOWN'
                  AND chain_id = ?
                  AND LOWER(wallet_address) = LOWER(?)
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                (rs, rowNum) -> mapRow(rs),
                chainId,
                walletAddress.trim(),
                limit
            );
        } catch (Exception ex) {
            log.warn("Institutional check-in reconciliation lookup skipped: {}", LogSanitizer.sanitize(ex.getMessage()));
            return List.of();
        }
    }

    public List<String> findReplacedHashes(long outboxId, long generation) {
        if (jdbcTemplate == null) {
            return List.of();
        }
        return jdbcTemplate.query(
            """
            SELECT tx_hash
            FROM institutional_checkin_outbox_hash_history
            WHERE outbox_id = ? AND generation = ?
            ORDER BY replaced_at ASC, id ASC
            """,
            (rs, rowNum) -> rs.getString("tx_hash"),
            outboxId, generation
        );
    }

    /** Marks a rebroadcast of already persisted material using the observed row version. */
    public boolean markSubmitted(
        InstitutionalCheckInOutboxClaim claim,
        InstitutionalCheckInOutboxRecord record,
        String txHash
    ) {
        if (jdbcTemplate == null || claim == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTED', tx_hash = ?, submitted_at = CURRENT_TIMESTAMP,
                last_error = NULL, claim_id = NULL, claimed_by = NULL,
                claim_version = NULL, claim_expires_at = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING' AND tx_hash <=> ? AND version = ?
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            txHash, record.id(), record.txHash(), record.version(),
            claim.claimId(), claim.claimedBy(), claim.claimVersion()
        ) == 1;
    }

    /** Marks the hash after the durable preparation write. */
    public boolean markSubmittedAfterPreparation(
        InstitutionalCheckInOutboxClaim claim,
        InstitutionalCheckInOutboxRecord record,
        String txHash
    ) {
        if (jdbcTemplate == null || claim == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTED', tx_hash = ?, submitted_at = CURRENT_TIMESTAMP,
                last_error = NULL, claim_id = NULL, claimed_by = NULL,
                claim_version = NULL, claim_expires_at = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING' AND tx_hash = ? AND version = ?
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            txHash, record.id(), txHash, record.version() + 1L,
            claim.claimId(), claim.claimedBy(), claim.claimVersion()
        ) == 1;
    }

    public boolean markMinedSuccess(
        InstitutionalCheckInOutboxClaim claim,
        InstitutionalCheckInOutboxRecord record,
        String txHash
    ) {
        if (jdbcTemplate == null || claim == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_SUCCESS',
                tx_hash = COALESCE(?, tx_hash),
                mined_at = CURRENT_TIMESTAMP,
                last_error = NULL,
                claim_id = NULL, claimed_by = NULL, claim_version = NULL, claim_expires_at = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            txHash,
            claim.outboxId(), claim.claimId(), claim.claimedBy(), claim.claimVersion()
        ) == 1;
    }

    public boolean markRetry(
        InstitutionalCheckInOutboxClaim claim,
        int attempts,
        Instant nextAttemptAt,
        String error
    ) {
        if (jdbcTemplate == null || claim == null || nextAttemptAt == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'RETRY',
                attempts = ?,
                next_attempt_at = ?,
                last_error = ?,
                claim_id = NULL, claimed_by = NULL, claim_version = NULL, claim_expires_at = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            attempts,
            Timestamp.from(nextAttemptAt),
            truncate(error),
            claim.outboxId(), claim.claimId(), claim.claimedBy(), claim.claimVersion()
        ) == 1;
    }

    public boolean markReplacementPending(
        InstitutionalCheckInOutboxRecord record, int attempts, Instant nextAttemptAt, String error
    ) {
        if (jdbcTemplate == null || record == null || nextAttemptAt == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'REPLACEMENT_PENDING', attempts = ?, next_attempt_at = ?, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            attempts, Timestamp.from(nextAttemptAt), truncate(error),
            record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markFailed(
        InstitutionalCheckInOutboxClaim claim,
        int attempts,
        String error
    ) {
        if (jdbcTemplate == null || claim == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'FAILED',
                attempts = ?,
                last_error = ?,
                claim_id = NULL, claimed_by = NULL, claim_version = NULL, claim_expires_at = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            attempts,
            truncate(error),
            claim.outboxId(), claim.claimId(), claim.claimedBy(), claim.claimVersion()
        ) == 1;
    }

    @Transactional
    public void markPrepared(
        InstitutionalCheckInOutboxClaim claim,
        InstitutionalCheckInOutboxRecord record,
        InstitutionalWalletTransactionDispatcher.PreparedTransaction prepared
    ) {
        if (jdbcTemplate == null || claim == null || record == null || prepared == null) {
            return;
        }
        BigInteger gasPrice = prepared.gasPrice() != null
            ? prepared.gasPrice() : record.currentGasPrice();
        BigInteger previousGasPrice = record.currentGasPrice() != null
            ? record.currentGasPrice() : record.originalGasPrice();
        if (record.txHash() != null && !record.txHash().isBlank()) {
            jdbcTemplate.update(
                """
                INSERT INTO institutional_checkin_outbox_hash_history
                    (outbox_id, generation, tx_hash, gas_price, replaced_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON DUPLICATE KEY UPDATE gas_price = VALUES(gas_price)
                """,
                record.id(), record.generation(), record.txHash(),
                previousGasPrice != null ? previousGasPrice : BigInteger.ZERO
            );
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET signed_raw_transaction = ?, tx_hash = ?,
                original_gas_price = COALESCE(original_gas_price, ?),
                current_gas_price = COALESCE(?, current_gas_price),
                updated_at = CURRENT_TIMESTAMP, version = version + 1
            WHERE id = ? AND generation = ? AND status = 'SUBMITTING'
              AND tx_hash <=> ? AND version = ?
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            prepared.rawTransaction(), prepared.transactionHash(), gasPrice, gasPrice,
            record.id(), record.generation(), record.txHash(), record.version(),
            claim.claimId(), claim.claimedBy(), claim.claimVersion()
        );
        if (updated != 1) {
            throw new IllegalStateException("Check-in signed transaction lost its fencing claim");
        }
    }

    public boolean markBroadcastUncertain(
        InstitutionalCheckInOutboxClaim claim,
        int attempts,
        String error
    ) {
        if (jdbcTemplate == null || claim == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'STUCK_UNKNOWN',
                attempts = ?,
                submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP),
                last_error = ?,
                claim_id = NULL, claimed_by = NULL, claim_version = NULL, claim_expires_at = NULL,
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTING'
              AND claim_id = ? AND claimed_by = ? AND claim_version = ?
              AND claim_expires_at > CURRENT_TIMESTAMP
            """,
            attempts,
            truncate(error),
            claim.outboxId(), claim.claimId(), claim.claimedBy(), claim.claimVersion()
        ) == 1;
    }

    private InstitutionalCheckInOutboxRecord mapRow(ResultSet rs) throws SQLException {
        Timestamp nextAttempt = rs.getTimestamp("next_attempt_at");
        long generation = rs.getLong("generation");
        if (rs.wasNull() || generation <= 0) {
            generation = 1L;
        }
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
            rs.getLong("version"),
            rs.getString("signed_raw_transaction"),
            rs.getObject("original_gas_price", BigInteger.class),
            rs.getObject("current_gas_price", BigInteger.class),
            generation
        );
    }

    public boolean markSubmittedMinedSuccess(InstitutionalCheckInOutboxRecord record) {
        return markSubmittedMinedSuccess(record, null);
    }

    public boolean markSubmittedMinedSuccess(
        InstitutionalCheckInOutboxRecord record, String minedTxHash
    ) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_SUCCESS', tx_hash = COALESCE(?, tx_hash),
                mined_at = CURRENT_TIMESTAMP, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            minedTxHash, record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markSubmittedMinedFailed(InstitutionalCheckInOutboxRecord record, String error) {
        return markSubmittedMinedFailed(record, null, error);
    }

    public boolean markSubmittedMinedFailed(
        InstitutionalCheckInOutboxRecord record, String minedTxHash, String error
    ) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_FAILED', tx_hash = COALESCE(?, tx_hash),
                mined_at = CURRENT_TIMESTAMP, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'SUBMITTED' AND tx_hash = ? AND version = ?
            """,
            minedTxHash, truncate(error), record.id(), record.txHash(), record.version()
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

    public boolean markUnknownVisibleSubmitted(InstitutionalCheckInOutboxRecord record) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTED', submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP),
                last_error = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markUnknownMinedSuccess(InstitutionalCheckInOutboxRecord record) {
        return markUnknownMinedSuccess(record, null);
    }

    public boolean markUnknownMinedSuccess(
        InstitutionalCheckInOutboxRecord record, String minedTxHash
    ) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_SUCCESS', tx_hash = COALESCE(?, tx_hash),
                mined_at = CURRENT_TIMESTAMP, last_error = NULL,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            minedTxHash, record.id(), record.txHash(), record.version()
        ) == 1;
    }

    public boolean markUnknownMinedFailed(InstitutionalCheckInOutboxRecord record, String error) {
        return markUnknownMinedFailed(record, null, error);
    }

    public boolean markUnknownMinedFailed(
        InstitutionalCheckInOutboxRecord record, String minedTxHash, String error
    ) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'MINED_FAILED', tx_hash = COALESCE(?, tx_hash),
                mined_at = CURRENT_TIMESTAMP, last_error = ?,
                version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            minedTxHash, truncate(error), record.id(), record.txHash(), record.version()
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

    public boolean markUnknownRebroadcast(InstitutionalCheckInOutboxRecord record, String txHash) {
        if (jdbcTemplate == null || record == null) {
            return false;
        }
        return jdbcTemplate.update(
            """
            UPDATE institutional_checkin_outbox
            SET status = 'SUBMITTED', tx_hash = COALESCE(?, tx_hash),
                submitted_at = COALESCE(submitted_at, CURRENT_TIMESTAMP),
                last_error = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND status = 'STUCK_UNKNOWN' AND tx_hash <=> ? AND version = ?
            """,
            txHash, record.id(), record.txHash(), record.version()
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
