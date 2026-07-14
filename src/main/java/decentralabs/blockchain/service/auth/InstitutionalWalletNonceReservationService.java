package decentralabs.blockchain.service.auth;

import java.math.BigInteger;
import java.util.function.BiConsumer;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Commits nonce allocation and its owning outbox row before any RPC broadcast. */
@Service
public class InstitutionalWalletNonceReservationService {
    private final InstitutionalCheckInOutboxService nonceStore;
    private final JdbcTemplate jdbcTemplate;

    /** Kept for focused unit tests and deployments that do not configure JDBC. */
    public InstitutionalWalletNonceReservationService(InstitutionalCheckInOutboxService nonceStore) {
        this.nonceStore = nonceStore;
        this.jdbcTemplate = null;
    }

    @Autowired
    public InstitutionalWalletNonceReservationService(
        InstitutionalCheckInOutboxService nonceStore,
        ObjectProvider<JdbcTemplate> jdbcTemplateProvider
    ) {
        this.nonceStore = nonceStore;
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    @Transactional
    public BigInteger reserveAndPersist(
        String walletAddress,
        BigInteger chainId,
        BigInteger nodePendingNonce,
        BiConsumer<BigInteger, BigInteger> persistNonce
    ) {
        BigInteger nonce = nonceStore.reserveNextNonce(chainId, walletAddress, nodePendingNonce);
        rejectAnyBlocker(walletAddress, chainId);
        persistNonce.accept(chainId, nonce);
        return nonce;
    }

    @Transactional
    public BigInteger reserve(String walletAddress, BigInteger chainId, BigInteger nodePendingNonce) {
        BigInteger nonce = nonceStore.reserveNextNonce(chainId, walletAddress, nodePendingNonce);
        rejectAnyBlocker(walletAddress, chainId);
        return nonce;
    }

    /**
     * Generic attempts and the dedicated check-in/session publishers share one
     * nonce row. A generic RESERVED/RETRYABLE attempt must therefore stop every
     * other producer before it can allocate a higher nonce.
     */
    private void rejectAnyBlocker(String walletAddress, BigInteger chainId) {
        if (jdbcTemplate == null) {
            return;
        }
        List<MapRow> blockers = jdbcTemplate.query(
            """
            SELECT id
            FROM institutional_transaction_outbox
            WHERE wallet_address = ? AND chain_id = ?
              AND status IN ('RESERVED', 'PREPARED', 'RETRYABLE', 'SUBMITTED', 'REPLACEMENT_PENDING', 'STUCK_UNKNOWN')
            ORDER BY nonce ASC
            LIMIT 1
            FOR UPDATE
            """,
            (rs, rowNum) -> new MapRow(rs.getLong("id")),
            walletAddress,
            chainId
        );
        if (!blockers.isEmpty()) {
            throw new TransactionBlockedException(
                "Institutional wallet has an unresolved generic transaction attempt"
            );
        }
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
            throw new TransactionBlockedException(
                "Institutional wallet has an unresolved check-in transaction"
            );
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
        if (sessionStarted != null && sessionStarted > 0) {
            throw new TransactionBlockedException(
                "Institutional wallet has an unresolved SessionStarted transaction"
            );
        }
    }

    private record MapRow(long id) { }

    public static class TransactionBlockedException extends RuntimeException {
        public TransactionBlockedException(String message) {
            super(message);
        }
    }
}
