package decentralabs.blockchain.service.auth;

import java.time.Instant;
import java.math.BigInteger;

public record InstitutionalCheckInOutboxRecord(
    long id,
    String reservationKey,
    String labId,
    String institutionalWallet,
    String pucHash,
    String accessSessionId,
    String status,
    int attempts,
    Instant nextAttemptAt,
    String txHash,
    String walletAddress,
    BigInteger chainId,
    BigInteger nonce,
    Instant submittedAt,
    long version,
    String signedRawTransaction
) {
    public InstitutionalCheckInOutboxRecord(
        long id, String reservationKey, String labId, String institutionalWallet,
        String pucHash, String accessSessionId, String status, int attempts,
        Instant nextAttemptAt, String txHash, String walletAddress, BigInteger nonce,
        Instant submittedAt
    ) {
        this(id, reservationKey, labId, institutionalWallet, pucHash, accessSessionId,
            status, attempts, nextAttemptAt, txHash, walletAddress, null, nonce, submittedAt, 0L, null);
    }

    public InstitutionalCheckInOutboxRecord(
        long id, String reservationKey, String labId, String institutionalWallet,
        String pucHash, String accessSessionId, String status, int attempts,
        Instant nextAttemptAt, String txHash, String walletAddress, BigInteger chainId,
        BigInteger nonce, Instant submittedAt, long version
    ) {
        this(id, reservationKey, labId, institutionalWallet, pucHash, accessSessionId,
            status, attempts, nextAttemptAt, txHash, walletAddress, chainId, nonce, submittedAt, version, null);
    }
}
