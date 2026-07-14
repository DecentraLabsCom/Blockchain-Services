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
    String signedRawTransaction,
    BigInteger originalGasPrice,
    BigInteger currentGasPrice,
    long generation
) {
    public InstitutionalCheckInOutboxRecord(
        long id, String reservationKey, String labId, String institutionalWallet,
        String pucHash, String accessSessionId, String status, int attempts,
        Instant nextAttemptAt, String txHash, String walletAddress, BigInteger nonce,
        Instant submittedAt
    ) {
        this(id, reservationKey, labId, institutionalWallet, pucHash, accessSessionId,
            status, attempts, nextAttemptAt, txHash, walletAddress, null, nonce, submittedAt, 0L, null, null, null, 1L);
    }

    public InstitutionalCheckInOutboxRecord(
        long id, String reservationKey, String labId, String institutionalWallet,
        String pucHash, String accessSessionId, String status, int attempts,
        Instant nextAttemptAt, String txHash, String walletAddress, BigInteger chainId,
        BigInteger nonce, Instant submittedAt, long version
    ) {
        this(id, reservationKey, labId, institutionalWallet, pucHash, accessSessionId,
            status, attempts, nextAttemptAt, txHash, walletAddress, chainId, nonce, submittedAt, version, null, null, null, 1L);
    }

    public InstitutionalCheckInOutboxRecord(
        long id, String reservationKey, String labId, String institutionalWallet,
        String pucHash, String accessSessionId, String status, int attempts,
        Instant nextAttemptAt, String txHash, String walletAddress, BigInteger chainId,
        BigInteger nonce, Instant submittedAt, long version, String signedRawTransaction
    ) {
        this(id, reservationKey, labId, institutionalWallet, pucHash, accessSessionId,
            status, attempts, nextAttemptAt, txHash, walletAddress, chainId, nonce,
            submittedAt, version, signedRawTransaction, null, null, 1L);
    }
}
