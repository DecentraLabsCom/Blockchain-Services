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
    BigInteger nonce,
    Instant submittedAt
) {
}
