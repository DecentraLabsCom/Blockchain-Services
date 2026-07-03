package decentralabs.blockchain.service.auth;

import java.time.Instant;

public record InstitutionalCheckInOutboxRecord(
    long id,
    String reservationKey,
    String labId,
    String institutionalWallet,
    String pucHash,
    String accessSessionId,
    String status,
    int attempts,
    Instant nextAttemptAt
) {
}
