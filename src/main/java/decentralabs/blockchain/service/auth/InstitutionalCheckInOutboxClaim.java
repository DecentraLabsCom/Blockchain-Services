package decentralabs.blockchain.service.auth;

/**
 * Durable ownership token returned when a check-in outbox row is claimed.
 *
 * The claim version identifies the generation of the ownership lease. The
 * row's ordinary version may advance while the worker persists a nonce and a
 * signed transaction, so mutations must check both values.
 */
public record InstitutionalCheckInOutboxClaim(
    InstitutionalCheckInOutboxRecord record,
    String claimId,
    String claimedBy,
    long claimVersion
) {
    public long outboxId() {
        return record.id();
    }
}
