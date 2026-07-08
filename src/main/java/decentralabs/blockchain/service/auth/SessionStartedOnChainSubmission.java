package decentralabs.blockchain.service.auth;

public record SessionStartedOnChainSubmission(
    long id,
    String reservationKey,
    String labId,
    String pucHash,
    String signerAddress,
    String gatewayId,
    String sessionId,
    String accessType,
    long startedAt,
    String nonce,
    String credentialHash,
    String clientProofHash,
    String signature
) { }
