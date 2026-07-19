package decentralabs.blockchain.service.organization;

/** Read-only result shown after the backend has offered its configured identity. */
public record ProvisioningPairingPreparation(
    String pairingId,
    String status,
    String institutionId,
    String registrationType,
    String walletAddress,
    String canonicalBackendOrigin,
    long expiresAt
) { }
