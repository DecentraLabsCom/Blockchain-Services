package decentralabs.blockchain.service.organization;

import java.math.BigInteger;

/** Exact values signed by the institutional wallet during backend pairing. */
public record ProvisioningPairingSecurityClaims(
    String institutionId,
    String walletAddress,
    String canonicalBackendOrigin,
    String registrationType,
    BigInteger chainId,
    String registryContract,
    String challenge,
    long issuedAt,
    long expiresAt
) { }
