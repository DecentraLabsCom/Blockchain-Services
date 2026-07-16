package decentralabs.blockchain.service.organization;

import java.math.BigInteger;

/**
 * Claims covered by the institutional wallet's EIP-712 provisioning proof.
 */
public record ProvisioningSecurityClaims(
    String institutionId,
    String walletAddress,
    String canonicalBackendOrigin,
    String registrationType,
    BigInteger chainId,
    String registryContract,
    String jti,
    String nonce,
    long issuedAt,
    long expiresAt
) { }

