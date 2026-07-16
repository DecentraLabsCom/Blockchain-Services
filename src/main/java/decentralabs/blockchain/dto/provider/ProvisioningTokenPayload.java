package decentralabs.blockchain.dto.provider;

import decentralabs.blockchain.service.organization.ProvisioningSecurityClaims;
import java.math.BigInteger;
import lombok.Builder;
import lombok.Value;

/**
 * Payload extracted from provisioning token after verification
 */
@Value
@Builder
public class ProvisioningTokenPayload {
    String marketplaceBaseUrl;
    String registrationType;
    String institutionId;
    String walletAddress;
    String canonicalBackendOrigin;
    BigInteger chainId;
    String registryContract;
    String nonce;
    long issuedAt;
    long expiresAt;
    String providerName;
    String providerEmail;
    String providerCountry;
    String jti;

    public ProvisioningSecurityClaims securityClaims() {
        return new ProvisioningSecurityClaims(
            institutionId,
            walletAddress,
            canonicalBackendOrigin,
            registrationType,
            chainId,
            registryContract,
            jti,
            nonce,
            issuedAt,
            expiresAt
        );
    }
}
