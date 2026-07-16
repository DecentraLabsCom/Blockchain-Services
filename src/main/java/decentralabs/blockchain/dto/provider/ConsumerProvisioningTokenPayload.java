package decentralabs.blockchain.dto.provider;

import decentralabs.blockchain.service.organization.ProvisioningSecurityClaims;
import java.math.BigInteger;
import lombok.Builder;
import lombok.Value;

/**
 * Payload extracted from consumer provisioning token after verification
 */
@Value
@Builder
public class ConsumerProvisioningTokenPayload {
    String registrationType;
    String marketplaceBaseUrl;
    String institutionId;
    String walletAddress;
    String canonicalBackendOrigin;
    BigInteger chainId;
    String registryContract;
    String nonce;
    long issuedAt;
    long expiresAt;
    String consumerName;
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
