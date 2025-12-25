package decentralabs.blockchain.dto.provider;

import lombok.Builder;
import lombok.Value;

/**
 * Payload extracted from provisioning token after verification
 */
@Value
@Builder
public class ProvisioningTokenPayload {
    String marketplaceBaseUrl;
    String apiKey;
    String providerName;
    String providerEmail;
    String providerCountry;
    String providerOrganization;
    String publicBaseUrl;
    String jti;
}
