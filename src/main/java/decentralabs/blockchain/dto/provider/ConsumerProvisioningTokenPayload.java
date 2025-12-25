package decentralabs.blockchain.dto.provider;

import lombok.Builder;
import lombok.Value;

/**
 * Payload extracted from consumer provisioning token after verification
 */
@Value
@Builder
public class ConsumerProvisioningTokenPayload {
    String type; // Should be "consumer"
    String marketplaceBaseUrl;
    String apiKey;
    String consumerName;
    String consumerOrganization;
    String jti;
}
