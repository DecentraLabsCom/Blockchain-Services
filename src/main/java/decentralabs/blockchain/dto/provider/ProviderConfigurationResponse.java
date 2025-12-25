package decentralabs.blockchain.dto.provider;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for provider configuration status response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderConfigurationResponse {

    private String marketplaceBaseUrl;
    private boolean hasApiKey; // Don't expose actual key
    private String providerName;
    private String providerEmail;
    private String providerCountry;
    private String providerOrganization;
    private String publicBaseUrl;
    private boolean isConfigured;
    private boolean isRegistered;
    private boolean fromProvisioningToken;
    private List<String> lockedFields;
}
