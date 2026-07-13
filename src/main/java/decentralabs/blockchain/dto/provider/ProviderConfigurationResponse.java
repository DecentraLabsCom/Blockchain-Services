package decentralabs.blockchain.dto.provider;

import com.fasterxml.jackson.annotation.JsonProperty;
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
    private String consumerName;
    private String providerName;
    private String providerEmail;
    private String providerCountry;
    private String providerOrganization;
    private String publicBaseUrl;
    @JsonProperty("isConfigured")
    private boolean isConfigured;
    @JsonProperty("isRegistered")
    private boolean isRegistered;
    private boolean providerRegistered;
    private boolean consumerRegistered;
    private boolean providerRegistrationEnabled;
    private String operatingMode;
    private String registrationRole;
    private boolean fromProvisioningToken;
    private List<String> lockedFields;
    private boolean localConfigSaved;
    private boolean localRegistrationCached;
    private boolean onChainStatusAvailable;
    private String walletAddress;
    private boolean providerRoleOnChain;
    private boolean institutionRoleOnChain;
    private String organizationOwner;
    private String backendUrlOnChain;
    private String authorizedBackendOnChain;
    private String providerNetworkStatus;
    private boolean fullyOperational;
}
