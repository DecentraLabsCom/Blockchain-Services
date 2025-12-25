package decentralabs.blockchain.dto.provider;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for provider configuration request
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderConfigurationRequest {

    @NotBlank(message = "Marketplace base URL is required")
    private String marketplaceBaseUrl;

    @NotBlank(message = "Marketplace API key is required")
    @Size(min = 32, message = "API key must be at least 32 characters")
    private String marketplaceApiKey;

    @NotBlank(message = "Provider name is required")
    private String providerName;

    @NotBlank(message = "Provider email is required")
    @Email(message = "Invalid email format")
    private String providerEmail;

    @NotBlank(message = "Provider country is required")
    private String providerCountry;

    @NotBlank(message = "Provider organization is required")
    private String providerOrganization;

    @NotBlank(message = "Public base URL is required")
    private String publicBaseUrl;
}
