package decentralabs.blockchain.dto.provider;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for applying a provisioning token issued by the Marketplace
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningTokenRequest {

    @NotBlank(message = "Provisioning token is required")
    private String token;
}
