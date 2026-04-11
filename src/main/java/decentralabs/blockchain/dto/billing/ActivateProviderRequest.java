package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.NotBlank;
import java.time.LocalDate;
import lombok.Data;

@Data
public class ActivateProviderRequest {
    @NotBlank
    private String providerAddress;

    @NotBlank
    private String contractId;

    @NotBlank
    private String agreementVersion;

    private String activatedBy;
    private LocalDate effectiveDate;
    private LocalDate expiryDate;
}
