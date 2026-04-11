package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;
import java.time.Instant;
import lombok.Data;

@Data
public class CreateFundingOrderRequest {
    @NotBlank
    private String institutionAddress;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurGrossAmount;

    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal creditAmount;

    private String reference;
    private Instant expiresAt;
}
