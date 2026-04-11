package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class RecordProviderPayoutRequest {
    @NotBlank
    private String providerAddress;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;

    @DecimalMin(value = "0.0", inclusive = true)
    private BigDecimal creditAmount;

    private String bankRef;
    private String eurcTxHash;
    private String usdcTxHash;
}
