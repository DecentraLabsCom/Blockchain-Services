package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class RecordProviderPayoutRequest {
    @NotBlank
    @Size(max = 42)
    private String providerAddress;

    @NotBlank
    @Size(max = 42)
    private String paidBy;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;

    @DecimalMin(value = "0.0", inclusive = true)
    private BigDecimal creditAmount;

    @NotBlank
    @Size(max = 256)
    private String paymentRef;

    @NotBlank
    @Size(max = 256)
    private String paymentAttestation;

    @Size(max = 256)
    private String bankRef;
    @Size(max = 256)
    private String eurcTxHash;
    @Size(max = 256)
    private String usdcTxHash;
}
