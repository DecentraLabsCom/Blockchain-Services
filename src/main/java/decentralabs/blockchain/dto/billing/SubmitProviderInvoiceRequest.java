package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class SubmitProviderInvoiceRequest {
    @NotBlank
    @Size(max = 42)
    private String providerAddress;

    @NotBlank
    @Size(max = 128)
    private String claimId;

    @NotBlank
    @Pattern(regexp = "0x[0-9a-fA-F]{64}")
    private String reservationHash;

    @NotBlank
    @Size(max = 256)
    private String invoiceRef;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;

    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal creditAmount;
}
