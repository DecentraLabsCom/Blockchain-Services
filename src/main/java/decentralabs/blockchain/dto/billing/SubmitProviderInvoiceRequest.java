package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class SubmitProviderInvoiceRequest {
    @NotBlank
    private String providerAddress;

    @NotBlank
    private String invoiceRef;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;

    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal creditAmount;
}
