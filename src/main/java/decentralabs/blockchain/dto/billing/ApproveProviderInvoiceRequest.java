package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class ApproveProviderInvoiceRequest {
    @NotBlank
    @Size(max = 256)
    private String approvalRef;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;
}
