package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class ApproveProviderInvoiceRequest {
    @NotBlank
    private String approvedBy;

    private String approvalRef;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;
}
