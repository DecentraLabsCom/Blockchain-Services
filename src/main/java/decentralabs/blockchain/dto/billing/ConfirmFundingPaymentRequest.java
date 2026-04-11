package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.math.BigDecimal;
import lombok.Data;

@Data
public class ConfirmFundingPaymentRequest {
    @NotBlank
    private String paymentRef;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;

    private String paymentMethod;
}
