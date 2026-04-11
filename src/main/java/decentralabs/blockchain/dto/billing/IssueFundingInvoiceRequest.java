package decentralabs.blockchain.dto.billing;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import lombok.Data;

@Data
public class IssueFundingInvoiceRequest {
    @NotBlank
    private String invoiceNumber;

    private Instant dueAt;
}
