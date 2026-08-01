package decentralabs.blockchain.dto.billing;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = false)
public class SubmitProviderInvoiceRequest {
    @NotBlank
    @Size(max = 128)
    private String claimId;

    @NotBlank
    @Pattern(regexp = "0x[0-9a-fA-F]{64}")
    private String batchId;

    @NotBlank
    @Size(max = 256)
    private String invoiceRef;

    @NotNull
    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal eurAmount;

    @DecimalMin(value = "0.0", inclusive = false)
    private BigDecimal creditAmount;

    @JsonAnySetter
    private void rejectUnknownField(String fieldName, Object value) {
        throw new IllegalArgumentException("Unknown invoice request field: " + fieldName);
    }
}
