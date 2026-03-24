package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Invoice issued for a funding order. One funding order may have one invoice.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FundingInvoice {

    public enum Status { ISSUED, PAID, CANCELLED }

    private Long id;
    private Long fundingOrderId;
    private String invoiceNumber;
    private BigDecimal eurAmount;
    private Instant issuedAt;
    private Instant dueAt;
    private Status status;
}
