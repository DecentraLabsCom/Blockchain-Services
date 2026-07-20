package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Completed provider payout with settlement proof references.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderPayout {

    private Long id;
    private Long invoiceRecordId;
    private String labId;
    private String providerAddress;
    private String claimId;
    private BigDecimal eurAmount;
    private BigDecimal creditAmount;
    private Instant paidAt;
    private String paidBy;
    private String paymentRef;
    private String paymentAttestation;
    private String bankRef;
    private String eurcTxHash;
    private String usdcTxHash;
}
