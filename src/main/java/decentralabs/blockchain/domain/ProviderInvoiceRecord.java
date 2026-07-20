package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Provider-submitted invoice for settlement of accrued receivables.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProviderInvoiceRecord {

    public enum Status { SUBMITTED, APPROVED, DISPUTED, PAID, CANCELLED }

    private Long id;
    private String labId;
    private String providerAddress;
    /** Stable claim identifier shared by the reservation set and settlement records. */
    private String claimId;
    /** Hash of the canonical, sorted reservation-key set covered by this claim. */
    private String reservationHash;
    private String invoiceRef;
    private BigDecimal eurAmount;
    private BigDecimal creditAmount;
    private Instant submittedAt;
    private Status status;
    private Instant updatedAt;
}
