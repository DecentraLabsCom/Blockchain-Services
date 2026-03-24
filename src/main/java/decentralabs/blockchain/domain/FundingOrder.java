package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Prepaid credit purchase order. Tracks the lifecycle from draft through
 * invoicing, payment confirmation, and on-chain credit minting.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FundingOrder {

    public enum Status { DRAFT, INVOICED, PAID, CREDITED, CANCELLED }

    private Long id;
    private String institutionAddress;
    private BigDecimal eurGrossAmount;
    private BigDecimal creditAmount;
    private Status status;
    private String reference;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant expiresAt;
}
