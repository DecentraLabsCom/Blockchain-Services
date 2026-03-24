package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Off-chain projection of a single credit lot (funding tranche).
 * Mirrors CreditLedgerFacet.getCreditLots() on-chain data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreditLot {

    private Long id;
    private String accountAddress;
    private int lotIndex;
    private Long fundingOrderId;
    private BigDecimal eurGrossAmount;
    private BigDecimal creditAmount;
    private BigDecimal remaining;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean expired;
}
