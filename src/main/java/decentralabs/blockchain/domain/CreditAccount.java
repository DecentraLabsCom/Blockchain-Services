package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Off-chain projection of an on-chain service-credit account.
 * Mirrors the balances held in the CreditLedgerFacet on-chain.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreditAccount {

    private Long id;
    private String accountAddress;
    private BigDecimal available;
    private BigDecimal locked;
    private BigDecimal consumed;
    private BigDecimal adjusted;
    private BigDecimal expired;
    private Instant updatedAt;
}
