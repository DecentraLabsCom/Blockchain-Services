package decentralabs.blockchain.dto.treasury;

import java.math.BigInteger;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Snapshot of an institutional user's allowance/usage on-chain.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InstitutionalUserFinancialStats {
    private BigInteger currentPeriodSpent;
    private BigInteger totalHistoricalSpent;
    private BigInteger spendingLimit;
    private BigInteger remainingAllowance;
    private BigInteger periodStart;
    private BigInteger periodEnd;
    private BigInteger periodDuration;
}

