package decentralabs.blockchain.dto.wallet;

import lombok.Builder;
import lombok.Data;

import java.math.BigInteger;

/**
 * DTO for provider stake information from the Diamond contract
 */
@Data
@Builder
public class StakeInfo {
    
    /** Amount of LAB tokens currently staked (6 decimals) */
    private BigInteger stakedAmount;
    
    /** Total amount of tokens slashed historically (6 decimals) */
    private BigInteger slashedAmount;
    
    /** Timestamp of the last reservation (Unix seconds) */
    private long lastReservationTimestamp;
    
    /** Timestamp when tokens can be unstaked (Unix seconds) */
    private long unlockTimestamp;
    
    /** Whether the provider can currently unstake */
    private boolean canUnstake;
    
    /**
     * Returns an empty StakeInfo with zero values
     */
    public static StakeInfo empty() {
        return StakeInfo.builder()
            .stakedAmount(BigInteger.ZERO)
            .slashedAmount(BigInteger.ZERO)
            .lastReservationTimestamp(0)
            .unlockTimestamp(0)
            .canUnstake(false)
            .build();
    }
    
    /**
     * Format staked amount as tokens (divide by 1e6)
     */
    public String getStakedAmountFormatted() {
        if (stakedAmount == null || stakedAmount.equals(BigInteger.ZERO)) {
            return "0";
        }
        return new java.math.BigDecimal(stakedAmount)
            .divide(java.math.BigDecimal.valueOf(1_000_000))
            .stripTrailingZeros()
            .toPlainString();
    }
}
