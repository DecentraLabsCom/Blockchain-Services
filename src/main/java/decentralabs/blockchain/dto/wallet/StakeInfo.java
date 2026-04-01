package decentralabs.blockchain.dto.wallet;

import decentralabs.blockchain.util.CreditUnitConverter;
import lombok.Builder;
import lombok.Data;

import java.math.BigInteger;

/**
 * DTO for provider bond information from the Diamond contract
 */
@Data
@Builder
public class StakeInfo {
    
    /** Amount of service credits currently bonded (5 decimals) */
    private BigInteger stakedAmount;
    
    /** Total amount of credits slashed historically (5 decimals) */
    private BigInteger slashedAmount;
    
    /** Timestamp of the last reservation (Unix seconds) */
    private long lastReservationTimestamp;
    
    /** Timestamp when credits can be released (Unix seconds) */
    private long unlockTimestamp;
    
    /** Whether the provider can currently release their bond */
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
     * Format bonded amount as credits using the canonical raw-credit scale.
     */
    public String getStakedAmountFormatted() {
        if (stakedAmount == null || stakedAmount.equals(BigInteger.ZERO)) {
            return "0";
        }
        return CreditUnitConverter.formatRawCredits(stakedAmount);
    }
}
