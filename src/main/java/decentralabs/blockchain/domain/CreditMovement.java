package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Audit trail entry for credit balance changes.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreditMovement {

    public enum Type { MINT, LOCK, CAPTURE, RELEASE, CANCEL, ADJUST, EXPIRE }

    private Long id;
    private String accountAddress;
    private Integer lotIndex;
    private Type movementType;
    private BigDecimal amount;
    private String reservationRef;
    private String reference;
    /** Stable source identifier used to make on-chain reconciliation idempotent. */
    private String sourceKey;
    private Instant createdAt;
}
