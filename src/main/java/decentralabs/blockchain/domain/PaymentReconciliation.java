package decentralabs.blockchain.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * Records a confirmed payment against a funding order.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentReconciliation {

    private Long id;
    private Long fundingOrderId;
    private String paymentRef;
    private BigDecimal eurAmount;
    private String paymentMethod;
    private Instant reconciledAt;
}
