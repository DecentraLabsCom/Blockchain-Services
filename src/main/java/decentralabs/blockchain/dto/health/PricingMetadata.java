package decentralabs.blockchain.dto.health;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PricingMetadata {
    private String displayAmount;
    private String displayUnit;
    private String rawPricePerSecond;
    private String roundingMode;
    private String billingMode;
}
