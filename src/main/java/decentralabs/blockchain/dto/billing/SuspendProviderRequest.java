package decentralabs.blockchain.dto.billing;

import lombok.Data;

@Data
public class SuspendProviderRequest {
    private String reason;
    private String actionBy;
}
