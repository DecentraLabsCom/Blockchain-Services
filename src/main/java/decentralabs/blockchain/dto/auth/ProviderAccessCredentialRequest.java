package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProviderAccessCredentialRequest {
    private String marketplaceToken;
    /**
     * Marketplace JWT minted for the consumer backend audience. It is used
     * only when the provider must query the consumer's remote check-in state.
     */
    private String consumerMarketplaceToken;
    private String reservationKey;
    private String labId;
    /**
     * Transaction submitted by the consumer backend. It is informational: the
     * provider always authorizes access from the reservation state on-chain.
     */
    private String accessAuthorizationTxHash;
}
