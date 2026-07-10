package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProviderAccessCredentialRequest {
    private String marketplaceToken;
    private String reservationKey;
    private String labId;
    /**
     * Transaction submitted by the consumer backend. It is informational: the
     * provider always authorizes access from the reservation state on-chain.
     */
    private String accessAuthorizationTxHash;
}
