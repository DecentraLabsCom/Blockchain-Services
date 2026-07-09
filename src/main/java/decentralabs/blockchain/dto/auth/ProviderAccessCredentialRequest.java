package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProviderAccessCredentialRequest {
    private String marketplaceToken;
    private String reservationKey;
    private String labId;
}
