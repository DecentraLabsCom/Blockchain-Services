package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InstitutionalCheckInRequest {
    private String marketplaceToken;
    private String samlAssertion;
    private String reservationKey;
    private String labId;
    private String institutionalProviderWallet;
    private String puc;
}
