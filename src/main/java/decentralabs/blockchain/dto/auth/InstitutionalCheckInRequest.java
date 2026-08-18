package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InstitutionalCheckInRequest {
    private String marketplaceToken;
    /** Backend-issued credential created during the fresh SAML login callback. */
    private String institutionalSessionToken;
    private String reservationKey;
    private String labId;
    private String payerInstitutionWallet;
    private String puc;
}
