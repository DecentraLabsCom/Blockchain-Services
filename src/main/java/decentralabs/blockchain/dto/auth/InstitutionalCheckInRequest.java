package decentralabs.blockchain.dto.auth;

import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InstitutionalCheckInRequest {
    private String marketplaceToken;
    private String samlAssertion;
    private String reservationKey;
    private String labId;
    private String payerInstitutionWallet;
    private String puc;
    private Integer delegationHop;
    private List<String> delegationTrace;
}
