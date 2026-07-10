package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccessCodeRedeemRequest {
    private String accessCode;
}
