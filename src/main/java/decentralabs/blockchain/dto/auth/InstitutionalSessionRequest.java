package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InstitutionalSessionRequest {
    @NotBlank
    private String samlAssertion;

    private String stableUserIdMode;
}
