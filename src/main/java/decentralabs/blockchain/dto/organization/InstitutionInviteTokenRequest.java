package decentralabs.blockchain.dto.organization;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InstitutionInviteTokenRequest {

    @NotBlank
    private String token;

    /**
     * Wallet address that should be registered. If empty, the server will
     * try to use the configured institutional wallet.
     */
    private String walletAddress;
}
