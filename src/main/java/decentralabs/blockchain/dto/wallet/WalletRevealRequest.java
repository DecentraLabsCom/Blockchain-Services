package decentralabs.blockchain.dto.wallet;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class WalletRevealRequest {

    @NotBlank(message = "Password is required to reveal the private key")
    private String password;
}
