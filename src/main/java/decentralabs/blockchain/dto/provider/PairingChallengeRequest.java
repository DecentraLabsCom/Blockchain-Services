package decentralabs.blockchain.dto.provider;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** User-supplied pairing challenge; wallet and backend values are server-side only. */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PairingChallengeRequest {
    @NotBlank(message = "Pairing challenge is required")
    private String challenge;
}
