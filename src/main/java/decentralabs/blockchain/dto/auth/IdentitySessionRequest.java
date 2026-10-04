package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Starts a backend-owned institutional session from a provider-neutral
 * identity envelope carried by a signed Marketplace service credential.
 */
@Getter
@Setter
public class IdentitySessionRequest {

    @Size(max = 80)
    private String stableUserIdMode;

    /**
     * Raw provider token carried only over the authenticated server-to-server
     * exchange. It must never be copied to a browser session or log message.
     */
    @Size(max = 16384)
    private String externalIdToken;
}
