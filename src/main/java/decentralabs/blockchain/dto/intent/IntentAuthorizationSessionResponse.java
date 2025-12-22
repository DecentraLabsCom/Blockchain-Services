package decentralabs.blockchain.dto.intent;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response payload for creating a WebAuthn intent authorization session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IntentAuthorizationSessionResponse {
    private String sessionId;
    private String ceremonyUrl;
    private String requestId;
    private Instant expiresAt;
}
