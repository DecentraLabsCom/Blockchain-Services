package decentralabs.blockchain.dto.intent;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Status response for an intent WebAuthn authorization session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IntentAuthorizationStatusResponse {
    private String sessionId;
    private String requestId;
    private String status;
    private String error;
    private Instant completedAt;
}
