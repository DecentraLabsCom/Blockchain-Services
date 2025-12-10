package decentralabs.blockchain.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response after completing WebAuthn onboarding (success or failure).
 * This response is sent both to the browser and optionally to the SP via callback.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebauthnOnboardingCompleteResponse {

    /**
     * Whether the onboarding was successful.
     */
    private boolean success;

    /**
     * The stable user ID that was onboarded.
     */
    private String stableUserId;

    /**
     * The institution ID associated with this onboarding.
     */
    private String institutionId;

    /**
     * The credential ID that was registered (base64url-encoded).
     */
    private String credentialId;

    /**
     * Human-readable message.
     */
    private String message;

    /**
     * Optional: AAGUID of the authenticator (for informational purposes).
     */
    private String aaguid;

    /**
     * Error code if onboarding failed.
     */
    private String errorCode;

    /**
     * Timestamp of when the onboarding was completed (epoch seconds).
     */
    private Long timestamp;
}
