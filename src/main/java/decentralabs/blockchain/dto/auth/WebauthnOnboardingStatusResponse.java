package decentralabs.blockchain.dto.auth;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for checking the status of an onboarding session.
 * The SP can poll this endpoint to know the result without needing a callback.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebauthnOnboardingStatusResponse {

    /**
     * Status of the onboarding session.
     * Values: "PENDING", "SUCCESS", "FAILED"
     */
    private String status;

    /**
     * The stable user ID for this session.
     */
    private String stableUserId;

    /**
     * The institution ID for this session.
     */
    private String institutionId;

    /**
     * The credential ID if onboarding completed successfully.
     */
    private String credentialId;

    /**
     * The credential public key (COSE, base64url-encoded).
     */
    private String publicKey;

    /**
     * RP ID used for the credential.
     */
    private String rpId;

    /**
     * Error message if onboarding failed.
     */
    private String error;

    /**
     * Timestamp when onboarding completed (if applicable).
     */
    private Instant completedAt;
}
