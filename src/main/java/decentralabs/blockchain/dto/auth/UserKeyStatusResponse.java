package decentralabs.blockchain.dto.auth;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for checking if a user has registered WebAuthn credentials.
 * Used by the SP to determine if onboarding is needed before requesting an action.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserKeyStatusResponse {

    /**
     * Whether the user has at least one active credential registered.
     */
    private boolean hasCredential;

    /**
     * Number of active credentials registered for this user.
     */
    private int credentialCount;

    /**
     * The stable user ID queried.
     */
    private String stableUserId;

    /**
     * The institution ID (if filtering by institution was applied).
     */
    private String institutionId;

    /**
     * Timestamp of the most recent credential registration.
     */
    private Instant lastRegistered;

    /**
     * Whether the user has any revoked credentials (for audit purposes).
     */
    private boolean hasRevokedCredentials;
}
