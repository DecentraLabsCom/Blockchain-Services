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

    /**
     * Whether the user has a platform credential (e.g. Windows Hello/Touch ID).
     */
    private boolean hasPlatformCredential;

    /**
     * Whether the user has a cross-platform credential (e.g. security key).
     */
    private boolean hasCrossPlatformCredential;

    /**
     * Whether any credential is resident (discoverable).
     */
    private boolean hasResidentCredential;
}
