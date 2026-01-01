package decentralabs.blockchain.dto.auth;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response containing the WebAuthn credential creation options.
 * This follows the W3C WebAuthn specification for PublicKeyCredentialCreationOptions.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebauthnOnboardingOptionsResponse {

    /**
     * Session ID to correlate the ceremony completion with this challenge.
     */
    private String sessionId;

    /**
     * URL where the SP should redirect the browser to perform the WebAuthn ceremony.
     * The IB serves the ceremony page at this URL, acting as the WebAuthn Relying Party.
     * Example: https://backend.institution.edu/onboarding/webauthn/ceremony/{sessionId}
     */
    private String onboardingUrl;

    /**
     * Base64url-encoded challenge bytes. The authenticator signs this.
     */
    private String challenge;

    /**
     * Relying Party information.
     */
    private RelyingParty rp;

    /**
     * User information for credential creation.
     */
    private User user;

    /**
     * Supported public key credential parameters.
     */
    private List<PubKeyCredParam> pubKeyCredParams;

    /**
     * Timeout for the ceremony in milliseconds.
     */
    private Long timeout;

    /**
     * Attestation preference: "none", "indirect", or "direct".
     */
    private String attestation;

    /**
     * Authenticator selection criteria.
     */
    private AuthenticatorSelection authenticatorSelection;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RelyingParty {
        private String id;
        private String name;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class User {
        /**
         * Base64url-encoded user handle (opaque identifier).
         */
        private String id;
        private String name;
        private String displayName;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PubKeyCredParam {
        /**
         * Type is always "public-key".
         */
        private String type;
        /**
         * COSE algorithm identifier: -7 (ES256), -257 (RS256), -8 (EdDSA).
         */
        private int alg;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthenticatorSelection {
        /**
         * "platform" or "cross-platform".
         */
        private String authenticatorAttachment;
        /**
         * "required", "preferred", or "discouraged".
         */
        private String residentKey;
        /**
         * Whether discoverable credential (resident key) is required.
         */
        private boolean requireResidentKey;
        /**
         * "required", "preferred", or "discouraged".
         */
        private String userVerification;
    }
}
