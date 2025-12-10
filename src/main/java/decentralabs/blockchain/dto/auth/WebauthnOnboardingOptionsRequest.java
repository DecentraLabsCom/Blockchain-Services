package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request to start a WebAuthn onboarding ceremony.
 * The SP sends this after validating the federated assertion.
 */
@Data
public class WebauthnOnboardingOptionsRequest {

    /**
     * Stable user identifier from the federated assertion (e.g., NameID, uid).
     * This is the PUC (Principal User Claim) that binds the user to their signing key.
     */
    @NotBlank(message = "stableUserId is required")
    private String stableUserId;

    /**
     * Institution identifier from the federated assertion (e.g., schacHomeOrganization).
     */
    @NotBlank(message = "institutionId is required")
    private String institutionId;

    /**
     * User display name for the WebAuthn credential.
     */
    private String displayName;

    /**
     * Optional: Base64-encoded SAML assertion for cryptographic validation.
     * If provided, the WIB will validate the assertion signature against the IdP.
     * This strengthens the binding between federated identity and WebAuthn credential.
     */
    private String samlAssertion;

    /**
     * Optional cryptographic reference to the federated assertion.
     * Can be a hash or signature of the assertion for audit purposes.
     * Used when samlAssertion is not provided directly.
     */
    private String assertionReference;

    /**
     * Optional attributes from the federated assertion.
     * JSON-encoded string with relevant user attributes.
     */
    private String attributes;

    /**
     * Optional callback URL for the SP to receive onboarding result notifications.
     * If provided, the WIB will POST the result to this URL when onboarding completes.
     */
    private String callbackUrl;
}
