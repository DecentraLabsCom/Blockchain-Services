package decentralabs.blockchain.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request to complete a WebAuthn onboarding ceremony.
 * Contains the attestation response from the authenticator.
 */
@Data
public class WebauthnOnboardingCompleteRequest {

    /**
     * Session ID from the options response.
     */
    @NotBlank(message = "sessionId is required")
    private String sessionId;

    /**
     * Base64url-encoded credential ID.
     */
    @NotBlank(message = "credentialId is required")
    private String credentialId;

    /**
     * Base64url-encoded attestation object from navigator.credentials.create().
     * Contains the public key, AAGUID, and attestation statement.
     */
    @NotBlank(message = "attestationObject is required")
    private String attestationObject;

    /**
     * Base64url-encoded client data JSON.
     * Contains the challenge, origin, and type.
     */
    @NotBlank(message = "clientDataJSON is required")
    private String clientDataJSON;

    /**
     * Optional: List of supported transports (usb, nfc, ble, internal, hybrid).
     */
    private String[] transports;
}
