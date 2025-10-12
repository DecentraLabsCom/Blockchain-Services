package decentralabs.auth.dto;

import lombok.Getter;

/**
 * Request DTO for SAML-based authentication with assertion forwarding
 */
@Getter
public class SamlAuthRequest {
    private String marketplaceToken;   // JWT signed by marketplace (for request validation)
    private String samlAssertion;      // SAML assertion from IdP (base64 encoded XML)
    private String labId;              // Lab ID - required if reservationKey not provided
    private String reservationKey;     // Optional - more efficient if provided (bytes32 as hex string)
    private long timestamp;            // Timestamp to prevent replay attacks
}
