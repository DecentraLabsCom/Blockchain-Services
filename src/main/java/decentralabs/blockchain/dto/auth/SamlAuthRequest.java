package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

/**
 * Request DTO for SAML-based authentication with assertion forwarding
 */
@Getter
@Setter
public class SamlAuthRequest {
    private String marketplaceToken;   // JWT signed by marketplace (for request validation)
    private String samlAssertion;      // SAML assertion from IdP (base64 encoded XML)
    private String labId;              // Lab ID - required if reservationKey not provided
    private String reservationKey;     // Optional - more efficient if provided (bytes32 as hex string)
    private long timestamp;            // Timestamp to prevent replay attacks
}

