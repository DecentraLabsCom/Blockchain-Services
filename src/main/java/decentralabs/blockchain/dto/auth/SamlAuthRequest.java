package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

/** Request DTO for combined institutional check-in and provider access delivery. */
@Getter
@Setter
public class SamlAuthRequest {
    private String marketplaceToken;   // JWT signed by marketplace (for request validation)
    /** Backend-issued credential created during the fresh SAML login callback. */
    private String institutionalSessionToken;
    private String labId;              // Lab ID - required if reservationKey not provided
    private String reservationKey;     // Optional - more efficient if provided (bytes32 as hex string)
    private long timestamp;            // Timestamp to prevent replay attacks
}

