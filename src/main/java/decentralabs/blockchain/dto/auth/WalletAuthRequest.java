package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

/**
 * Request DTO for wallet-based authentication
 */
@Getter
@Setter
public class WalletAuthRequest {
    private String wallet;
    private String signature;
    private String labId;              // Lab ID - required if reservationKey not provided
    private String reservationKey;     // Optional - more efficient if provided (bytes32 as hex string)
}

