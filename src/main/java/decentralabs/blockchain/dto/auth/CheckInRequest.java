package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

/**
 * Request DTO for EIP-712 reservation check-in
 */
@Getter
@Setter
public class CheckInRequest {
    private String reservationKey; // bytes32 hex string
    private String signer;         // address expected to sign (wallet or backend)
    private String signature;      // EIP-712 signature
    private Long timestamp;        // unix seconds
    private String puc;            // optional (institutional)
}
