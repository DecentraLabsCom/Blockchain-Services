package decentralabs.blockchain.dto.auth;

import lombok.Getter;
import lombok.Setter;

/** Authenticated status lookup used by provider-only retries after delegated check-in. */
@Getter
@Setter
public class InstitutionalCheckInStatusRequest {
    private String marketplaceToken;
    private String reservationKey;
    private String labId;
}
