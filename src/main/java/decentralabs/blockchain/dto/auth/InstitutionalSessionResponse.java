package decentralabs.blockchain.dto.auth;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class InstitutionalSessionResponse {
    private String sessionToken;
    private Instant expiresAt;
    private Instant reauthenticationAt;
    private String samlAssertionHash;
}
