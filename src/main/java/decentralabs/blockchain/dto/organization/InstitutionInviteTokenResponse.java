package decentralabs.blockchain.dto.organization;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InstitutionInviteTokenResponse {
    @Getter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class DomainResult {
        private final String organization;
        private final String transactionHash;
        private final String error;
    }

    private final boolean success;
    private final String walletAddress;
    private final List<String> organizations;
    private final List<DomainResult> domains;
    private final String message;
    private final String inviteId;
}
