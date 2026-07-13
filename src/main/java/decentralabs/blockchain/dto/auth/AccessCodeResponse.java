package decentralabs.blockchain.dto.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccessCodeResponse {
    private final String accessCode;
    private final String labURL;
    private final String resourceType;

    public AccessCodeResponse(String accessCode, String labURL) {
        this(accessCode, labURL, null);
    }
}
