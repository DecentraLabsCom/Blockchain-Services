package decentralabs.blockchain.dto.wallet;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WalletResponse {
    private boolean success;
    private String address;
    private String encryptedPrivateKey;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String privateKey;
    private String message;
    private String error;

    public static WalletResponse error(String error) {
        return WalletResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}
