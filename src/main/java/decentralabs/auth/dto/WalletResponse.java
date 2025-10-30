package decentralabs.auth.dto;

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
    private String message;
    private String error;

    public static WalletResponse error(String error) {
        return WalletResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}