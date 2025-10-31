package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignMessageResponse {
    private boolean success;
    private String address;
    private String message;
    private String signature;
    private String error;

    public static SignMessageResponse error(String error) {
        return SignMessageResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}