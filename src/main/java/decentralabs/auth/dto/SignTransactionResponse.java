package decentralabs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignTransactionResponse {
    private boolean success;
    private String from;
    private String to;
    private String value;
    private String signedTransaction;
    private String error;

    public static SignTransactionResponse error(String error) {
        return SignTransactionResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}