package decentralabs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SendTransactionResponse {
    private boolean success;
    private String transactionHash;
    private String network;
    private String error;

    public static SendTransactionResponse error(String error) {
        return SendTransactionResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}