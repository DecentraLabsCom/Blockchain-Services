package decentralabs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionHistoryResponse {
    private boolean success;
    private String address;
    private String transactionCount;
    private List<TransactionInfo> transactions;
    private String network;
    private String error;

    public static TransactionHistoryResponse error(String error) {
        return TransactionHistoryResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}