package decentralabs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BalanceResponse {
    private boolean success;
    private String address;
    private String balanceWei;
    private String balanceEth;
    private String network;
    private String error;

    public static BalanceResponse error(String error) {
        return BalanceResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}