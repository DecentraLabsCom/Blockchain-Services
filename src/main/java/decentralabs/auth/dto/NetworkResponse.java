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
public class NetworkResponse {
    private boolean success;
    private List<NetworkInfo> networks;
    private String activeNetwork;
    private String error;

    public static NetworkResponse error(String error) {
        return NetworkResponse.builder()
            .success(false)
            .error(error)
            .build();
    }
}