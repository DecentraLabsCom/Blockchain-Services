package decentralabs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkInfo {
    private String id;
    private String name;
    private String rpcUrl;
    private int chainId;
}