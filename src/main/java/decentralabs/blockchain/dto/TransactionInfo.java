package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionInfo {
    private String hash;
    private String from;
    private String to;
    private String value;
    private String timestamp;
    private String status;
}