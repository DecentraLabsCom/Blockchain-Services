package decentralabs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignTransactionRequest {
    private String encryptedPrivateKey;
    private String password;
    private String to;
    private String value; // in ETH
    private String gasPrice; // optional
    private String gasLimit; // optional
    private String nonce; // optional
}