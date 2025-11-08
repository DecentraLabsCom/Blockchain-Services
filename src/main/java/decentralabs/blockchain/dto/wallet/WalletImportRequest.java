package decentralabs.blockchain.dto.wallet;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WalletImportRequest {
    
    @Pattern(regexp = "^0x[0-9a-fA-F]{64}$", message = "Private key must be a valid hex string with 0x prefix (66 characters)")
    private String privateKey;
    
    private String mnemonic;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    private String password;
}
