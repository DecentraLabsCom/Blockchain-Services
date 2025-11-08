package decentralabs.blockchain.dto.treasury;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Response DTO for institutional treasury administrative operations
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class InstitutionalAdminResponse {
    private boolean success;
    private String message;
    private String transactionHash;
    private String operationType;

    // Additional data for specific operations
    private String treasuryBalance;
    private String userLimit;
    private String spendingPeriod;
    private String authorizedBackend;

    public static InstitutionalAdminResponse success(String message, String txHash, String operationType) {
        return new InstitutionalAdminResponse(true, message, txHash, operationType, null, null, null, null);
    }

    public InstitutionalAdminResponse withUserLimit(String userLimit) {
        this.userLimit = userLimit;
        return this;
    }

    public InstitutionalAdminResponse withSpendingPeriod(String spendingPeriod) {
        this.spendingPeriod = spendingPeriod;
        return this;
    }

    public static InstitutionalAdminResponse error(String message) {
        return new InstitutionalAdminResponse(false, message, null, null, null, null, null, null);
    }
}
