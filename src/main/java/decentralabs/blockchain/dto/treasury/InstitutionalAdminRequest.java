package decentralabs.blockchain.dto.treasury;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Request DTO for institutional treasury administrative operations
 * Secured by localhost access and wallet ownership validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class InstitutionalAdminRequest {
    // Wallet address of the administrator (must match configured institutional wallet)
    private String adminWalletAddress;

    // Administrative operation type
    private AdminOperation operation;

    // Operation parameters
    private String providerAddress; // Target provider for admin operations
    private String backendAddress;  // For backend authorization operations
    private String spendingLimit;   // For limit setting operations
    private String spendingPeriod;  // For period setting operations
    private String amount;          // For deposit/withdraw operations

    public enum AdminOperation {
        AUTHORIZE_BACKEND,
        REVOKE_BACKEND,
        ADMIN_RESET_BACKEND,
        SET_USER_LIMIT,
        SET_SPENDING_PERIOD,
        RESET_SPENDING_PERIOD,
        DEPOSIT_TREASURY,
        WITHDRAW_TREASURY
    }
}
