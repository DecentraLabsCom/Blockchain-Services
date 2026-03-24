package decentralabs.blockchain.dto.billing;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Request DTO for institutional billing administrative operations
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

    // EIP-712 signature payload (timestamp in epoch millis)
    private Long timestamp;
    private String signature;

    // Operation parameters
    private String providerAddress; // Target provider for admin operations
    private String backendAddress;  // For backend authorization operations
    private String spendingLimit;   // For limit setting operations
    private String spendingPeriod;  // For period setting operations
    private String amount;          // For deposit/withdraw operations
    private String labId;           // For collect operations
    private String maxBatch;        // For collect operations
    private String creditAccount;   // Target account for service credit operations
    private String creditDelta;     // Signed delta for service credit adjustment operations
    private String reference;       // External reference for funding/adjustment traceability
    private String fromReceivableState; // Provider receivable lifecycle source state
    private String toReceivableState;   // Provider receivable lifecycle target state

    public enum AdminOperation {
        AUTHORIZE_BACKEND,
        REVOKE_BACKEND,
        ADMIN_RESET_BACKEND,
        SET_USER_LIMIT,
        SET_SPENDING_PERIOD,
        RESET_SPENDING_PERIOD,
        ISSUE_SERVICE_CREDITS,
        ADJUST_SERVICE_CREDITS,
        TRANSITION_PROVIDER_RECEIVABLE_STATE,
        COLLECT_LAB_PAYOUT
    }
}
