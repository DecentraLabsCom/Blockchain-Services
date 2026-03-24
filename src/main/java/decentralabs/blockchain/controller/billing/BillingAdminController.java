package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.billing.InstitutionalAdminResponse;
import decentralabs.blockchain.service.billing.InstitutionalAdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Billing admin controller that isolates high-privilege institutional operations
 * (reservations with triple validation + administrative functions).
 */
@RestController
@RequestMapping("/billing")
@RequiredArgsConstructor
@Slf4j
public class BillingAdminController {

    private final InstitutionalAdminService adminService;

    /**
     * POST /billing/admin/execute
     * Wraps administrative contract operations with localhost+wallet checks.
     */
    @PostMapping("/admin/execute")
    public ResponseEntity<InstitutionalAdminResponse> executeAdminOperation(
        @RequestBody InstitutionalAdminRequest request
    ) {
        log.info("Received institutional admin request: {}", request.getOperation());
        try {
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);
            if (response.isSuccess()) {
                log.info("Admin operation {} completed successfully. Tx: {}",
                    request.getOperation(), response.getTransactionHash());
                return ResponseEntity.ok(response);
            }
            log.warn("Admin operation {} failed: {}", request.getOperation(), response.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Error processing admin request: {}", e.getMessage(), e);
            InstitutionalAdminResponse errorResponse =
                InstitutionalAdminResponse.error("Internal server error: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * POST /billing/admin/request-provider-payout
     * Executes a provider payout request server-side using the configured institutional wallet.
     */
    @PostMapping("/admin/request-provider-payout")
    public ResponseEntity<InstitutionalAdminResponse> requestProviderPayout(
        @RequestBody InstitutionalAdminRequest request
    ) {
        log.info("Received server-side provider payout request for lab {}", request.getLabId());
        try {
            InstitutionalAdminResponse response = adminService.requestProviderPayoutWithConfiguredWallet(
                request.getLabId(),
                request.getMaxBatch()
            );
            if (response.isSuccess()) {
                log.info("Server-side provider payout request completed. Tx: {}", response.getTransactionHash());
                return ResponseEntity.ok(response);
            }
            log.warn("Server-side provider payout request failed: {}", response.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Error processing provider payout request: {}", e.getMessage(), e);
            InstitutionalAdminResponse errorResponse =
                InstitutionalAdminResponse.error("Internal server error: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }
}
