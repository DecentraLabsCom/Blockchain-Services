package decentralabs.blockchain.controller.treasury;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.service.treasury.InstitutionalAdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Treasury controller that isolates high-privilege institutional operations
 * (reservations with triple validation + administrative functions).
 */
@RestController
@RequestMapping("/treasury")
@RequiredArgsConstructor
@Slf4j
public class InstitutionalTreasuryController {

    private final InstitutionalAdminService adminService;

    /**
     * POST /treasury/admin/execute
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
     * POST /treasury/admin/collect-lab-payout
     * Executes collect payout server-side using the configured institutional wallet.
     */
    @PostMapping("/admin/collect-lab-payout")
    public ResponseEntity<InstitutionalAdminResponse> collectLabPayout(
        @RequestBody InstitutionalAdminRequest request
    ) {
        log.info("Received server-side collect payout request for lab {}", request.getLabId());
        try {
            InstitutionalAdminResponse response = adminService.collectLabPayoutWithConfiguredWallet(
                request.getLabId(),
                request.getMaxBatch()
            );
            if (response.isSuccess()) {
                log.info("Server-side collect payout completed. Tx: {}", response.getTransactionHash());
                return ResponseEntity.ok(response);
            }
            log.warn("Server-side collect payout failed: {}", response.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            log.error("Error processing collect payout request: {}", e.getMessage(), e);
            InstitutionalAdminResponse errorResponse =
                InstitutionalAdminResponse.error("Internal server error: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }
}
