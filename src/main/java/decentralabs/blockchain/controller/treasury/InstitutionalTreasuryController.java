package decentralabs.blockchain.controller.treasury;

import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.dto.treasury.InstitutionalReservationRequest;
import decentralabs.blockchain.service.treasury.InstitutionalAdminService;
import decentralabs.blockchain.service.treasury.InstitutionalReservationService;
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

    private final InstitutionalReservationService reservationService;
    private final InstitutionalAdminService adminService;

    /**
     * POST /treasury/reservations
     * Processes an institutional reservation request with 3-layer auth.
     */
    @PostMapping("/reservations")
    public ResponseEntity<?> createInstitutionalReservation(
        @RequestBody InstitutionalReservationRequest request
    ) {
        try {
            return ResponseEntity.ok(reservationService.processReservation(request));
        } catch (Exception e) {
            log.error("Institutional reservation failed: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                .body(java.util.Map.of("success", false, "error", e.getMessage()));
        }
    }

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
}
