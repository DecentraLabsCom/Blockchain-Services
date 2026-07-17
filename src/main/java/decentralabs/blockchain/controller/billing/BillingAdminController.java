package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.billing.InstitutionalAdminResponse;
import decentralabs.blockchain.exception.IdempotencyKeyPayloadMismatchException;
import decentralabs.blockchain.util.LogSanitizer;
import java.util.Map;
import decentralabs.blockchain.service.billing.InstitutionalAdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
    public ResponseEntity<?> executeAdminOperation(
        @RequestBody InstitutionalAdminRequest request
    ) {
        String operation = request.getOperation() == null ? "unknown" : request.getOperation().name();
        log.info("Received institutional admin request: {}", operation);
        try {
            InstitutionalAdminResponse response = adminService.executeAdminOperation(request);
            if (response == null) {
                log.error("Admin service returned null response for operation {}",
                    operation);
                return ResponseEntity.internalServerError()
                    .body(InstitutionalAdminResponse.error("Internal server error: empty service response"));
            }
            if (response.isSuccess()) {
                log.info("Admin operation {} completed successfully. Tx: {}",
                    operation,
                    LogSanitizer.maskIdentifier(response.getTransactionHash()));
                return ResponseEntity.ok(response);
            }
            log.warn("Admin operation {} failed: {}", operation,
                LogSanitizer.sanitize(response.getMessage()));
            return ResponseEntity.badRequest().body(response);
        } catch (IdempotencyKeyPayloadMismatchException e) {
            return idempotencyConflict(e);
        } catch (Exception e) {
            log.error("Error processing admin request: {}", LogSanitizer.sanitize(e.getMessage()), e);
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
    public ResponseEntity<?> requestProviderPayout(
        @RequestBody InstitutionalAdminRequest request,
        @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey
    ) {
        // codeql[java/log-injection]
        log.info("Received server-side provider payout request for lab {}",
            LogSanitizer.sanitize(String.valueOf(request.getLabId())));
        try {
            InstitutionalAdminResponse response = idempotencyKey != null && !idempotencyKey.isBlank()
                ? adminService.requestProviderPayoutWithConfiguredWallet(
                    request.getLabId(), request.getMaxBatch(), idempotencyKey
                )
                : adminService.requestProviderPayoutWithConfiguredWallet(
                    request.getLabId(), request.getMaxBatch()
                );
            if (response == null) {
                // codeql[java/log-injection]
                log.error("Admin service returned null response for payout request on lab {}",
                    LogSanitizer.sanitize(String.valueOf(request.getLabId())));
                return ResponseEntity.internalServerError()
                    .body(InstitutionalAdminResponse.error("Internal server error: empty service response"));
            }
            if (response.isSuccess()) {
                log.info("Server-side provider payout request completed. Tx: {}",
                    LogSanitizer.maskIdentifier(response.getTransactionHash()));
                return ResponseEntity.ok(response);
            }
            log.warn("Server-side provider payout request failed: {}",
                LogSanitizer.sanitize(response.getMessage()));
            return ResponseEntity.badRequest().body(response);
        } catch (IdempotencyKeyPayloadMismatchException e) {
            return idempotencyConflict(e);
        } catch (Exception e) {
            log.error("Error processing provider payout request: {}", LogSanitizer.sanitize(e.getMessage()), e);
            InstitutionalAdminResponse errorResponse =
                InstitutionalAdminResponse.error("Internal server error: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @GetMapping("/admin/transaction-status")
    public ResponseEntity<?> getTransactionStatus(@RequestParam String txHash) {
        var result = adminService.getTransactionStatus(txHash);
        if (Boolean.TRUE.equals(result.get("success"))) {
            return ResponseEntity.ok(result);
        }
        return ResponseEntity.badRequest().body(result);
    }

    private ResponseEntity<Map<String, Object>> idempotencyConflict(IdempotencyKeyPayloadMismatchException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
            "success", false,
            "code", IdempotencyKeyPayloadMismatchException.CODE,
            "message", ex.getMessage(),
            "status", HttpStatus.CONFLICT.value()
        ));
    }
}
