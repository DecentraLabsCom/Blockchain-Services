package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.billing.FundingOrderService;
import decentralabs.blockchain.service.billing.CreditProjectionService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * REST endpoints for the funding order lifecycle and credit account projections.
 * Secured by localhost-only access (same as existing billing admin).
 */
@RestController
@RequestMapping("/billing")
@RequiredArgsConstructor
@Slf4j
public class FundingController {

    private final FundingOrderService fundingOrderService;
    private final CreditProjectionService creditProjectionService;

    // ── Funding Orders ──────────────────────────────────────────────────

    @PostMapping("/funding-orders")
    public ResponseEntity<?> createFundingOrder(@RequestBody Map<String, Object> body) {
        try {
            String institution = extractString(body, "institutionAddress");
            EthereumAddressValidator.validate(institution, "institutionAddress");
            BigDecimal eurAmount = extractDecimal(body, "eurGrossAmount");
            BigDecimal creditAmount = extractDecimal(body, "creditAmount");
            String reference = (String) body.get("reference");
            Instant expiresAt = body.containsKey("expiresAt") ? Instant.parse((String) body.get("expiresAt")) : null;

            FundingOrder order = fundingOrderService.createFundingOrder(
                    institution, eurAmount, creditAmount, reference, expiresAt);
            return ResponseEntity.ok(order);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/funding-orders")
    public ResponseEntity<?> listFundingOrders(
            @RequestParam(required = false) String institution,
            @RequestParam(required = false) String status) {
        try {
            if (status != null) {
                FundingOrder.Status s = FundingOrder.Status.valueOf(status.toUpperCase());
                return ResponseEntity.ok(fundingOrderService.findByStatus(s));
            }
            if (institution != null) {
                EthereumAddressValidator.validate(institution, "institution");
                return ResponseEntity.ok(fundingOrderService.findByInstitution(institution));
            }
            // Default: pending orders
            return ResponseEntity.ok(fundingOrderService.findByStatus(FundingOrder.Status.DRAFT));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/funding-orders/{id}")
    public ResponseEntity<?> getFundingOrder(@PathVariable long id) {
        return fundingOrderService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/funding-orders/{id}/invoice")
    public ResponseEntity<?> issueInvoice(@PathVariable long id, @RequestBody Map<String, Object> body) {
        try {
            String invoiceNumber = extractString(body, "invoiceNumber");
            Instant dueAt = body.containsKey("dueAt") ? Instant.parse((String) body.get("dueAt")) : null;
            FundingInvoice invoice = fundingOrderService.issueInvoice(id, invoiceNumber, dueAt);
            return ResponseEntity.ok(invoice);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/funding-orders/{id}/confirm-payment")
    public ResponseEntity<?> confirmPayment(@PathVariable long id, @RequestBody Map<String, Object> body) {
        try {
            String paymentRef = extractString(body, "paymentRef");
            BigDecimal eurAmount = extractDecimal(body, "eurAmount");
            String paymentMethod = (String) body.get("paymentMethod");
            PaymentReconciliation recon = fundingOrderService.confirmPayment(id, paymentRef, eurAmount, paymentMethod);
            return ResponseEntity.ok(recon);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/funding-orders/{id}/cancel")
    public ResponseEntity<?> cancelFundingOrder(@PathVariable long id) {
        try {
            fundingOrderService.cancelFundingOrder(id);
            return ResponseEntity.ok(Map.of("status", "CANCELLED"));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/funding-orders/{id}/mark-credited")
    public ResponseEntity<?> markCredited(@PathVariable long id) {
        try {
            fundingOrderService.markCredited(id);
            return ResponseEntity.ok(Map.of("status", "CREDITED"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ── Credit Account Projections ──────────────────────────────────────

    @GetMapping("/credit-accounts/{address}")
    public ResponseEntity<?> getCreditAccount(@PathVariable String address) {
        try {
            EthereumAddressValidator.validate(address, "address");
            return creditProjectionService.getAccount(address)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/credit-accounts/{address}/lots")
    public ResponseEntity<?> getCreditLots(@PathVariable String address) {
        try {
            EthereumAddressValidator.validate(address, "address");
            return ResponseEntity.ok(creditProjectionService.getLots(address));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/credit-accounts/{address}/movements")
    public ResponseEntity<?> getCreditMovements(
            @PathVariable String address,
            @RequestParam(defaultValue = "100") int limit) {
        try {
            EthereumAddressValidator.validate(address, "address");
            int safeLimit = Math.min(Math.max(limit, 1), 1000);
            return ResponseEntity.ok(creditProjectionService.getMovements(address, safeLimit));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private String extractString(Map<String, Object> body, String key) {
        Object val = body.get(key);
        if (val == null || val.toString().isBlank()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return val.toString().trim();
    }

    private BigDecimal extractDecimal(Map<String, Object> body, String key) {
        Object val = body.get(key);
        if (val == null) {
            throw new IllegalArgumentException(key + " is required");
        }
        try {
            return new BigDecimal(val.toString());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(key + " must be a valid decimal number");
        }
    }
}
