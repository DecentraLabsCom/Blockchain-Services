package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.domain.*;
import decentralabs.blockchain.service.billing.ProviderNetworkService;
import decentralabs.blockchain.service.billing.ProviderSettlementService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

/**
 * REST endpoints for provider network registry and provider settlement lifecycle.
 * Secured by localhost-only access.
 */
@RestController
@RequestMapping("/billing")
@RequiredArgsConstructor
@Slf4j
public class ProviderBillingController {

    private final ProviderNetworkService providerNetworkService;
    private final ProviderSettlementService providerSettlementService;

    // ── Provider Network ────────────────────────────────────────────────

    @GetMapping("/provider-network")
    public ResponseEntity<?> listProviderNetwork(@RequestParam(required = false) String status) {
        if ("all".equalsIgnoreCase(status)) {
            return ResponseEntity.ok(providerNetworkService.findAll());
        }
        return ResponseEntity.ok(providerNetworkService.findAllActive());
    }

    @PostMapping("/provider-network")
    public ResponseEntity<?> activateProvider(@RequestBody Map<String, Object> body) {
        try {
            String provider = extractString(body, "providerAddress");
            EthereumAddressValidator.validate(provider, "providerAddress");
            String contractId = extractString(body, "contractId");
            String agreementVersion = extractString(body, "agreementVersion");
            String activatedBy = (String) body.get("activatedBy");
            LocalDate effective = body.containsKey("effectiveDate")
                    ? LocalDate.parse(body.get("effectiveDate").toString()) : null;
            LocalDate expiry = body.containsKey("expiryDate")
                    ? LocalDate.parse(body.get("expiryDate").toString()) : null;

            ProviderNetworkMembership m = providerNetworkService.activate(
                    provider, contractId, agreementVersion, effective, expiry, activatedBy);
            return ResponseEntity.ok(m);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/provider-network/{id}/suspend")
    public ResponseEntity<?> suspendProvider(@PathVariable long id, @RequestBody Map<String, Object> body) {
        String reason = (String) body.get("reason");
        String actionBy = (String) body.get("actionBy");
        providerNetworkService.suspend(id, reason, actionBy);
        return ResponseEntity.ok(Map.of("status", "SUSPENDED"));
    }

    @PostMapping("/provider-network/{id}/terminate")
    public ResponseEntity<?> terminateProvider(@PathVariable long id, @RequestBody(required = false) Map<String, Object> body) {
        String actionBy = body != null ? (String) body.get("actionBy") : null;
        providerNetworkService.terminate(id, actionBy);
        return ResponseEntity.ok(Map.of("status", "TERMINATED"));
    }

    // ── Provider Settlement ─────────────────────────────────────────────

    @GetMapping("/provider-receivables")
    public ResponseEntity<?> listProviderInvoices(@RequestParam(required = false) String status) {
        if (status != null) {
            ProviderInvoiceRecord.Status s = ProviderInvoiceRecord.Status.valueOf(status.toUpperCase());
            return ResponseEntity.ok(providerSettlementService.findInvoicesByStatus(s));
        }
        return ResponseEntity.ok(providerSettlementService.findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED));
    }

    @PostMapping("/provider-receivables/{labId}/invoice")
    public ResponseEntity<?> submitProviderInvoice(@PathVariable String labId, @RequestBody Map<String, Object> body) {
        try {
            String provider = extractString(body, "providerAddress");
            EthereumAddressValidator.validate(provider, "providerAddress");
            String invoiceRef = extractString(body, "invoiceRef");
            BigDecimal eurAmount = extractDecimal(body, "eurAmount");
            BigDecimal creditAmount = body.containsKey("creditAmount")
                    ? extractDecimal(body, "creditAmount") : null;

            ProviderInvoiceRecord record = providerSettlementService.submitInvoice(
                    labId, provider, invoiceRef, eurAmount, creditAmount);
            return ResponseEntity.ok(record);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/provider-receivables/invoices/{invoiceId}/approve")
    public ResponseEntity<?> approveInvoice(@PathVariable long invoiceId, @RequestBody Map<String, Object> body) {
        try {
            String approvedBy = extractString(body, "approvedBy");
            EthereumAddressValidator.validate(approvedBy, "approvedBy");
            String approvalRef = (String) body.get("approvalRef");
            BigDecimal eurAmount = extractDecimal(body, "eurAmount");

            ProviderApproval approval = providerSettlementService.approveInvoice(invoiceId, approvedBy, approvalRef, eurAmount);
            return ResponseEntity.ok(approval);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/provider-receivables/{labId}/pay")
    public ResponseEntity<?> recordPayout(@PathVariable String labId, @RequestBody Map<String, Object> body) {
        try {
            String provider = extractString(body, "providerAddress");
            EthereumAddressValidator.validate(provider, "providerAddress");
            BigDecimal eurAmount = extractDecimal(body, "eurAmount");
            BigDecimal creditAmount = body.containsKey("creditAmount")
                    ? extractDecimal(body, "creditAmount") : BigDecimal.ZERO;
            String bankRef = (String) body.get("bankRef");
            String eurcTxHash = (String) body.get("eurcTxHash");
            String usdcTxHash = (String) body.get("usdcTxHash");

            ProviderPayout payout = providerSettlementService.recordPayout(
                    labId, provider, eurAmount, creditAmount, bankRef, eurcTxHash, usdcTxHash);
            return ResponseEntity.ok(payout);
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
