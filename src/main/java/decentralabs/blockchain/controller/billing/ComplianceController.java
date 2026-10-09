package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.service.billing.ComplianceExportService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST endpoints for compliance reporting and accounting exports.
 * Secured by localhost-only access.
 */
@RestController
@RequestMapping("/billing/compliance")
@RequiredArgsConstructor
@Slf4j
public class ComplianceController {

    private final ComplianceExportService exportService;

    @GetMapping("/mica-volume")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageProviderNetwork()")
    public ResponseEntity<?> getMicaVolume() {
        return ResponseEntity.ok(Map.of(
                "rolling12MonthEurVolume", exportService.exportRolling12MonthVolume(),
                "history", exportService.exportMicaVolumeHistory(12)
        ));
    }

    @GetMapping("/exports/prepaid-balances")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageInstitutionPolicies()")
    public ResponseEntity<?> exportPrepaidBalances(@RequestParam String address) {
        try {
            EthereumAddressValidator.validate(address, "address");
            return ResponseEntity.ok(exportService.exportPrepaidBalancesByLot(address));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/exports/consumed")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageInstitutionPolicies()")
    public ResponseEntity<?> exportConsumed(
            @RequestParam String address,
            @RequestParam(defaultValue = "1000") int limit) {
        try {
            EthereumAddressValidator.validate(address, "address");
            return ResponseEntity.ok(exportService.exportConsumedByPeriod(address, Math.min(limit, 10000)));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/exports/expired")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageInstitutionPolicies()")
    public ResponseEntity<?> exportExpired(@RequestParam String address) {
        try {
            EthereumAddressValidator.validate(address, "address");
            return ResponseEntity.ok(exportService.exportExpiredLots(address));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/exports/receivable-accruals")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageProviderNetwork()")
    public ResponseEntity<?> exportReceivableAccruals() {
        return ResponseEntity.ok(exportService.exportProviderReceivableAccruals());
    }

    @GetMapping("/exports/completed-payouts")
    @PreAuthorize("@walletDashboardAuthorizationService.canReadProviderPayouts(#p0)")
    public ResponseEntity<?> exportCompletedPayouts(@RequestParam String providerAddress) {
        try {
            EthereumAddressValidator.validate(providerAddress, "providerAddress");
            return ResponseEntity.ok(exportService.exportCompletedPayouts(providerAddress));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/exports/provider-network")
    @PreAuthorize("@walletDashboardAuthorizationService.canManageProviderNetwork()")
    public ResponseEntity<?> exportProviderNetwork() {
        return ResponseEntity.ok(exportService.exportProviderNetworkSnapshot());
    }
}
