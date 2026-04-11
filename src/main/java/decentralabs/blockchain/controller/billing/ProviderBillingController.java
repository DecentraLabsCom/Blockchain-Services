package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.domain.ProviderApproval;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderNetworkMembership;
import decentralabs.blockchain.domain.ProviderPayout;
import decentralabs.blockchain.dto.billing.ActivateProviderRequest;
import decentralabs.blockchain.dto.billing.ApproveProviderInvoiceRequest;
import decentralabs.blockchain.dto.billing.RecordProviderPayoutRequest;
import decentralabs.blockchain.dto.billing.SubmitProviderInvoiceRequest;
import decentralabs.blockchain.dto.billing.SuspendProviderRequest;
import decentralabs.blockchain.service.billing.ProviderNetworkService;
import decentralabs.blockchain.service.billing.ProviderSettlementService;
import decentralabs.blockchain.util.EthereumAddressValidator;
import jakarta.validation.Valid;
import java.math.BigDecimal;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/billing")
@RequiredArgsConstructor
@Slf4j
public class ProviderBillingController {

    private final ProviderNetworkService providerNetworkService;
    private final ProviderSettlementService providerSettlementService;

    @GetMapping("/provider-network")
    public ResponseEntity<?> listProviderNetwork(@RequestParam(required = false) String status) {
        if ("all".equalsIgnoreCase(status)) {
            return ResponseEntity.ok(providerNetworkService.findAll());
        }
        return ResponseEntity.ok(providerNetworkService.findAllActive());
    }

    @PostMapping("/provider-network")
    public ResponseEntity<ProviderNetworkMembership> activateProvider(
        @Valid @RequestBody ActivateProviderRequest request
    ) {
        EthereumAddressValidator.validate(request.getProviderAddress(), "providerAddress");
        ProviderNetworkMembership membership = providerNetworkService.activate(
            request.getProviderAddress(),
            request.getContractId(),
            request.getAgreementVersion(),
            request.getEffectiveDate(),
            request.getExpiryDate(),
            request.getActivatedBy()
        );
        return ResponseEntity.ok(membership);
    }

    @PostMapping("/provider-network/{id}/suspend")
    public ResponseEntity<Map<String, String>> suspendProvider(
        @PathVariable long id,
        @RequestBody(required = false) SuspendProviderRequest request
    ) {
        String reason = request != null ? request.getReason() : null;
        String actionBy = request != null ? request.getActionBy() : null;
        providerNetworkService.suspend(id, reason, actionBy);
        return ResponseEntity.ok(Map.of("status", "SUSPENDED"));
    }

    @PostMapping("/provider-network/{id}/terminate")
    public ResponseEntity<Map<String, String>> terminateProvider(
        @PathVariable long id,
        @RequestBody(required = false) SuspendProviderRequest request
    ) {
        String actionBy = request != null ? request.getActionBy() : null;
        providerNetworkService.terminate(id, actionBy);
        return ResponseEntity.ok(Map.of("status", "TERMINATED"));
    }

    @GetMapping("/provider-receivables")
    public ResponseEntity<?> listProviderInvoices(@RequestParam(required = false) String status) {
        if (status != null) {
            ProviderInvoiceRecord.Status resolvedStatus = ProviderInvoiceRecord.Status.valueOf(status.toUpperCase());
            return ResponseEntity.ok(providerSettlementService.findInvoicesByStatus(resolvedStatus));
        }
        return ResponseEntity.ok(
            providerSettlementService.findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED)
        );
    }

    @PostMapping("/provider-receivables/{labId}/invoice")
    public ResponseEntity<ProviderInvoiceRecord> submitProviderInvoice(
        @PathVariable String labId,
        @Valid @RequestBody SubmitProviderInvoiceRequest request
    ) {
        EthereumAddressValidator.validate(request.getProviderAddress(), "providerAddress");
        ProviderInvoiceRecord record = providerSettlementService.submitInvoice(
            labId,
            request.getProviderAddress(),
            request.getInvoiceRef(),
            request.getEurAmount(),
            request.getCreditAmount()
        );
        return ResponseEntity.ok(record);
    }

    @PostMapping("/provider-receivables/invoices/{invoiceId}/approve")
    public ResponseEntity<ProviderApproval> approveInvoice(
        @PathVariable long invoiceId,
        @Valid @RequestBody ApproveProviderInvoiceRequest request
    ) {
        EthereumAddressValidator.validate(request.getApprovedBy(), "approvedBy");
        ProviderApproval approval = providerSettlementService.approveInvoice(
            invoiceId,
            request.getApprovedBy(),
            request.getApprovalRef(),
            request.getEurAmount()
        );
        return ResponseEntity.ok(approval);
    }

    @PostMapping("/provider-receivables/{labId}/pay")
    public ResponseEntity<ProviderPayout> recordPayout(
        @PathVariable String labId,
        @Valid @RequestBody RecordProviderPayoutRequest request
    ) {
        EthereumAddressValidator.validate(request.getProviderAddress(), "providerAddress");
        BigDecimal creditAmount = request.getCreditAmount() != null ? request.getCreditAmount() : BigDecimal.ZERO;
        ProviderPayout payout = providerSettlementService.recordPayout(
            labId,
            request.getProviderAddress(),
            request.getEurAmount(),
            creditAmount,
            request.getBankRef(),
            request.getEurcTxHash(),
            request.getUsdcTxHash()
        );
        return ResponseEntity.ok(payout);
    }
}
