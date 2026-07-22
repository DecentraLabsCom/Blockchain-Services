package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.domain.FundingInvoice;
import decentralabs.blockchain.domain.FundingOrder;
import decentralabs.blockchain.domain.PaymentReconciliation;
import decentralabs.blockchain.dto.billing.ConfirmFundingPaymentRequest;
import decentralabs.blockchain.dto.billing.CreateFundingOrderRequest;
import decentralabs.blockchain.dto.billing.IssueFundingInvoiceRequest;
import decentralabs.blockchain.service.billing.CreditProjectionService;
import decentralabs.blockchain.service.billing.FundingOrderService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import decentralabs.blockchain.security.LocalhostOnlyFilter;
import decentralabs.blockchain.util.EthereumAddressValidator;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
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
public class FundingController {

    private final FundingOrderService fundingOrderService;
    private final CreditProjectionService creditProjectionService;
    private final MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    private static final String BILLING_READ_SCOPE = "billing:read";

    @PostMapping("/funding-orders")
    public ResponseEntity<FundingOrder> createFundingOrder(@Valid @RequestBody CreateFundingOrderRequest request) {
        EthereumAddressValidator.validate(request.getInstitutionAddress(), "institutionAddress");
        FundingOrder order = fundingOrderService.createFundingOrder(
            request.getInstitutionAddress(),
            request.getEurGrossAmount(),
            request.getCreditAmount(),
            request.getReference(),
            request.getExpiresAt()
        );
        return ResponseEntity.ok(order);
    }

    @GetMapping("/funding-orders")
    public ResponseEntity<?> listFundingOrders(
        HttpServletRequest request,
        @RequestParam(required = false) String institution,
        @RequestParam(required = false) String status
    ) {
        authorizeMarketplaceRead(request);
        if (status != null) {
            FundingOrder.Status resolvedStatus = FundingOrder.Status.valueOf(status.toUpperCase());
            return ResponseEntity.ok(fundingOrderService.findByStatus(resolvedStatus));
        }
        if (institution != null) {
            EthereumAddressValidator.validate(institution, "institution");
            return ResponseEntity.ok(fundingOrderService.findByInstitution(institution));
        }
        return ResponseEntity.ok(fundingOrderService.findByStatus(FundingOrder.Status.DRAFT));
    }

    @GetMapping("/funding-orders/{id}")
    public ResponseEntity<?> getFundingOrder(
        HttpServletRequest request,
        @PathVariable long id
    ) {
        authorizeMarketplaceRead(request);
        return fundingOrderService.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/funding-orders/{id}/invoice")
    public ResponseEntity<FundingInvoice> issueInvoice(
        @PathVariable long id,
        @Valid @RequestBody IssueFundingInvoiceRequest request
    ) {
        FundingInvoice invoice = fundingOrderService.issueInvoice(id, request.getInvoiceNumber(), request.getDueAt());
        return ResponseEntity.ok(invoice);
    }

    @PostMapping("/funding-orders/{id}/confirm-payment")
    public ResponseEntity<PaymentReconciliation> confirmPayment(
        @PathVariable long id,
        @Valid @RequestBody ConfirmFundingPaymentRequest request
    ) {
        PaymentReconciliation reconciliation = fundingOrderService.confirmPayment(
            id,
            request.getPaymentRef(),
            request.getEurAmount(),
            request.getPaymentMethod()
        );
        return ResponseEntity.ok(reconciliation);
    }

    @PostMapping("/funding-orders/{id}/cancel")
    public ResponseEntity<Map<String, String>> cancelFundingOrder(@PathVariable long id) {
        fundingOrderService.cancelFundingOrder(id);
        return ResponseEntity.ok(Map.of("status", "CANCELLED"));
    }

    @PostMapping("/funding-orders/{id}/mark-credited")
    public ResponseEntity<Map<String, String>> markCredited(@PathVariable long id) {
        fundingOrderService.markCredited(id);
        return ResponseEntity.ok(Map.of("status", "CREDITED"));
    }

    @GetMapping("/credit-accounts/{address}")
    public ResponseEntity<?> getCreditAccount(
        HttpServletRequest request,
        @PathVariable String address
    ) {
        authorizeMarketplaceRead(request);
        EthereumAddressValidator.validate(address, "address");
        return creditProjectionService.getAccount(address)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/credit-accounts/{address}/lots")
    public ResponseEntity<?> getCreditLots(
        HttpServletRequest request,
        @PathVariable String address
    ) {
        authorizeMarketplaceRead(request);
        EthereumAddressValidator.validate(address, "address");
        return ResponseEntity.ok(creditProjectionService.getLots(address));
    }

    @GetMapping("/credit-accounts/{address}/movements")
    public ResponseEntity<?> getCreditMovements(
        HttpServletRequest request,
        @PathVariable String address,
        @RequestParam(defaultValue = "100") int limit
    ) {
        authorizeMarketplaceRead(request);
        EthereumAddressValidator.validate(address, "address");
        int safeLimit = Math.min(Math.max(limit, 1), 1000);
        return ResponseEntity.ok(creditProjectionService.getMovements(address, safeLimit));
    }

    /**
     * Local wallet-admin sessions intentionally do not carry a Marketplace JWT.
     * Remote Marketplace calls do, and the network filters only let those
     * read-only requests reach these mappings. Validate that credential here so
     * the read endpoints remain protected even when the backend is reached
     * directly instead of through OpenResty.
     */
    private void authorizeMarketplaceRead(HttpServletRequest request) {
        // The local exemption is a server-set attribute written by
        // LocalhostOnlyFilter only after its network and route-token checks.
        // Every request without that trusted marker must present a valid
        // Marketplace service JWT, including requests with no Authorization
        // header or a malformed one.
        // codeql[java/user-controlled-bypass]
        if (!Boolean.TRUE.equals(
            request.getAttribute(LocalhostOnlyFilter.LOCAL_BILLING_READ_ALLOWED_ATTRIBUTE))) {
            marketplaceEndpointAuthService.enforceServiceAuthorization(
                request.getHeader("Authorization"), BILLING_READ_SCOPE);
        }
    }
}
