package decentralabs.blockchain.controller.billing;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.domain.FundingOrder;
import decentralabs.blockchain.domain.FundingInvoice;
import decentralabs.blockchain.domain.PaymentReconciliation;
import decentralabs.blockchain.domain.CreditAccount;
import decentralabs.blockchain.exception.GlobalExceptionHandler;
import decentralabs.blockchain.service.billing.CreditProjectionService;
import decentralabs.blockchain.service.billing.FundingOrderService;
import decentralabs.blockchain.service.auth.MarketplaceEndpointAuthService;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class FundingControllerTest {

    @Mock
    private FundingOrderService fundingOrderService;

    @Mock
    private CreditProjectionService creditProjectionService;

    @Mock
    private MarketplaceEndpointAuthService marketplaceEndpointAuthService;

    @InjectMocks
    private FundingController fundingController;

    private MockMvc mockMvc;
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(fundingController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
    }

    @Test
    void createFundingOrder_usesTypedPayload() throws Exception {
        FundingOrder order = FundingOrder.builder()
            .id(7L)
            .institutionAddress("0x1111111111111111111111111111111111111111")
            .eurGrossAmount(new BigDecimal("12.50"))
            .status(FundingOrder.Status.DRAFT)
            .build();
        when(fundingOrderService.createFundingOrder(
            eq("0x1111111111111111111111111111111111111111"),
            eq(new BigDecimal("12.50")),
            eq(new BigDecimal("10.00")),
            eq("PO-1"),
            eq(Instant.parse("2026-04-11T10:15:30Z"))
        )).thenReturn(order);

        mockMvc.perform(post("/billing/funding-orders")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "institutionAddress":"0x1111111111111111111111111111111111111111",
                      "eurGrossAmount":"12.50",
                      "creditAmount":"10.00",
                      "reference":"PO-1",
                      "expiresAt":"2026-04-11T10:15:30Z"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(7))
            .andExpect(jsonPath("$.institutionAddress").value("0x1111111111111111111111111111111111111111"));
    }

    @Test
    void createFundingOrder_rejectsMissingInstitutionAddress() throws Exception {
        mockMvc.perform(post("/billing/funding-orders")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "eurGrossAmount":"12.50"
                    }
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void listFundingOrders_byInstitutionValidatesAddress() throws Exception {
        when(fundingOrderService.findByInstitution("0x1111111111111111111111111111111111111111"))
            .thenReturn(List.of());

        mockMvc.perform(get("/billing/funding-orders")
                .header("Authorization", "Bearer marketplace-service-token")
                .param("institution", "0x1111111111111111111111111111111111111111"))
            .andExpect(status().isOk());
    }

    @Test
    void listFundingOrdersSupportsStatusAndDefaultsToDraft() throws Exception {
        when(fundingOrderService.findByStatus(FundingOrder.Status.PAID)).thenReturn(List.of());
        when(fundingOrderService.findByStatus(FundingOrder.Status.DRAFT)).thenReturn(List.of());

        mockMvc.perform(get("/billing/funding-orders")
                .header("Authorization", "Bearer marketplace-service-token")
                .param("status", "paid"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
        mockMvc.perform(get("/billing/funding-orders")
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(fundingOrderService).findByStatus(FundingOrder.Status.PAID);
        verify(fundingOrderService).findByStatus(FundingOrder.Status.DRAFT);
    }

    @Test
    void listFundingOrders_requiresBillingReadScopeWhenServiceTokenIsPresent() throws Exception {
        org.mockito.Mockito.doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.FORBIDDEN, "missing_marketplace_scope"))
            .when(marketplaceEndpointAuthService)
            .enforceServiceAuthorization("Bearer marketplace-service-token", "billing:read");

        mockMvc.perform(get("/billing/funding-orders")
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isForbidden());
    }

    @Test
    void listFundingOrders_requiresMarketplaceTokenWhenLocalFilterMarkerIsAbsent() throws Exception {
        doThrow(new org.springframework.web.server.ResponseStatusException(
            org.springframework.http.HttpStatus.UNAUTHORIZED, "missing_marketplace_token"))
            .when(marketplaceEndpointAuthService)
            .enforceServiceAuthorization(null, "billing:read");

        mockMvc.perform(get("/billing/funding-orders"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void getCreditAccount_rejectsInvalidAddress() throws Exception {
        mockMvc.perform(get("/billing/credit-accounts/not-an-address")
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void getFundingOrder_returnsNotFoundWhenMissing() throws Exception {
        when(fundingOrderService.findById(33L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/billing/funding-orders/33")
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isNotFound());
    }

    @Test
    void getFundingOrderReturnsExistingOrder() throws Exception {
        FundingOrder order = FundingOrder.builder().id(33L).status(FundingOrder.Status.INVOICED).build();
        when(fundingOrderService.findById(33L)).thenReturn(Optional.of(order));

        mockMvc.perform(get("/billing/funding-orders/33")
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(33))
            .andExpect(jsonPath("$.status").value("INVOICED"));
    }

    @Test
    void issuesInvoiceAndConfirmsPayment() throws Exception {
        FundingInvoice invoice = FundingInvoice.builder().id(5L).fundingOrderId(33L).build();
        PaymentReconciliation reconciliation = PaymentReconciliation.builder()
            .id(6L)
            .fundingOrderId(33L)
            .paymentRef("PAY-33")
            .build();
        when(fundingOrderService.issueInvoice(33L, "INV-33", Instant.parse("2026-05-01T00:00:00Z")))
            .thenReturn(invoice);
        when(fundingOrderService.confirmPayment(33L, "PAY-33", new BigDecimal("12.50"), "BANK"))
            .thenReturn(reconciliation);

        mockMvc.perform(post("/billing/funding-orders/33/invoice")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"invoiceNumber":"INV-33","dueAt":"2026-05-01T00:00:00Z"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(5));
        mockMvc.perform(post("/billing/funding-orders/33/confirm-payment")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"paymentRef":"PAY-33","eurAmount":"12.50","paymentMethod":"BANK"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.paymentRef").value("PAY-33"));
    }

    @Test
    void cancelsAndMarksFundingOrderCredited() throws Exception {
        mockMvc.perform(post("/billing/funding-orders/33/cancel"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("CANCELLED"));
        mockMvc.perform(post("/billing/funding-orders/33/mark-credited"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("CREDITED"));

        verify(fundingOrderService).cancelFundingOrder(33L);
        verify(fundingOrderService).markCredited(33L);
    }

    @Test
    void servesCreditAccountLotsAndBoundedMovements() throws Exception {
        CreditAccount account = CreditAccount.builder().accountAddress(
            "0x1111111111111111111111111111111111111111").build();
        when(creditProjectionService.getAccount(account.getAccountAddress())).thenReturn(Optional.of(account));
        when(creditProjectionService.getLots(account.getAccountAddress())).thenReturn(List.of());
        when(creditProjectionService.getMovements(account.getAccountAddress(), 1000)).thenReturn(List.of());

        mockMvc.perform(get("/billing/credit-accounts/{address}", account.getAccountAddress())
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accountAddress").value(account.getAccountAddress()));
        mockMvc.perform(get("/billing/credit-accounts/{address}/lots", account.getAccountAddress())
                .header("Authorization", "Bearer marketplace-service-token"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
        mockMvc.perform(get("/billing/credit-accounts/{address}/movements", account.getAccountAddress())
                .header("Authorization", "Bearer marketplace-service-token")
                .param("limit", "5000"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(creditProjectionService).getMovements(account.getAccountAddress(), 1000);
    }
}
