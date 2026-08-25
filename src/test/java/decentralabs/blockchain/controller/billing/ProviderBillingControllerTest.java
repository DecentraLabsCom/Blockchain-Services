package decentralabs.blockchain.controller.billing;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.domain.ProviderApproval;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderNetworkMembership;
import decentralabs.blockchain.domain.ProviderPayout;
import decentralabs.blockchain.exception.GlobalExceptionHandler;
import decentralabs.blockchain.service.billing.ProviderNetworkService;
import decentralabs.blockchain.service.billing.ProviderSettlementService;
import java.math.BigDecimal;
import java.time.LocalDate;
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
class ProviderBillingControllerTest {

    @Mock
    private ProviderNetworkService providerNetworkService;

    @Mock
    private ProviderSettlementService providerSettlementService;

    @InjectMocks
    private ProviderBillingController providerBillingController;

    private MockMvc mockMvc;
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(providerBillingController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
    }

    @Test
    void activateProvider_usesTypedPayload() throws Exception {
        ProviderNetworkMembership membership = ProviderNetworkMembership.builder()
            .id(1L)
            .providerAddress("0x1111111111111111111111111111111111111111")
            .contractId("provider-1")
            .agreementVersion("2026.1")
            .effectiveDate(LocalDate.parse("2026-04-11"))
            .build();
        when(providerNetworkService.activate(
            eq("0x1111111111111111111111111111111111111111"),
            eq("provider-1"),
            eq("2026.1"),
            eq(LocalDate.parse("2026-04-11")),
            eq(LocalDate.parse("2027-04-11")),
            eq("ops")
        )).thenReturn(membership);

        mockMvc.perform(post("/billing/provider-network")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "providerAddress":"0x1111111111111111111111111111111111111111",
                      "contractId":"provider-1",
                      "agreementVersion":"2026.1",
                      "activatedBy":"ops",
                      "effectiveDate":"2026-04-11",
                      "expiryDate":"2027-04-11"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(1))
            .andExpect(jsonPath("$.contractId").value("provider-1"));
    }

    @Test
    void activateProvider_rejectsMissingAgreementVersion() throws Exception {
        mockMvc.perform(post("/billing/provider-network")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "providerAddress":"0x1111111111111111111111111111111111111111",
                      "contractId":"provider-1"
                    }
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void listProviderNetworkUsesActiveByDefaultAndSupportsAll() throws Exception {
        when(providerNetworkService.findAllActive()).thenReturn(java.util.List.of());
        when(providerNetworkService.findAll()).thenReturn(java.util.List.of());

        mockMvc.perform(get("/billing/provider-network"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
        mockMvc.perform(get("/billing/provider-network").param("status", "all"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(providerNetworkService).findAllActive();
        verify(providerNetworkService).findAll();
    }

    @Test
    void suspendAndTerminateForwardOptionalRequestFields() throws Exception {
        mockMvc.perform(post("/billing/provider-network/12/suspend"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("SUSPENDED"));
        mockMvc.perform(post("/billing/provider-network/12/terminate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"actionBy\":\"operator\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("TERMINATED"));

        verify(providerNetworkService).suspend(12L, null, null);
        verify(providerNetworkService).terminate(12L, "operator");
    }

    @Test
    void submitProviderInvoice_usesTypedPayload() throws Exception {
        ProviderInvoiceRecord invoice = ProviderInvoiceRecord.builder()
            .id(9L)
            .labId("12")
            .providerAddress("0x1111111111111111111111111111111111111111")
            .invoiceRef("INV-1")
            .eurAmount(new BigDecimal("25.00"))
            .build();
        when(providerSettlementService.submitInvoice(
            eq("12"),
            eq("CLAIM-1"),
            eq("0x" + "11".repeat(32)),
            eq("INV-1"),
            eq(new BigDecimal("25.00")),
            eq(new BigDecimal("20.00"))
        )).thenReturn(invoice);

        mockMvc.perform(post("/billing/provider-receivables/12/invoice")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "claimId":"CLAIM-1",
                      "batchId":"0x1111111111111111111111111111111111111111111111111111111111111111",
                      "invoiceRef":"INV-1",
                      "eurAmount":"25.00",
                      "creditAmount":"20.00"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(9))
            .andExpect(jsonPath("$.invoiceRef").value("INV-1"));
    }

    @Test
    void submitProviderInvoice_rejectsProviderAddressFromBody() throws Exception {
        mockMvc.perform(post("/billing/provider-receivables/12/invoice")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "providerAddress":"0x9999999999999999999999999999999999999999",
                      "claimId":"CLAIM-1",
                      "batchId":"0x1111111111111111111111111111111111111111111111111111111111111111",
                      "invoiceRef":"INV-1",
                      "eurAmount":"25.00",
                      "creditAmount":"20.00"
                    }
                    """))
            .andExpect(status().isBadRequest());
    }

    @Test
    void listProviderInvoicesDefaultsToSubmittedAndParsesStatus() throws Exception {
        when(providerSettlementService.findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED))
            .thenReturn(java.util.List.of());
        when(providerSettlementService.findInvoicesByStatus(ProviderInvoiceRecord.Status.APPROVED))
            .thenReturn(java.util.List.of());

        mockMvc.perform(get("/billing/provider-receivables"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
        mockMvc.perform(get("/billing/provider-receivables").param("status", "approved"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(providerSettlementService).findInvoicesByStatus(ProviderInvoiceRecord.Status.SUBMITTED);
        verify(providerSettlementService).findInvoicesByStatus(ProviderInvoiceRecord.Status.APPROVED);
    }

    @Test
    void approveProviderInvoice_doesNotAcceptActorFromBody() throws Exception {
        ProviderApproval approval = ProviderApproval.builder()
            .id(10L)
            .invoiceRecordId(12L)
            .approvedBy("0x2222222222222222222222222222222222222222")
            .approvalRef("APPROVAL-1")
            .eurAmount(new BigDecimal("25.00"))
            .build();
        when(providerSettlementService.approveInvoice(
            eq(12L), eq("APPROVAL-1"), eq(new BigDecimal("25.00"))
        )).thenReturn(approval);

        mockMvc.perform(post("/billing/provider-receivables/invoices/12/approve")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "approvedBy":"0x9999999999999999999999999999999999999999",
                      "approvalRef":"APPROVAL-1",
                      "eurAmount":"25.00"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.approvedBy").value("0x2222222222222222222222222222222222222222"));

        verify(providerSettlementService).approveInvoice(12L, "APPROVAL-1", new BigDecimal("25.00"));
    }

    @Test
    void recordPayoutForwardsSettlementProofFields() throws Exception {
        ProviderPayout payout = ProviderPayout.builder().id(15L).invoiceRecordId(12L).build();
        when(providerSettlementService.recordPayout(
            eq(12L),
            eq(new BigDecimal("25.00")),
            eq(new BigDecimal("20.00")),
            eq("PAY-1"),
            eq("attestation"),
            eq("bank-1"),
            eq("0xeurc"),
            eq("0xusdc")
        )).thenReturn(payout);

        mockMvc.perform(post("/billing/provider-receivables/invoices/12/pay")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "eurAmount":"25.00",
                      "creditAmount":"20.00",
                      "paymentRef":"PAY-1",
                      "paymentAttestation":"attestation",
                      "bankRef":"bank-1",
                      "eurcTxHash":"0xeurc",
                      "usdcTxHash":"0xusdc"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(15));

        verify(providerSettlementService).recordPayout(
            12L,
            new BigDecimal("25.00"),
            new BigDecimal("20.00"),
            "PAY-1",
            "attestation",
            "bank-1",
            "0xeurc",
            "0xusdc"
        );
    }
}
