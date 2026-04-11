package decentralabs.blockchain.controller.billing;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.domain.ProviderInvoiceRecord;
import decentralabs.blockchain.domain.ProviderNetworkMembership;
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
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(providerBillingController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
        objectMapper = new ObjectMapper().findAndRegisterModules();
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
            eq("0x1111111111111111111111111111111111111111"),
            eq("INV-1"),
            eq(new BigDecimal("25.00")),
            eq(new BigDecimal("20.00"))
        )).thenReturn(invoice);

        mockMvc.perform(post("/billing/provider-receivables/12/invoice")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "providerAddress":"0x1111111111111111111111111111111111111111",
                      "invoiceRef":"INV-1",
                      "eurAmount":"25.00",
                      "creditAmount":"20.00"
                    }
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(9))
            .andExpect(jsonPath("$.invoiceRef").value("INV-1"));
    }
}
