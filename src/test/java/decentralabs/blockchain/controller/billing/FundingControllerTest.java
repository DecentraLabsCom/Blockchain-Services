package decentralabs.blockchain.controller.billing;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.domain.FundingOrder;
import decentralabs.blockchain.exception.GlobalExceptionHandler;
import decentralabs.blockchain.service.billing.CreditProjectionService;
import decentralabs.blockchain.service.billing.FundingOrderService;
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

    @InjectMocks
    private FundingController fundingController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(fundingController)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
        objectMapper = new ObjectMapper().findAndRegisterModules();
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
                .param("institution", "0x1111111111111111111111111111111111111111"))
            .andExpect(status().isOk());
    }

    @Test
    void getCreditAccount_rejectsInvalidAddress() throws Exception {
        mockMvc.perform(get("/billing/credit-accounts/not-an-address"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void getFundingOrder_returnsNotFoundWhenMissing() throws Exception {
        when(fundingOrderService.findById(33L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/billing/funding-orders/33"))
            .andExpect(status().isNotFound());
    }
}
