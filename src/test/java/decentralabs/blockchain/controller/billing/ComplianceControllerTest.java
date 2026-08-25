package decentralabs.blockchain.controller.billing;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import decentralabs.blockchain.service.billing.ComplianceExportService;
import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class ComplianceControllerTest {

    private static final String ADDRESS = "0x1111111111111111111111111111111111111111";

    @Mock
    private ComplianceExportService exportService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new ComplianceController(exportService)).build();
    }

    @Test
    void returnsMicaVolumeAndHistory() throws Exception {
        when(exportService.exportRolling12MonthVolume()).thenReturn(new BigDecimal("42.50"));
        when(exportService.exportMicaVolumeHistory(12)).thenReturn(List.of());

        mockMvc.perform(get("/billing/compliance/mica-volume"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.rolling12MonthEurVolume").value(42.50))
            .andExpect(jsonPath("$.history").isArray());
    }

    @Test
    void validatesAddressBeforeExportingPrepaidBalances() throws Exception {
        when(exportService.exportPrepaidBalancesByLot(ADDRESS)).thenReturn(List.of());
        when(exportService.exportExpiredLots(ADDRESS)).thenReturn(List.of());

        mockMvc.perform(get("/billing/compliance/exports/prepaid-balances")
                .param("address", ADDRESS))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(exportService).exportPrepaidBalancesByLot(ADDRESS);

        mockMvc.perform(get("/billing/compliance/exports/expired")
                .param("address", ADDRESS))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(exportService).exportExpiredLots(ADDRESS);
    }

    @Test
    void rejectsInvalidAddressForAddressBoundExports() throws Exception {
        mockMvc.perform(get("/billing/compliance/exports/prepaid-balances")
                .param("address", "not-an-address"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("Invalid Ethereum address for address: not-an-address"));

        mockMvc.perform(get("/billing/compliance/exports/expired")
                .param("address", "not-an-address"))
            .andExpect(status().isBadRequest());

        mockMvc.perform(get("/billing/compliance/exports/completed-payouts")
                .param("providerAddress", "not-an-address"))
            .andExpect(status().isBadRequest());

        verify(exportService, never()).exportPrepaidBalancesByLot("not-an-address");
        verify(exportService, never()).exportExpiredLots("not-an-address");
        verify(exportService, never()).exportCompletedPayouts("not-an-address");
    }

    @Test
    void capsConsumedExportLimitAtTenThousand() throws Exception {
        when(exportService.exportConsumedByPeriod(ADDRESS, 10_000)).thenReturn(List.of());

        mockMvc.perform(get("/billing/compliance/exports/consumed")
                .param("address", ADDRESS)
                .param("limit", "25000"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(exportService).exportConsumedByPeriod(ADDRESS, 10_000);
    }

    @Test
    void rejectsInvalidAddressBeforeConsumedExport() throws Exception {
        mockMvc.perform(get("/billing/compliance/exports/consumed")
                .param("address", "not-an-address")
                .param("limit", "5"))
            .andExpect(status().isBadRequest());

        verify(exportService, never()).exportConsumedByPeriod(eq("not-an-address"), eq(5));
    }

    @Test
    void returnsReceivableAccrualsAndProviderNetworkSnapshot() throws Exception {
        when(exportService.exportProviderReceivableAccruals()).thenReturn(List.of());
        when(exportService.exportProviderNetworkSnapshot()).thenReturn(List.of());

        mockMvc.perform(get("/billing/compliance/exports/receivable-accruals"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
        mockMvc.perform(get("/billing/compliance/exports/provider-network"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());
    }

    @Test
    void exportsCompletedPayoutsForAValidProviderAddress() throws Exception {
        when(exportService.exportCompletedPayouts(ADDRESS)).thenReturn(List.of());

        mockMvc.perform(get("/billing/compliance/exports/completed-payouts")
                .param("providerAddress", ADDRESS))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$").isArray());

        verify(exportService).exportCompletedPayouts(ADDRESS);
    }
}
