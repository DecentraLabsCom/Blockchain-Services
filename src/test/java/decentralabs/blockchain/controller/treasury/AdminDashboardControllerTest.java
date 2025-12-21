package decentralabs.blockchain.controller.treasury;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import decentralabs.blockchain.dto.wallet.NetworkInfo;
import decentralabs.blockchain.dto.wallet.NetworkResponse;
import decentralabs.blockchain.service.treasury.InstitutionalAnalyticsService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;

/**
 * Unit tests for AdminDashboardController.
 * Tests administrative dashboard endpoints with localhost-only access control.
 */
@ExtendWith(MockitoExtension.class)
class AdminDashboardControllerTest {

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private WalletService walletService;

    @Mock
    private InstitutionalAnalyticsService institutionalAnalyticsService;

    @InjectMocks
    private AdminDashboardController adminDashboardController;

    private MockMvc mockMvc;

    private static final String VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";

    @BeforeEach
    void setUp() {
        // Disable localhost-only check for testing
        ReflectionTestUtils.setField(adminDashboardController, "adminDashboardLocalOnly", false);
        ReflectionTestUtils.setField(adminDashboardController, "adminDashboardAllowPrivate", true);
        ReflectionTestUtils.setField(adminDashboardController, "contractAddress", VALID_ADDRESS);
        ReflectionTestUtils.setField(adminDashboardController, "marketplaceUrl", "https://marketplace.example.com");
        mockMvc = MockMvcBuilders.standaloneSetup(adminDashboardController).build();
    }

    @Nested
    @DisplayName("System Status Endpoint Tests")
    class SystemStatusTests {

        @Test
        @DisplayName("Should get system status successfully with configured wallet")
        void shouldGetSystemStatusWithWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());

            mockMvc.perform(get("/treasury/admin/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.walletConfigured").value(true))
                .andExpect(jsonPath("$.institutionalWalletAddress").value(VALID_ADDRESS));
        }

        @Test
        @DisplayName("Should get system status when wallet not configured")
        void shouldGetSystemStatusWithoutWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());

            mockMvc.perform(get("/treasury/admin/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.walletConfigured").value(false))
                .andExpect(jsonPath("$.institutionalWalletAddress").isEmpty());
        }

        @Test
        @DisplayName("Should handle error getting system status")
        void shouldHandleErrorGettingStatus() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress())
                .thenThrow(new RuntimeException("Database error"));

            mockMvc.perform(get("/treasury/admin/status"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").exists());
        }
    }

    @Nested
    @DisplayName("Balance Endpoint Tests")
    class BalanceTests {

        @Test
        @DisplayName("Should get balance when wallet is configured")
        void shouldGetBalanceWithWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());

            mockMvc.perform(get("/treasury/admin/balance"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should return zeros when wallet not configured")
        void shouldReturnZerosWhenNoWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);

            mockMvc.perform(get("/treasury/admin/balance"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.walletConfigured").value(false))
                .andExpect(jsonPath("$.ethBalance").value("0"));
        }

        @Test
        @DisplayName("Should get balance for specific chain")
        void shouldGetBalanceForSpecificChain() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            // When chainId is specified, the controller switches network and gets balance
            // Mock those calls
            when(walletService.getBalance(VALID_ADDRESS)).thenReturn(
                decentralabs.blockchain.dto.wallet.BalanceResponse.builder()
                    .success(true)
                    .address(VALID_ADDRESS)
                    .balanceWei("1000000000000000000")
                    .balanceEth("1.0")
                    .network("sepolia")
                    .build()
            );

            mockMvc.perform(get("/treasury/admin/balance")
                    .param("chainId", "11155111"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }
    }

    @Nested
    @DisplayName("Transactions Endpoint Tests")
    class TransactionsTests {

        @Test
        @DisplayName("Should get transactions successfully")
        void shouldGetTransactionsSuccessfully() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(institutionalAnalyticsService.getRecentTransactions(any(), anyInt()))
                .thenReturn(Collections.emptyList());

            mockMvc.perform(get("/treasury/admin/transactions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.transactions").isArray());
        }

        @Test
        @DisplayName("Should respect limit parameter")
        void shouldRespectLimitParameter() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(institutionalAnalyticsService.getRecentTransactions(VALID_ADDRESS, 20))
                .thenReturn(Collections.emptyList());

            mockMvc.perform(get("/treasury/admin/transactions")
                    .param("limit", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should reject when wallet not configured")
        void shouldRejectWhenNoWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);

            mockMvc.perform(get("/treasury/admin/transactions"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("Institutional wallet not configured"));
        }
    }

    @Nested
    @DisplayName("Contract Info Endpoint Tests")
    class ContractInfoTests {

        @Test
        @DisplayName("Should get contract info successfully")
        void shouldGetContractInfoSuccessfully() throws Exception {
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());

            mockMvc.perform(get("/treasury/admin/contract-info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.contractAddress").exists());
        }

        @Test
        @DisplayName("Should handle error getting contract info")
        void shouldHandleErrorGettingContractInfo() throws Exception {
            when(walletService.getAvailableNetworks())
                .thenThrow(new RuntimeException("Network error"));

            mockMvc.perform(get("/treasury/admin/contract-info"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("Access Control Tests")
    class AccessControlTests {

        @BeforeEach
        void setUpAccess() {
            ReflectionTestUtils.setField(adminDashboardController, "adminDashboardLocalOnly", true);
            ReflectionTestUtils.setField(adminDashboardController, "adminDashboardAllowPrivate", true);
            ReflectionTestUtils.setField(adminDashboardController, "allowPrivateNetworks", true);
            ReflectionTestUtils.setField(adminDashboardController, "internalToken", "test-token");
            ReflectionTestUtils.setField(adminDashboardController, "internalTokenHeader", "X-Internal-Token");
            ReflectionTestUtils.setField(adminDashboardController, "internalTokenCookie", "internal_token");
            ReflectionTestUtils.setField(adminDashboardController, "internalTokenRequired", true);
            mockMvc = MockMvcBuilders.standaloneSetup(adminDashboardController).build();
        }

        @Test
        @DisplayName("Should reject private network without internal token")
        void shouldRejectPrivateNetworkWithoutToken() throws Exception {
            mockMvc.perform(get("/treasury/admin/status")
                    .with(req -> { req.setRemoteAddr("10.0.0.5"); return req; }))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false));
        }

        @Test
        @DisplayName("Should allow private network with valid internal token")
        void shouldAllowPrivateNetworkWithToken() throws Exception {
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());

            mockMvc.perform(get("/treasury/admin/status")
                    .header("X-Internal-Token", "test-token")
                    .with(req -> { req.setRemoteAddr("10.0.0.5"); return req; }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }
    }

    private NetworkResponse createNetworkResponse() {
        NetworkInfo sepolia = NetworkInfo.builder()
            .id("sepolia")
            .name("Sepolia")
            .chainId(11155111)
            .rpcUrl("https://sepolia.infura.io/v3/xxx")
            .build();
        NetworkInfo mainnet = NetworkInfo.builder()
            .id("mainnet")
            .name("Mainnet")
            .chainId(1)
            .rpcUrl("https://mainnet.infura.io/v3/xxx")
            .build();
        return NetworkResponse.builder()
            .success(true)
            .activeNetwork("sepolia")
            .networks(List.of(sepolia, mainnet))
            .build();
    }
}
