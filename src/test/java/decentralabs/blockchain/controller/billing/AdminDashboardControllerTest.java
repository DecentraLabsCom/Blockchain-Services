package decentralabs.blockchain.controller.billing;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

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
import decentralabs.blockchain.dto.wallet.PayoutRequestSimulationResult;
import decentralabs.blockchain.dto.wallet.ProviderReceivableStatus;
import decentralabs.blockchain.security.AdminNetworkAccessPolicy;
import decentralabs.blockchain.service.billing.OnChainAdminTransactionService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.billing.InstitutionalAnalyticsService;
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

    @Mock
    private LabMetadataService labMetadataService;

    @Mock
    private AdminNetworkAccessPolicy adminNetworkAccessPolicy;

    @Mock
    private OnChainAdminTransactionService onChainAdminTransactionService;

    @InjectMocks
    private AdminDashboardController adminDashboardController;

    private MockMvc mockMvc;

    private static final String VALID_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678";

    @BeforeEach
    void setUp() {
        lenient().when(adminNetworkAccessPolicy.isRequestAllowed(any(), any())).thenReturn(true);
        lenient().when(adminNetworkAccessPolicy.isLocalOnly()).thenReturn(false);
        lenient().when(adminNetworkAccessPolicy.isPrivateAccessEnabled()).thenReturn(true);
        lenient().when(adminNetworkAccessPolicy.getConfiguredCidrs()).thenReturn(Collections.emptyList());
        lenient().when(onChainAdminTransactionService.getRecentTransactions(any(), anyInt()))
            .thenReturn(Collections.emptyList());
        ReflectionTestUtils.setField(adminDashboardController, "contractAddress", VALID_ADDRESS);
        ReflectionTestUtils.setField(adminDashboardController, "marketplaceUrl", "https://marketplace.example.com");
        ReflectionTestUtils.setField(adminDashboardController, "collectMaxBatch", 50);
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

            mockMvc.perform(get("/billing/admin/status"))
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

            mockMvc.perform(get("/billing/admin/status"))
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

            mockMvc.perform(get("/billing/admin/status"))
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

            mockMvc.perform(get("/billing/admin/balance"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should return zeros when wallet not configured")
        void shouldReturnZerosWhenNoWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);

            mockMvc.perform(get("/billing/admin/balance"))
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

            mockMvc.perform(get("/billing/admin/balance")
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

            mockMvc.perform(get("/billing/admin/transactions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.transactions").isArray());
        }

        @Test
        @DisplayName("Should respect limit parameter")
        void shouldRespectLimitParameter() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(institutionalAnalyticsService.getRecentTransactions(VALID_ADDRESS, 25))
                .thenReturn(Collections.emptyList());

            mockMvc.perform(get("/billing/admin/transactions")
                    .param("limit", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should reject when wallet not configured")
        void shouldRejectWhenNoWallet() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(null);

            mockMvc.perform(get("/billing/admin/transactions"))
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

            mockMvc.perform(get("/billing/admin/contract-info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.contractAddress").exists());
        }

        @Test
        @DisplayName("Should handle error getting contract info")
        void shouldHandleErrorGettingContractInfo() throws Exception {
            when(walletService.getAvailableNetworks())
                .thenThrow(new RuntimeException("Network error"));

            mockMvc.perform(get("/billing/admin/contract-info"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("Access Control Tests")
    class AccessControlTests {

        @BeforeEach
        void setUpAccess() {
            ReflectionTestUtils.setField(adminDashboardController, "accessToken", "test-token");
            ReflectionTestUtils.setField(adminDashboardController, "accessTokenHeader", "X-Access-Token");
            ReflectionTestUtils.setField(adminDashboardController, "accessTokenCookie", "access_token");
            ReflectionTestUtils.setField(adminDashboardController, "accessTokenRequired", true);
            mockMvc = MockMvcBuilders.standaloneSetup(adminDashboardController).build();
        }

        @Test
        @DisplayName("Should reject private network without access token")
        void shouldRejectPrivateNetworkWithoutToken() throws Exception {
            when(adminNetworkAccessPolicy.isRequestAllowed(any(), any())).thenReturn(false);
            mockMvc.perform(get("/billing/admin/status")
                    .with(req -> { req.setRemoteAddr("10.0.0.5"); return req; }))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success").value(false));
        }

        @Test
        @DisplayName("Should allow private network with valid access token")
        void shouldAllowPrivateNetworkWithToken() throws Exception {
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());
            when(adminNetworkAccessPolicy.isRequestAllowed(any(), any())).thenReturn(true);

            mockMvc.perform(get("/billing/admin/status")
                    .header("X-Access-Token", "test-token")
                    .with(req -> { req.setRemoteAddr("10.0.0.5"); return req; }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should allow IPv6-mapped loopback without access token")
        void shouldAllowIpv6MappedLoopback() throws Exception {
            when(walletService.getAvailableNetworks()).thenReturn(createNetworkResponse());
            when(adminNetworkAccessPolicy.isRequestAllowed(any(), any())).thenReturn(true);

            mockMvc.perform(get("/billing/admin/status")
                    .with(req -> { req.setRemoteAddr("::ffff:127.0.0.1"); return req; }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }
    }

    @Nested
    @DisplayName("Collect Endpoints Tests")
    class CollectEndpointsTests {

        @Test
        @DisplayName("Should list provider labs with payout info")
        void shouldListProviderLabs() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(walletService.isLabProvider(VALID_ADDRESS)).thenReturn(true);
            when(walletService.getLabsOwnedByProvider(VALID_ADDRESS)).thenReturn(List.of(BigInteger.valueOf(3)));
            when(walletService.getLabTokenUri(BigInteger.valueOf(3))).thenReturn(Optional.of("https://example.com/lab-3.json"));
            when(labMetadataService.getLabMetadata("https://example.com/lab-3.json")).thenReturn(
                decentralabs.blockchain.dto.health.LabMetadata.builder().name("Quantum Lab").build()
            );
            when(walletService.getProviderReceivableStatus(BigInteger.valueOf(3))).thenReturn(
                Optional.of(new ProviderReceivableStatus(
                    BigInteger.valueOf(1_000_000),
                    BigInteger.ZERO,
                    BigInteger.valueOf(1_000_000),
                    BigInteger.ZERO
                ))
            );

            mockMvc.perform(get("/billing/admin/provider-labs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.labs[0].labId").value("3"))
                .andExpect(jsonPath("$.labs[0].label").value("Quantum Lab"))
                .andExpect(jsonPath("$.labs[0].eligibleReservationCount").value("0"))
                .andExpect(jsonPath("$.labs[0].totalReceivableLab").value("10"));
        }

        @Test
        @DisplayName("Should reject lab payout status when lab is not owned")
        void shouldRejectProviderReceivableStatusWhenLabIsNotOwned() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(walletService.isLabOwnedByProvider(VALID_ADDRESS, BigInteger.valueOf(3))).thenReturn(false);

            mockMvc.perform(get("/billing/admin/provider-receivable-status").param("labId", "3"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("Selected lab is not associated with this institutional provider"));
        }

        @Test
        @DisplayName("Should reject lab payout status with invalid labId")
        void shouldRejectProviderReceivableStatusWithInvalidLabId() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);

            mockMvc.perform(get("/billing/admin/provider-receivable-status").param("labId", "-1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error").value("labId must be greater than zero"));
        }

        @Test
        @DisplayName("Should return lab payout status when collect is available")
        void shouldReturnProviderReceivableStatus() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(walletService.isLabOwnedByProvider(VALID_ADDRESS, BigInteger.valueOf(3))).thenReturn(true);
            when(walletService.getProviderReceivableStatus(BigInteger.valueOf(3))).thenReturn(
                Optional.of(new ProviderReceivableStatus(
                    BigInteger.valueOf(2_000_000),
                    BigInteger.ZERO,
                    BigInteger.valueOf(2_000_000),
                    BigInteger.ZERO,
                    BigInteger.valueOf(500_000),
                    BigInteger.valueOf(750_000),
                    BigInteger.valueOf(250_000),
                    BigInteger.valueOf(500_000),
                    BigInteger.ZERO,
                    BigInteger.ZERO,
                    BigInteger.ZERO,
                    BigInteger.valueOf(1_700_000_000L)
                ))
            );
            when(walletService.simulateProviderPayoutRequest(VALID_ADDRESS, BigInteger.valueOf(3), BigInteger.valueOf(50)))
                .thenReturn(new PayoutRequestSimulationResult(true, null));

            mockMvc.perform(get("/billing/admin/provider-receivable-status").param("labId", "3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.labId").value("3"))
                .andExpect(jsonPath("$.canRequestPayout").value(true))
                .andExpect(jsonPath("$.eligibleReservationCount").value("0"))
                .andExpect(jsonPath("$.totalReceivableLab").value("20"))
                .andExpect(jsonPath("$.accruedReceivableLab").value("5"))
                .andExpect(jsonPath("$.settlementQueuedLab").value("7.5"))
                .andExpect(jsonPath("$.invoicedReceivableLab").value("2.5"))
                .andExpect(jsonPath("$.approvedReceivableLab").value("5"))
                .andExpect(jsonPath("$.lastAccruedAt").value("1700000000"));
        }
    }

    @Nested
    @DisplayName("Billing Info Endpoint Tests")
    class BillingInfoEndpointTests {

        @Test
        @DisplayName("Should include service credit balance in billing info")
        void shouldIncludeServiceCreditBalanceInBillingInfo() throws Exception {
            when(institutionalWalletService.getInstitutionalWalletAddress()).thenReturn(VALID_ADDRESS);
            when(walletService.getInstitutionalUserLimit(VALID_ADDRESS)).thenReturn(BigInteger.valueOf(1_000_000));
            when(walletService.getInstitutionalSpendingPeriod(VALID_ADDRESS)).thenReturn(BigInteger.valueOf(86_400));
            when(walletService.getInstitutionalBillingBalance(VALID_ADDRESS)).thenReturn(BigInteger.valueOf(250_000));
            when(walletService.getServiceCreditBalance(VALID_ADDRESS)).thenReturn(BigInteger.valueOf(750_000));
            when(walletService.isLabProvider(VALID_ADDRESS)).thenReturn(false);

            mockMvc.perform(get("/billing/admin/billing-info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.walletConfigured").value(true))
                .andExpect(jsonPath("$.serviceCreditBalance").value("750000"))
                .andExpect(jsonPath("$.serviceCreditBalanceFormatted").value("7.5"))
                .andExpect(jsonPath("$.billingBalance").value("250000"))
                .andExpect(jsonPath("$.billingBalanceFormatted").value("2.5"));
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
