package decentralabs.blockchain.controller.health;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.Web3ClientVersion;

import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.organization.InstitutionRegistrationService;
import decentralabs.blockchain.service.organization.InstitutionRole;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;

@ExtendWith(MockitoExtension.class)
class HealthControllerTest {

    @Mock
    private MarketplaceKeyService marketplaceKeyService;

    @Mock
    private WalletService walletService;

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @Mock
    private InstitutionRegistrationService institutionRegistrationService;

    @Mock
    private ObjectProvider<JdbcTemplate> jdbcTemplateProvider;

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private Web3j web3j;

    @TempDir
    Path tempDir;

    private HealthController healthController;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() throws Exception {
        healthController = new HealthController(
            marketplaceKeyService,
            walletService,
            samlValidationService,
            institutionalWalletService,
            institutionRegistrationService,
            jdbcTemplateProvider
        );

        // Create a temporary private key file so isPrivateKeyPresent() returns true
        Path privateKeyFile = tempDir.resolve("private-key.pem");
        Files.writeString(privateKeyFile, "dummy-key-content");

        ReflectionTestUtils.setField(healthController, "marketplacePublicKeyUrl", "https://marketplace.example.com/public-key");
        ReflectionTestUtils.setField(healthController, "privateKeyPath", privateKeyFile.toString());
        ReflectionTestUtils.setField(healthController, "providersEnabled", true);
        ReflectionTestUtils.setField(healthController, "eventListeningEnabled", true);
        ReflectionTestUtils.setField(healthController, "contractAddress", "0xContract");

        mockMvc = MockMvcBuilders.standaloneSetup(healthController).build();
    }

    @Nested
    @DisplayName("Health Check Basic Tests")
    class BasicHealthTests {

        @Test
        @DisplayName("Should return health status with timestamp and service name")
        void shouldReturnHealthStatusWithBasicInfo() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("blockchain-services"))
                .andExpect(jsonPath("$.version").value("1.0.0"))
                .andExpect(jsonPath("$.timestamp").exists());
        }

        @Test
        @DisplayName("Should return UP status when all services healthy")
        void shouldReturnUpStatusWhenAllServicesHealthy() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
        }
    }

    @Nested
    @DisplayName("Marketplace Key Health Tests")
    class MarketplaceKeyTests {

        @Test
        @DisplayName("Should include marketplace key status")
        void shouldIncludeMarketplaceKeyStatus() throws Exception {
            setupHealthyEnvironment();
            when(marketplaceKeyService.ensureKey(anyBoolean())).thenReturn(true);

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.marketplace_key_cached").value(true))
                .andExpect(jsonPath("$.marketplace_key_url").value("https://marketplace.example.com/public-key"));
        }

        @Test
        @DisplayName("Should return DEGRADED when marketplace key unavailable")
        void shouldReturnDegradedWhenMarketplaceKeyUnavailable() throws Exception {
            setupHealthyEnvironment();
            when(marketplaceKeyService.ensureKey(anyBoolean())).thenReturn(false);

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DEGRADED"))
                .andExpect(jsonPath("$.marketplace_key_cached").value(false));
        }

        @Test
        @DisplayName("Should handle marketplace key check exception")
        void shouldHandleMarketplaceKeyCheckException() throws Exception {
            setupHealthyEnvironment();
            when(marketplaceKeyService.ensureKey(anyBoolean())).thenThrow(new RuntimeException("Key error"));

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.marketplace_key_cached").value(false));
        }
    }

    @Nested
    @DisplayName("RPC Client Health Tests")
    class RpcClientTests {

        @Test
        @DisplayName("Should include RPC client version when available")
        void shouldIncludeRpcClientVersionWhenAvailable() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rpc_up").value(true))
                .andExpect(jsonPath("$.rpc_client_version").value("Geth/v1.10.0"));
        }

        @Test
        @DisplayName("Should return DEGRADED when RPC unavailable")
        void shouldReturnDegradedWhenRpcUnavailable() throws Exception {
            setupHealthyEnvironment();
            when(walletService.getWeb3jInstance()).thenThrow(new RuntimeException("RPC connection failed"));

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.rpc_up").value(false));
        }
    }

    @Nested
    @DisplayName("Database Health Tests")
    class DatabaseTests {

        @Test
        @DisplayName("Should include database status")
        void shouldIncludeDatabaseStatus() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.database_up").value(true));
        }

        @Test
        @DisplayName("Should return DEGRADED when database unavailable")
        void shouldReturnDegradedWhenDatabaseUnavailable() throws Exception {
            setupHealthyEnvironment();
            when(jdbcTemplateProvider.getIfAvailable()).thenReturn(null);

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.database_up").value(false));
        }

        @Test
        @DisplayName("Should return DEGRADED when database query fails")
        void shouldReturnDegradedWhenDatabaseQueryFails() throws Exception {
            setupHealthyEnvironment();
            when(jdbcTemplate.queryForObject(anyString(), eq(Integer.class)))
                .thenThrow(new RuntimeException("Connection refused"));

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.database_up").value(false));
        }
    }

    @Nested
    @DisplayName("Wallet Configuration Tests")
    class WalletConfigTests {

        @Test
        @DisplayName("Should include wallet configuration status")
        void shouldIncludeWalletConfigurationStatus() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.wallet_configured").value(true));
        }

        @Test
        @DisplayName("Should return DEGRADED when wallet not configured")
        void shouldReturnDegradedWhenWalletNotConfigured() throws Exception {
            setupHealthyEnvironment();
            when(institutionalWalletService.isConfigured()).thenReturn(false);

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.wallet_configured").value(false));
        }
    }

    @Nested
    @DisplayName("SAML Validation Tests")
    class SamlValidationTests {

        @Test
        @DisplayName("Should include SAML validation status")
        void shouldIncludeSamlValidationStatus() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saml_validation_ready").value(true));
        }
    }

    @Nested
    @DisplayName("Endpoint Status Tests")
    class EndpointStatusTests {

        @Test
        @DisplayName("Should include endpoint status when providers enabled")
        void shouldIncludeEndpointStatusWhenProvidersEnabled() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.endpoints.['wallet-auth']").value("available"))
                .andExpect(jsonPath("$.endpoints.jwks").value("available"))
                .andExpect(jsonPath("$.endpoints.health").value("available"));
        }

        @Test
        @DisplayName("Should mark endpoints disabled when providers disabled")
        void shouldMarkEndpointsDisabledWhenProvidersDisabled() throws Exception {
            setupHealthyEnvironment();
            ReflectionTestUtils.setField(healthController, "providersEnabled", false);

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable()) // treasury_configured will be false
                .andExpect(jsonPath("$.endpoints.['wallet-auth']").value("disabled (providers flag off)"));
        }
    }

    @Nested
    @DisplayName("Treasury Configuration Tests")
    class TreasuryConfigTests {

        @Test
        @DisplayName("Should include treasury configuration status")
        void shouldIncludeTreasuryConfigurationStatus() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.treasury_configured").value(true));
        }

        @Test
        @DisplayName("Should return DEGRADED when treasury not configured")
        void shouldReturnDegradedWhenTreasuryNotConfigured() throws Exception {
            setupHealthyEnvironment();
            ReflectionTestUtils.setField(healthController, "contractAddress", "");

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.treasury_configured").value(false));
        }
    }

    @Nested
    @DisplayName("Invite Token Configuration Tests")
    class InviteTokenConfigTests {

        @Test
        @DisplayName("Should include invite token configuration status")
        void shouldIncludeInviteTokenConfigurationStatus() throws Exception {
            setupHealthyEnvironment();

            mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.invite_token_configured").value(true));
        }

        @Test
        @DisplayName("Should return DEGRADED when provider not registered")
        void shouldReturnDegradedWhenProviderNotRegistered() throws Exception {
            setupHealthyEnvironment();
            when(institutionRegistrationService.isRegistered(InstitutionRole.PROVIDER)).thenReturn(false);

            mockMvc.perform(get("/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.provider_registered").value(false));
        }
    }

    private void setupHealthyEnvironment() throws Exception {
        // Use lenient() to avoid UnnecessaryStubbingException in tests that override specific mocks
        lenient().when(marketplaceKeyService.ensureKey(anyBoolean())).thenReturn(true);
        lenient().when(samlValidationService.isConfigured()).thenReturn(true);
        lenient().when(institutionalWalletService.isConfigured()).thenReturn(true);
        lenient().when(institutionRegistrationService.isRegistered(InstitutionRole.PROVIDER)).thenReturn(true);
        lenient().when(jdbcTemplateProvider.getIfAvailable()).thenReturn(jdbcTemplate);
        lenient().when(jdbcTemplate.queryForObject(anyString(), eq(Integer.class))).thenReturn(1);

        // Setup Web3j mock chain using doReturn to avoid generic type issues
        lenient().when(walletService.getWeb3jInstance()).thenReturn(web3j);
        Web3ClientVersion clientVersion = mock(Web3ClientVersion.class);
        lenient().when(clientVersion.getWeb3ClientVersion()).thenReturn("Geth/v1.10.0");
        
        @SuppressWarnings("unchecked")
        Request<?, Web3ClientVersion> mockRequest = mock(Request.class);
        lenient().when(mockRequest.send()).thenReturn(clientVersion);
        lenient().doReturn(mockRequest).when(web3j).web3ClientVersion();
    }
}
