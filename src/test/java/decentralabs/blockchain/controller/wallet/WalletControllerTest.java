package decentralabs.blockchain.controller.wallet;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.dto.wallet.BalanceResponse;
import decentralabs.blockchain.dto.wallet.EventListenerResponse;
import decentralabs.blockchain.dto.wallet.NetworkResponse;
import decentralabs.blockchain.dto.wallet.TransactionHistoryResponse;
import decentralabs.blockchain.dto.wallet.WalletCreateRequest;
import decentralabs.blockchain.dto.wallet.WalletImportRequest;
import decentralabs.blockchain.dto.wallet.WalletResponse;
import decentralabs.blockchain.dto.wallet.WalletRevealRequest;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;

/**
 * Unit tests for WalletController.
 * Tests wallet creation, import, balance, and transaction endpoints.
 */
@ExtendWith(MockitoExtension.class)
class WalletControllerTest {

    @Mock
    private WalletService walletService;

    @Mock
    private RateLimitService rateLimitService;

    @Mock
    private InstitutionalWalletService institutionalWalletService;

    @InjectMocks
    private WalletController walletController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final String VALID_ADDRESS = "0x1234567890123456789012345678901234567890";
    private static final String INVALID_ADDRESS = "invalid-address";

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(walletController).build();
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("Create Wallet Endpoint Tests")
    class CreateWalletTests {

        @Test
        @DisplayName("Should create wallet successfully")
        void shouldCreateWalletSuccessfully() throws Exception {
            WalletCreateRequest request = new WalletCreateRequest();
            request.setPassword("securePassword123");

            WalletResponse response = WalletResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .message("Wallet created")
                .build();

            when(walletService.createWallet("securePassword123")).thenReturn(response);
            doNothing().when(institutionalWalletService).saveConfigToFile(anyString(), anyString());
            doNothing().when(institutionalWalletService).initializeInstitutionalWallet();

            mockMvc.perform(post("/wallet/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.address").value(VALID_ADDRESS));
        }

        @Test
        @DisplayName("Should return error when password too weak")
        void shouldReturnErrorWhenPasswordTooWeak() throws Exception {
            WalletCreateRequest request = new WalletCreateRequest();
            request.setPassword("weak"); // Too short - validation will fail

            // No stubbing needed - validation fails before service is called
            mockMvc.perform(post("/wallet/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should auto-configure institutional wallet after creation")
        void shouldAutoConfigureInstitutionalWallet() throws Exception {
            WalletCreateRequest request = new WalletCreateRequest();
            request.setPassword("securePassword123");

            WalletResponse response = WalletResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .build();

            when(walletService.createWallet(anyString())).thenReturn(response);
            doNothing().when(institutionalWalletService).saveConfigToFile(anyString(), anyString());
            doNothing().when(institutionalWalletService).initializeInstitutionalWallet();

            mockMvc.perform(post("/wallet/create")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

            verify(institutionalWalletService).saveConfigToFile(VALID_ADDRESS, "securePassword123");
            verify(institutionalWalletService).initializeInstitutionalWallet();
        }
    }

    @Nested
    @DisplayName("Import Wallet Endpoint Tests")
    class ImportWalletTests {

        @Test
        @DisplayName("Should import wallet from private key")
        void shouldImportWalletFromPrivateKey() throws Exception {
            WalletImportRequest request = new WalletImportRequest();
            request.setPrivateKey("0x" + "a".repeat(64));
            request.setPassword("securePassword123");

            WalletResponse response = WalletResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .message("Imported")
                .build();

            when(walletService.importWallet(any(WalletImportRequest.class))).thenReturn(response);
            doNothing().when(institutionalWalletService).saveConfigToFile(anyString(), anyString());
            doNothing().when(institutionalWalletService).initializeInstitutionalWallet();

            mockMvc.perform(post("/wallet/import")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should import wallet from mnemonic")
        void shouldImportWalletFromMnemonic() throws Exception {
            WalletImportRequest request = new WalletImportRequest();
            request.setMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
            request.setPassword("securePassword123");

            WalletResponse response = WalletResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .build();

            when(walletService.importWallet(any(WalletImportRequest.class))).thenReturn(response);
            doNothing().when(institutionalWalletService).saveConfigToFile(anyString(), anyString());
            doNothing().when(institutionalWalletService).initializeInstitutionalWallet();

            mockMvc.perform(post("/wallet/import")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should return error for invalid private key format")
        void shouldReturnErrorForInvalidPrivateKey() throws Exception {
            WalletImportRequest request = new WalletImportRequest();
            request.setPrivateKey("invalid-key"); // Invalid format - validation will fail
            request.setPassword("password12345678");

            // No stubbing needed - validation fails before service is called
            mockMvc.perform(post("/wallet/import")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Reveal Private Key Endpoint Tests")
    class RevealPrivateKeyTests {

        @Test
        @DisplayName("Should reveal private key with correct password")
        void shouldRevealPrivateKeyWithCorrectPassword() throws Exception {
            WalletRevealRequest request = new WalletRevealRequest();
            request.setPassword("correctPassword");

            WalletResponse response = WalletResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .privateKey("0x" + "a".repeat(64))
                .build();

            when(walletService.revealInstitutionalPrivateKey("correctPassword")).thenReturn(response);

            mockMvc.perform(post("/wallet/reveal")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should reject reveal with incorrect password")
        void shouldRejectRevealWithIncorrectPassword() throws Exception {
            WalletRevealRequest request = new WalletRevealRequest();
            request.setPassword("wrongPassword");

            WalletResponse response = WalletResponse.error("Invalid password");

            when(walletService.revealInstitutionalPrivateKey("wrongPassword")).thenReturn(response);

            mockMvc.perform(post("/wallet/reveal")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
        }
    }

    @Nested
    @DisplayName("Get Balance Endpoint Tests")
    class GetBalanceTests {

        @Test
        @DisplayName("Should get balance for valid address")
        void shouldGetBalanceForValidAddress() throws Exception {
            when(rateLimitService.allowBalanceCheck(VALID_ADDRESS)).thenReturn(true);
            
            BalanceResponse response = BalanceResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .balanceEth("1.5")
                .network("mainnet")
                .build();

            when(walletService.getBalance(VALID_ADDRESS)).thenReturn(response);

            mockMvc.perform(get("/wallet/" + VALID_ADDRESS + "/balance"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.address").value(VALID_ADDRESS));
        }

        @Test
        @DisplayName("Should reject invalid address format")
        void shouldRejectInvalidAddressFormat() throws Exception {
            mockMvc.perform(get("/wallet/" + INVALID_ADDRESS + "/balance"))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should enforce rate limiting")
        void shouldEnforceRateLimiting() throws Exception {
            when(rateLimitService.allowBalanceCheck(VALID_ADDRESS)).thenReturn(false);

            mockMvc.perform(get("/wallet/" + VALID_ADDRESS + "/balance"))
                .andExpect(status().isTooManyRequests());
        }

        @Test
        @DisplayName("Should handle balance check exception")
        void shouldHandleBalanceCheckException() throws Exception {
            when(rateLimitService.allowBalanceCheck(VALID_ADDRESS)).thenReturn(true);
            when(walletService.getBalance(VALID_ADDRESS))
                .thenThrow(new RuntimeException("RPC connection failed"));

            mockMvc.perform(get("/wallet/" + VALID_ADDRESS + "/balance"))
                .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Get Transaction History Endpoint Tests")
    class GetTransactionHistoryTests {

        @Test
        @DisplayName("Should get transaction history")
        void shouldGetTransactionHistory() throws Exception {
            TransactionHistoryResponse response = TransactionHistoryResponse.builder()
                .success(true)
                .address(VALID_ADDRESS)
                .build();

            when(walletService.getTransactionHistory(VALID_ADDRESS)).thenReturn(response);

            mockMvc.perform(get("/wallet/" + VALID_ADDRESS + "/transactions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should handle transaction history error")
        void shouldHandleTransactionHistoryError() throws Exception {
            when(walletService.getTransactionHistory(anyString()))
                .thenThrow(new RuntimeException("API unavailable"));

            mockMvc.perform(get("/wallet/" + VALID_ADDRESS + "/transactions"))
                .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Event Listener Status Endpoint Tests")
    class EventListenerStatusTests {

        @Test
        @DisplayName("Should get event listener status")
        void shouldGetEventListenerStatus() throws Exception {
            EventListenerResponse response = EventListenerResponse.builder()
                .success(true)
                .contractAddress("0xContractAddress")
                .eventName("ReservationCreated")
                .network("sepolia")
                .build();

            when(walletService.getEventListenerStatus()).thenReturn(response);

            mockMvc.perform(get("/wallet/listen-events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should handle event listener status error")
        void shouldHandleEventListenerStatusError() throws Exception {
            when(walletService.getEventListenerStatus())
                .thenThrow(new RuntimeException("Event service unavailable"));

            mockMvc.perform(get("/wallet/listen-events"))
                .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Get Networks Endpoint Tests")
    class GetNetworksTests {

        @Test
        @DisplayName("Should get available networks")
        void shouldGetAvailableNetworks() throws Exception {
            NetworkResponse response = NetworkResponse.builder()
                .success(true)
                .build();

            when(walletService.getAvailableNetworks()).thenReturn(response);

            mockMvc.perform(get("/wallet/networks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
        }

        @Test
        @DisplayName("Should handle networks error")
        void shouldHandleNetworksError() throws Exception {
            when(walletService.getAvailableNetworks())
                .thenThrow(new RuntimeException("Configuration error"));

            mockMvc.perform(get("/wallet/networks"))
                .andExpect(status().isBadRequest());
        }
    }
}
