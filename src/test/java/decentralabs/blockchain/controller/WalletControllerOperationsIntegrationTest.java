package decentralabs.blockchain.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.controller.wallet.WalletController;
import decentralabs.blockchain.dto.wallet.BalanceResponse;
import decentralabs.blockchain.dto.wallet.EventListenerResponse;
import decentralabs.blockchain.dto.wallet.NetworkInfo;
import decentralabs.blockchain.dto.wallet.NetworkResponse;
import decentralabs.blockchain.dto.wallet.NetworkSwitchRequest;
import decentralabs.blockchain.dto.wallet.TransactionHistoryResponse;
import decentralabs.blockchain.dto.wallet.WalletImportRequest;
import decentralabs.blockchain.dto.wallet.WalletResponse;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = WalletController.class)
@Import(TestSecurityConfig.class)
@WithMockUser
class WalletControllerOperationsIntegrationTest {

    private static final String VALID_ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private WalletService walletService;

    @MockitoBean
    private RateLimitService rateLimitService;

    @MockitoBean
    private InstitutionalWalletService institutionalWalletService;

    @Test
    void shouldReturnBalanceForValidAddress() throws Exception {
        when(rateLimitService.allowBalanceCheck(VALID_ADDRESS)).thenReturn(true);
        BalanceResponse response = BalanceResponse.builder()
            .success(true)
            .address(VALID_ADDRESS)
            .balanceWei("1000000000000000000")
            .balanceEth("1")
            .network("sepolia")
            .build();
        when(walletService.getBalance(VALID_ADDRESS)).thenReturn(response);

        mockMvc.perform(get("/wallet/{address}/balance", VALID_ADDRESS))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.address").value(VALID_ADDRESS))
            .andExpect(jsonPath("$.balanceEth").value("1"));

        verify(walletService).getBalance(VALID_ADDRESS);
    }

    @Test
    void shouldRejectInvalidAddresses() throws Exception {
        mockMvc.perform(get("/wallet/{address}/balance", "invalid-address"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.success").value(false));

        verifyNoInteractions(walletService);
    }

    @Test
    void shouldReturnTooManyRequestsWhenRateLimited() throws Exception {
        when(rateLimitService.allowBalanceCheck(VALID_ADDRESS)).thenReturn(false);

        mockMvc.perform(get("/wallet/{address}/balance", VALID_ADDRESS))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.success").value(false));

        verify(walletService, never()).getBalance(any());
    }

    @Test
    void shouldImportWalletWithPrivateKey() throws Exception {
        WalletImportRequest request = WalletImportRequest.builder()
            .privateKey("0x1111111111111111111111111111111111111111111111111111111111111111")
            .password("superSecret8")
            .build();
        WalletResponse response = WalletResponse.builder()
            .success(true)
            .address(VALID_ADDRESS)
            .encryptedPrivateKey("enc")
            .message("Wallet imported successfully")
            .build();
        when(walletService.importWallet(any(WalletImportRequest.class))).thenReturn(response);

        mockMvc.perform(post("/wallet/import")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.address").value(VALID_ADDRESS))
            .andExpect(jsonPath("$.message").value("Wallet imported successfully"));
    }

    @Test
    void shouldReturnTransactionHistory() throws Exception {
        TransactionHistoryResponse response = TransactionHistoryResponse.builder()
            .success(true)
            .address(VALID_ADDRESS)
            .transactionCount("0")
            .transactions(List.of())
            .network("sepolia")
            .build();
        when(walletService.getTransactionHistory(VALID_ADDRESS)).thenReturn(response);

        mockMvc.perform(get("/wallet/{address}/transactions", VALID_ADDRESS))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.address").value(VALID_ADDRESS));
    }

    @Test
    void shouldExposeEventListenerStatus() throws Exception {
        EventListenerResponse response = EventListenerResponse.builder()
            .success(true)
            .contractAddress("0x123")
            .network("sepolia")
            .message("ready")
            .build();
        when(walletService.getEventListenerStatus()).thenReturn(response);

        mockMvc.perform(get("/wallet/listen-events"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.message").value("ready"));
    }

    @Test
    void shouldListNetworks() throws Exception {
        NetworkResponse response = NetworkResponse.builder()
            .success(true)
            .activeNetwork("sepolia")
            .networks(List.of(
                new NetworkInfo("sepolia", "Sepolia", "https://rpc", 11155111)
            ))
            .build();
        when(walletService.getAvailableNetworks()).thenReturn(response);

        mockMvc.perform(get("/wallet/networks"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.activeNetwork").value("sepolia"));
    }

    @Test
    void shouldSwitchNetworks() throws Exception {
        NetworkSwitchRequest request = new NetworkSwitchRequest("goerli");
        NetworkResponse response = NetworkResponse.builder()
            .success(true)
            .activeNetwork("goerli")
            .networks(List.of())
            .build();
        when(walletService.switchNetwork(eq("goerli"))).thenReturn(response);

        mockMvc.perform(post("/wallet/switch-network")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.activeNetwork").value("goerli"));
    }
}
