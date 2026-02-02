package decentralabs.blockchain.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.controller.wallet.WalletController;
import decentralabs.blockchain.dto.wallet.WalletCreateRequest;
import decentralabs.blockchain.dto.wallet.WalletResponse;
import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(WalletController.class)
@AutoConfigureMockMvc(addFilters = false)
public class WalletControllerIntegrationTest {

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
    public void testCreateWallet() throws Exception {
        // Given
        WalletCreateRequest request = new WalletCreateRequest();
        request.setPassword("testPassword123");

        WalletResponse mockedResponse = WalletResponse.builder()
            .success(true)
            .address("0x1234567890abcdef1234567890abcdef12345678")
            .encryptedPrivateKey("encrypted-key")
            .message("Wallet created successfully")
            .build();

        when(walletService.createWallet("testPassword123")).thenReturn(mockedResponse);

        // When
        MvcResult result = mockMvc.perform(post("/wallet/create")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.address").exists())
                .andExpect(jsonPath("$.encryptedPrivateKey").exists())
                .andReturn();

        // Then
        String responseJson = result.getResponse().getContentAsString();
        WalletResponse response = objectMapper.readValue(responseJson, WalletResponse.class);

        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getAddress()).startsWith("0x");
        assertThat(response.getAddress()).hasSize(42); // Ethereum address length
        assertThat(response.getEncryptedPrivateKey()).isNotEmpty();
        assertThat(response.getMessage()).isEqualTo("Wallet created successfully");
    }

    @Test
    public void testCreateWalletWithoutPassword() throws Exception {
        // Given - empty request

        // When & Then
        mockMvc.perform(post("/wallet/create")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }
}
