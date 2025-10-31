package decentralabs.blockchain.controller;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.dto.WalletCreateRequest;
import decentralabs.blockchain.dto.WalletResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@AutoConfigureWebMvc
public class WalletControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    public void testCreateWallet() throws Exception {
        // Given
        WalletCreateRequest request = new WalletCreateRequest();
        request.setPassword("testPassword123");

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