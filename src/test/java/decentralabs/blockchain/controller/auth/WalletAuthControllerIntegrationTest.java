package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.WalletAuthRequest;
import decentralabs.blockchain.service.auth.CheckInOnChainService;
import decentralabs.blockchain.service.auth.WalletAuthService;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;

@WebMvcTest(controllers = WalletAuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class WalletAuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private WalletAuthService walletAuthService;

    @MockitoBean
    private CheckInOnChainService checkInOnChainService;

    @MockitoBean
    private BlockchainBookingService blockchainBookingService;

    @Test
    void shouldReturnLoginMessage() throws Exception {
        mockMvc.perform(get("/auth/message"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.purpose").value("login"))
            .andExpect(jsonPath("$.message").exists())
            .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void shouldReturnCheckInTypedData() throws Exception {
        mockMvc.perform(get("/auth/message")
                .param("purpose", "checkin")
                .param("reservationKey", "0x" + "a".repeat(64))
                .param("signer", "0x1234567890123456789012345678901234567890"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.purpose").value("checkin"))
            .andExpect(jsonPath("$.typedData.message.reservationKey").exists());
    }

    @Test
    void shouldReturnCheckInTypedDataFromLabId() throws Exception {
        String resolvedKey = "0x" + "b".repeat(64);

        when(blockchainBookingService.resolveActiveReservationKeyHex(
            eq("0x1234567890123456789012345678901234567890"),
            eq("10"),
            eq(null)
        )).thenReturn(resolvedKey);

        mockMvc.perform(get("/auth/message")
                .param("purpose", "checkin")
                .param("labId", "10")
                .param("signer", "0x1234567890123456789012345678901234567890"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.reservationKey").value(resolvedKey))
            .andExpect(jsonPath("$.typedData.message.reservationKey").value(resolvedKey));
    }

    @Test
    void shouldAuthenticateWallet() throws Exception {
        WalletAuthRequest request = new WalletAuthRequest();
        request.setWallet("0x1234567890123456789012345678901234567890");
        request.setSignature("0xSignature");

        when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(false)))
            .thenReturn(new AuthResponse("jwt-token"));

        mockMvc.perform(post("/auth/wallet-auth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-token"));
    }

    @Test
    void shouldAuthenticateWalletWithLabId() throws Exception {
        WalletAuthRequest request = new WalletAuthRequest();
        request.setWallet("0x1234567890123456789012345678901234567890");
        request.setSignature("0xSignature");
        request.setLabId("lab-001");

        when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
            .thenReturn(new AuthResponse("jwt-token", "https://lab.example.com"));

        mockMvc.perform(post("/auth/wallet-auth2")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-token"))
            .andExpect(jsonPath("$.labURL").value("https://lab.example.com"));
    }

    @Test
    void shouldAuthenticateWalletWithReservationKey() throws Exception {
        WalletAuthRequest request = new WalletAuthRequest();
        request.setWallet("0x1234567890123456789012345678901234567890");
        request.setSignature("0xSignature");
        request.setReservationKey("0x" + "a".repeat(64));

        when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
            .thenReturn(new AuthResponse("jwt-token"));

        mockMvc.perform(post("/auth/wallet-auth2")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("jwt-token"));
    }

    @Test
    void shouldAcceptCheckIn() throws Exception {
        CheckInRequest request = new CheckInRequest();
        request.setReservationKey("0x" + "a".repeat(64));
        request.setSigner("0x1234567890123456789012345678901234567890");
        request.setSignature("0xSignature");
        request.setTimestamp(1700000000L);

        CheckInResponse response = new CheckInResponse();
        response.setValid(true);
        response.setTxHash("0xabc123");

        when(checkInOnChainService.verifyAndSubmit(any(CheckInRequest.class)))
            .thenReturn(response);

        mockMvc.perform(post("/auth/checkin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(true))
            .andExpect(jsonPath("$.txHash").value("0xabc123"));
    }
}
