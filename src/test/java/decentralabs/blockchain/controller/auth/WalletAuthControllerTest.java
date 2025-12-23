package decentralabs.blockchain.controller.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.WalletAuthRequest;
import decentralabs.blockchain.service.auth.CheckInOnChainService;
import decentralabs.blockchain.service.auth.WalletAuthService;

/**
 * Unit tests for WalletAuthController.
 * Tests wallet-based authentication endpoints.
 */
@ExtendWith(MockitoExtension.class)
class WalletAuthControllerTest {

    @Mock
    private WalletAuthService walletAuthService;

    @Mock
    private CheckInOnChainService checkInOnChainService;

    @InjectMocks
    private WalletAuthController walletAuthController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(walletAuthController).build();
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("Get Message Endpoint Tests")
    class GetMessageTests {

        @Test
        @DisplayName("Should return message with timestamp")
        void shouldReturnMessageWithTimestamp() throws Exception {
            mockMvc.perform(get("/auth/message"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
        }

        @Test
        @DisplayName("Should return message containing Login request prefix")
        void shouldReturnMessageWithLoginPrefix() throws Exception {
            MvcResult result = mockMvc.perform(get("/auth/message"))
                .andExpect(status().isOk())
                .andReturn();

            String content = result.getResponse().getContentAsString();
            assertThat(content).contains("Login request:");
        }

        @Test
        @DisplayName("Should return numeric timestamp")
        void shouldReturnNumericTimestamp() throws Exception {
            MvcResult result = mockMvc.perform(get("/auth/message"))
                .andExpect(status().isOk())
                .andReturn();

            String content = result.getResponse().getContentAsString();
            assertThat(content).containsPattern("\"timestamp\"\\s*:\\s*\"\\d+\"");
        }

        @Test
        @DisplayName("Should return typed data for check-in purpose")
        void shouldReturnCheckInTypedData() throws Exception {
            mockMvc.perform(get("/auth/message")
                    .param("purpose", "checkin")
                    .param("reservationKey", "0xabc")
                    .param("signer", "0x1234567890123456789012345678901234567890"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.purpose").value("checkin"))
                .andExpect(jsonPath("$.typedData").exists())
                .andExpect(jsonPath("$.typedData.message.reservationKey").exists());
        }

        @Test
        @DisplayName("Should return 400 when reservationKey is missing for check-in")
        void shouldReturn400WhenReservationKeyMissing() throws Exception {
            mockMvc.perform(get("/auth/message")
                    .param("purpose", "checkin")
                    .param("signer", "0x1234567890123456789012345678901234567890"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Missing reservationKey"));
        }

        @Test
        @DisplayName("Should return 400 when signer is missing for check-in")
        void shouldReturn400WhenSignerMissing() throws Exception {
            mockMvc.perform(get("/auth/message")
                    .param("purpose", "checkin")
                    .param("reservationKey", "0xabc"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Missing signer"));
        }
    }

    @Nested
    @DisplayName("Wallet Auth Endpoint Tests")
    class WalletAuthTests {

        @Test
        @DisplayName("Should authenticate wallet successfully")
        void shouldAuthenticateWalletSuccessfully() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");
            request.setSignature("0xSignature");

            AuthResponse authResponse = new AuthResponse("jwt-token-here");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(false)))
                .thenReturn(authResponse);

            mockMvc.perform(post("/auth/wallet-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should return 400 for invalid request")
        void shouldReturn400ForInvalidRequest() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("invalid-address");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(false)))
                .thenThrow(new IllegalArgumentException("Invalid wallet address"));

            mockMvc.perform(post("/auth/wallet-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should return 401 for invalid signature")
        void shouldReturn401ForInvalidSignature() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");
            request.setSignature("invalid-signature");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(false)))
                .thenThrow(new SecurityException("Invalid signature"));

            mockMvc.perform(post("/auth/wallet-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should return 500 for unexpected error")
        void shouldReturn500ForUnexpectedError() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(false)))
                .thenThrow(new RuntimeException("Unexpected error"));

            mockMvc.perform(post("/auth/wallet-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError());
        }
    }

    @Nested
    @DisplayName("Wallet Auth2 Endpoint Tests")
    class WalletAuth2Tests {

        @Test
        @DisplayName("Should authenticate with booking info successfully")
        void shouldAuthenticateWithBookingInfoSuccessfully() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");
            request.setSignature("0xSignature");
            request.setLabId("lab-001");

            AuthResponse authResponse = new AuthResponse("jwt-token", "https://lab.example.com");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
                .thenReturn(authResponse);

            mockMvc.perform(post("/auth/wallet-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should return 400 when labId is missing")
        void shouldReturn400WhenLabIdMissing() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
                .thenThrow(new IllegalArgumentException("labId or reservationKey required"));

            mockMvc.perform(post("/auth/wallet-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should authenticate with reservationKey")
        void shouldAuthenticateWithReservationKey() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");
            request.setSignature("0xSignature");
            request.setReservationKey("0x" + "a".repeat(64));

            AuthResponse authResponse = new AuthResponse("jwt-token");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
                .thenReturn(authResponse);

            mockMvc.perform(post("/auth/wallet-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should return 401 for unauthorized booking access")
        void shouldReturn401ForUnauthorizedBookingAccess() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");
            request.setLabId("lab-001");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
                .thenThrow(new SecurityException("No active booking for this lab"));

            mockMvc.perform(post("/auth/wallet-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should return 500 for internal error")
        void shouldReturn500ForInternalError() throws Exception {
            WalletAuthRequest request = new WalletAuthRequest();
            request.setWallet("0x1234567890123456789012345678901234567890");
            request.setLabId("lab-001");

            when(walletAuthService.handleAuthentication(any(WalletAuthRequest.class), eq(true)))
                .thenThrow(new RuntimeException("Database error"));

            mockMvc.perform(post("/auth/wallet-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError());
        }
    }

    @Nested
    @DisplayName("Check-in Endpoint Tests")
    class CheckInEndpointTests {

        @Test
        @DisplayName("Should accept valid check-in request")
        void shouldAcceptValidCheckIn() throws Exception {
            CheckInRequest request = new CheckInRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            request.setSigner("0x1234567890123456789012345678901234567890");
            request.setSignature("0xSignature");
            request.setTimestamp(1700000000L);

            CheckInResponse response = new CheckInResponse();
            response.setValid(true);

            when(checkInOnChainService.verifyAndSubmit(any(CheckInRequest.class)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/checkin")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
        }

        @Test
        @DisplayName("Should return 400 for invalid check-in request")
        void shouldReturn400ForInvalidCheckIn() throws Exception {
            CheckInRequest request = new CheckInRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            request.setSigner("0x1234567890123456789012345678901234567890");

            when(checkInOnChainService.verifyAndSubmit(any(CheckInRequest.class)))
                .thenThrow(new IllegalArgumentException("Missing signature"));

            mockMvc.perform(post("/auth/checkin")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("Missing signature"));
        }

        @Test
        @DisplayName("Should return 401 for unauthorized check-in")
        void shouldReturn401ForUnauthorizedCheckIn() throws Exception {
            CheckInRequest request = new CheckInRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            request.setSigner("0x1234567890123456789012345678901234567890");

            when(checkInOnChainService.verifyAndSubmit(any(CheckInRequest.class)))
                .thenThrow(new SecurityException("Signature mismatch"));

            mockMvc.perform(post("/auth/checkin")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("Signature mismatch"));
        }
    }
}
