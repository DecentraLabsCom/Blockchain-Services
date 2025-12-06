package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
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

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.service.auth.SamlAuthService;

/**
 * Unit tests for SamlAuthController.
 * Tests SAML authentication endpoints with various scenarios.
 */
@ExtendWith(MockitoExtension.class)
class SamlAuthControllerTest {

    @Mock
    private SamlAuthService samlAuthService;

    @InjectMocks
    private SamlAuthController samlAuthController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(samlAuthController).build();
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("SAML Auth Endpoint Tests")
    class SamlAuthTests {

        @Test
        @DisplayName("Should authenticate successfully with valid SAML request")
        void shouldAuthenticateWithValidSamlRequest() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            AuthResponse response = new AuthResponse("valid-jwt-token");

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(false)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/saml-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("valid-jwt-token"));
        }

        @Test
        @DisplayName("Should return 400 for invalid request")
        void shouldReturn400ForInvalidRequest() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(false)))
                .thenThrow(new IllegalArgumentException("Invalid SAML assertion format"));

            mockMvc.perform(post("/auth/saml-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid SAML assertion format"));
        }

        @Test
        @DisplayName("Should return 401 for security exception")
        void shouldReturn401ForSecurityException() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(false)))
                .thenThrow(new SecurityException("SAML assertion expired"));

            mockMvc.perform(post("/auth/saml-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("SAML assertion expired"));
        }

        @Test
        @DisplayName("Should return 500 for unexpected error")
        void shouldReturn500ForUnexpectedError() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(false)))
                .thenThrow(new RuntimeException("Database connection failed"));

            mockMvc.perform(post("/auth/saml-auth")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Internal server error"));
        }
    }

    @Nested
    @DisplayName("SAML Auth2 Endpoint Tests")
    class SamlAuth2Tests {

        @Test
        @DisplayName("Should authenticate with booking info successfully")
        void shouldAuthenticateWithBookingInfo() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            request.setLabId("lab-123");
            AuthResponse response = new AuthResponse("jwt-with-booking", "https://lab.example.com");

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/saml-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-with-booking"))
                .andExpect(jsonPath("$.labURL").value("https://lab.example.com"));
        }

        @Test
        @DisplayName("Should authenticate with reservation key")
        void shouldAuthenticateWithReservationKey() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            AuthResponse response = new AuthResponse("jwt-with-reservation", "https://lab2.example.com");

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/saml-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-with-reservation"));
        }

        @Test
        @DisplayName("Should return 400 for missing booking info")
        void shouldReturn400ForMissingBookingInfo() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            // No labId or reservationKey set

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
                .thenThrow(new IllegalArgumentException("labId or reservationKey is required"));

            mockMvc.perform(post("/auth/saml-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("labId or reservationKey is required"));
        }

        @Test
        @DisplayName("Should return 401 for invalid booking")
        void shouldReturn401ForInvalidBooking() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            request.setLabId("invalid-lab");

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
                .thenThrow(new SecurityException("No valid booking found for user"));

            mockMvc.perform(post("/auth/saml-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("No valid booking found for user"));
        }

        @Test
        @DisplayName("Should return 500 for internal error in booking flow")
        void shouldReturn500ForInternalError() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            request.setLabId("lab-123");

            when(samlAuthService.handleAuthentication(any(SamlAuthRequest.class), eq(true)))
                .thenThrow(new RuntimeException("Blockchain unavailable"));

            mockMvc.perform(post("/auth/saml-auth2")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Internal server error"));
        }
    }

    private SamlAuthRequest createValidSamlRequest() {
        SamlAuthRequest request = new SamlAuthRequest();
        request.setMarketplaceToken("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxOTk5OTk5OTk5fQ.signature");
        request.setSamlAssertion("PHNhbWxwOlJlc3BvbnNlPi4uLjwvc2FtbHA6UmVzcG9uc2U+");
        request.setTimestamp(System.currentTimeMillis());
        return request;
    }
}
