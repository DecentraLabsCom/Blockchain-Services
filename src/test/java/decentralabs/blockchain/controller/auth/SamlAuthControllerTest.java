package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.AccessAuthorizationPendingException;
import decentralabs.blockchain.exception.AccessAuthorizationRejectedException;
import decentralabs.blockchain.exception.SamlAuthControllerAdvice;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.SamlAuthService;

/**
 * Unit tests for SamlAuthController.
 * Tests SAML authentication endpoints with various scenarios.
 */
@ExtendWith(MockitoExtension.class)
class SamlAuthControllerTest {

    @Mock
    private SamlAuthService samlAuthService;

    @Mock
    private InstitutionalCheckInService institutionalCheckInService;

    @InjectMocks
    private SamlAuthController samlAuthController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(samlAuthController)
            .setControllerAdvice(new SamlAuthControllerAdvice())
            .build();
        objectMapper = new ObjectMapper();
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

            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/authorize-and-issue")
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

            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/authorize-and-issue")
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

            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenThrow(new IllegalArgumentException("labId or reservationKey is required"));

            mockMvc.perform(post("/auth/authorize-and-issue")
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

            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenThrow(new SecurityException("No valid booking found for user"));

            mockMvc.perform(post("/auth/authorize-and-issue")
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

            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenThrow(new RuntimeException("Blockchain unavailable"));

            mockMvc.perform(post("/auth/authorize-and-issue")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").value("Internal server error"));
        }

        @Test
        @DisplayName("Should return retryable 503 while authorization is pending")
        void shouldReturnRetryablePendingResponse() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenThrow(new AccessAuthorizationPendingException(
                    "Access authorization was not confirmed on-chain within 27000 ms",
                    request.getReservationKey(),
                    "0x" + "b".repeat(64)
                ));

            mockMvc.perform(post("/auth/authorize-and-issue")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "1"))
                .andExpect(jsonPath("$.error").value("ACCESS_AUTHORIZATION_PENDING"))
                .andExpect(jsonPath("$.retryable").value(true))
                .andExpect(jsonPath("$.reservationKey").value(request.getReservationKey()));
        }

        @Test
        @DisplayName("Should return non-retryable conflict when authorization transaction reverts")
        void shouldReturnRejectedResponse() throws Exception {
            SamlAuthRequest request = createValidSamlRequest();
            when(samlAuthService.authorizeAndIssue(any(SamlAuthRequest.class)))
                .thenThrow(new AccessAuthorizationRejectedException("Access authorization transaction reverted on-chain"));

            mockMvc.perform(post("/auth/authorize-and-issue")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("ACCESS_AUTHORIZATION_REJECTED"))
                .andExpect(jsonPath("$.retryable").value(false));
        }
    }

    @Nested
    @DisplayName("Institutional Check-In Endpoint Tests")
    class InstitutionalCheckInTests {

        @Test
        @DisplayName("Should accept institutional check-in")
        void shouldAcceptInstitutionalCheckIn() throws Exception {
            InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            request.setSamlAssertion("assertion");

            CheckInResponse response = new CheckInResponse();
            response.setValid(true);

            when(institutionalCheckInService.checkIn(any(InstitutionalCheckInRequest.class)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/checkin-institutional")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
        }

        @Test
        @DisplayName("Should return 400 for invalid institutional check-in")
        void shouldReturn400ForInvalidInstitutionalCheckIn() throws Exception {
            InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            request.setSamlAssertion("assertion");

            when(institutionalCheckInService.checkIn(any(InstitutionalCheckInRequest.class)))
                .thenThrow(new IllegalArgumentException("Missing samlAssertion"));

            mockMvc.perform(post("/auth/checkin-institutional")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("Missing samlAssertion"));
        }

        @Test
        @DisplayName("Should return 401 for unauthorized institutional check-in")
        void shouldReturn401ForUnauthorizedInstitutionalCheckIn() throws Exception {
            InstitutionalCheckInRequest request = new InstitutionalCheckInRequest();
            request.setReservationKey("0x" + "a".repeat(64));
            request.setSamlAssertion("assertion");

            when(institutionalCheckInService.checkIn(any(InstitutionalCheckInRequest.class)))
                .thenThrow(new SecurityException("Invalid SAML assertion"));

            mockMvc.perform(post("/auth/checkin-institutional")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("Invalid SAML assertion"));
        }
    }

    @Nested
    @DisplayName("Provider Access Credential Endpoint Tests")
    class ProviderAccessCredentialTests {

        @Test
        @DisplayName("Should issue provider access credential")
        void shouldIssueProviderAccessCredential() throws Exception {
            ProviderAccessCredentialRequest request = new ProviderAccessCredentialRequest();
            request.setMarketplaceToken("marketplace-token");
            request.setReservationKey("0x" + "a".repeat(64));

            AuthResponse response = AuthResponse.opaqueAccess(
                "opaque-code", "https://lab.example.com/fmu/", "fmu", "0xcanonical"
            );
            when(samlAuthService.issueAccessCredential(any(ProviderAccessCredentialRequest.class)))
                .thenReturn(response);

            mockMvc.perform(post("/auth/access-credential")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(jsonPath("$.accessCode").value("opaque-code"))
                .andExpect(jsonPath("$.labURL").value("https://lab.example.com/fmu/"))
                .andExpect(jsonPath("$.resourceType").value("fmu"))
                .andExpect(jsonPath("$.reservationKey").value("0xcanonical"));
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
