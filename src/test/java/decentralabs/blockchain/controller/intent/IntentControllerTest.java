package decentralabs.blockchain.controller.intent;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentStatusResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.intent.IntentAuthService;
import decentralabs.blockchain.service.intent.IntentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests for IntentController.
 * Tests intent submission JWT validation and status responses.
 */
@ExtendWith(MockitoExtension.class)
class IntentControllerTest {

    @Mock
    private IntentService intentService;

    @Mock
    private IntentAuthService intentAuthService;

    @InjectMocks
    private IntentController intentController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final String VALID_BEARER = "Bearer test-token";

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(intentController).build();
        objectMapper = new ObjectMapper();
        doNothing().when(intentAuthService).enforceSubmitAuthorization(any());
        doNothing().when(intentAuthService).enforceStatusAuthorization(any());
    }

    @Nested
    @DisplayName("Submit Intent Endpoint Tests")
    class SubmitIntentTests {

        @Test
        @DisplayName("Should submit intent successfully with Bearer token")
        void shouldSubmitIntentWithBearerToken() throws Exception {
            IntentSubmission submission = createValidSubmission();
            IntentAckResponse ack = createAckResponse("req-123", "QUEUED");

            when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

            mockMvc.perform(post("/intents")
                    .header("Authorization", VALID_BEARER)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("req-123"))
                .andExpect(jsonPath("$.status").value("QUEUED"));
        }

        @Test
        @DisplayName("Should reject intent without Authorization")
        void shouldRejectIntentWithoutAuthorization() throws Exception {
            IntentSubmission submission = createValidSubmission();

            doThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED))
                .when(intentAuthService).enforceSubmitAuthorization(eq(null));

            mockMvc.perform(post("/intents")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("Get Intent Status Endpoint Tests")
    class GetIntentStatusTests {

        @Test
        @DisplayName("Should get intent status successfully with Bearer token")
        void shouldGetIntentStatusSuccessfullyWithBearerToken() throws Exception {
            IntentStatusResponse statusResponse = createStatusResponse("req-123", "EXECUTED", "0xabc123");

            when(intentService.getStatus("req-123")).thenReturn(statusResponse);

            mockMvc.perform(get("/intents/req-123")
                    .header("Authorization", VALID_BEARER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("req-123"))
                .andExpect(jsonPath("$.status").value("EXECUTED"))
                .andExpect(jsonPath("$.txHash").value("0xabc123"));
        }

        @Test
        @DisplayName("Should reject status request without Authorization")
        void shouldRejectStatusRequestWithoutAuthorization() throws Exception {
            doThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED))
                .when(intentAuthService).enforceStatusAuthorization(eq(null));

            mockMvc.perform(get("/intents/req-123"))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should return status for failed intent")
        void shouldReturnStatusForFailedIntent() throws Exception {
            IntentStatusResponse statusResponse = createStatusResponse("req-failed", "FAILED", null);
            statusResponse.setError("Insufficient balance");

            when(intentService.getStatus("req-failed")).thenReturn(statusResponse);

            mockMvc.perform(get("/intents/req-failed")
                    .header("Authorization", VALID_BEARER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.error").value("Insufficient balance"));
        }
    }

    private IntentSubmission createValidSubmission() {
        IntentSubmission submission = new IntentSubmission();
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("0x" + "a".repeat(64));
        meta.setSigner("0x" + "1".repeat(40));
        meta.setExecutor("0x" + "1".repeat(40));
        meta.setAction(1);
        meta.setPayloadHash("0x" + "b".repeat(64));
        meta.setNonce(1L);
        meta.setRequestedAt(System.currentTimeMillis());
        meta.setExpiresAt(System.currentTimeMillis() + 3600000L);
        submission.setMeta(meta);
        submission.setSignature("0x" + "a".repeat(130));
        submission.setSamlAssertion("base64-saml-assertion");
        submission.setWebauthnCredentialId("credential-id-123");
        submission.setWebauthnClientDataJSON("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=");
        submission.setWebauthnAuthenticatorData("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAABBA==");
        submission.setWebauthnSignature("MEUCIQDf1234567890abcdef==");
        return submission;
    }

    private IntentAckResponse createAckResponse(String requestId, String status) {
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId(requestId);
        ack.setStatus(status);
        return ack;
    }

    private IntentStatusResponse createStatusResponse(String requestId, String status, String txHash) {
        IntentStatusResponse response = new IntentStatusResponse();
        response.setRequestId(requestId);
        response.setStatus(status);
        response.setTxHash(txHash);
        return response;
    }
}
