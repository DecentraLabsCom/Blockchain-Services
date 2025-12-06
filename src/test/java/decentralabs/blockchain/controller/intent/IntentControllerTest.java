package decentralabs.blockchain.controller.intent;

import static org.mockito.ArgumentMatchers.any;
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
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentStatusResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.service.intent.IntentService;

/**
 * Unit tests for IntentController.
 * Tests intent submission and status endpoints with API key validation.
 */
@ExtendWith(MockitoExtension.class)
class IntentControllerTest {

    @Mock
    private IntentService intentService;

    @InjectMocks
    private IntentController intentController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    private static final String VALID_API_KEY = "test-api-key-12345";
    private static final String INVALID_API_KEY = "invalid-key";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(intentController, "configuredApiKey", VALID_API_KEY);
        mockMvc = MockMvcBuilders.standaloneSetup(intentController).build();
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("Submit Intent Endpoint Tests")
    class SubmitIntentTests {

        @Test
        @DisplayName("Should submit intent successfully with x-api-key header")
        void shouldSubmitIntentWithApiKeyHeader() throws Exception {
            IntentSubmission submission = createValidSubmission();
            IntentAckResponse ack = createAckResponse("req-123", "QUEUED");

            when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

            mockMvc.perform(post("/intents")
                    .header("x-api-key", VALID_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("req-123"))
                .andExpect(jsonPath("$.status").value("QUEUED"));
        }

        @Test
        @DisplayName("Should submit intent successfully with Bearer token")
        void shouldSubmitIntentWithBearerToken() throws Exception {
            IntentSubmission submission = createValidSubmission();
            IntentAckResponse ack = createAckResponse("req-456", "QUEUED");

            when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

            mockMvc.perform(post("/intents")
                    .header("Authorization", "Bearer " + VALID_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("req-456"));
        }

        @Test
        @DisplayName("Should reject intent with invalid API key")
        void shouldRejectIntentWithInvalidApiKey() throws Exception {
            IntentSubmission submission = createValidSubmission();

            mockMvc.perform(post("/intents")
                    .header("x-api-key", INVALID_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should reject intent without API key when configured")
        void shouldRejectIntentWithoutApiKey() throws Exception {
            IntentSubmission submission = createValidSubmission();

            mockMvc.perform(post("/intents")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should allow intent without API key when not configured")
        void shouldAllowIntentWithoutApiKeyWhenNotConfigured() throws Exception {
            ReflectionTestUtils.setField(intentController, "configuredApiKey", "");

            IntentSubmission submission = createValidSubmission();
            IntentAckResponse ack = createAckResponse("req-789", "QUEUED");

            when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

            mockMvc.perform(post("/intents")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should accept bearer token case-insensitively")
        void shouldAcceptBearerTokenCaseInsensitively() throws Exception {
            IntentSubmission submission = createValidSubmission();
            IntentAckResponse ack = createAckResponse("req-abc", "QUEUED");

            when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

            mockMvc.perform(post("/intents")
                    .header("Authorization", "BEARER " + VALID_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Get Intent Status Endpoint Tests")
    class GetIntentStatusTests {

        @Test
        @DisplayName("Should get intent status successfully")
        void shouldGetIntentStatusSuccessfully() throws Exception {
            IntentStatusResponse statusResponse = createStatusResponse("req-123", "EXECUTED", "0xabc123");

            when(intentService.getStatus("req-123")).thenReturn(statusResponse);

            mockMvc.perform(get("/intents/req-123")
                    .header("x-api-key", VALID_API_KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("req-123"))
                .andExpect(jsonPath("$.status").value("EXECUTED"))
                .andExpect(jsonPath("$.txHash").value("0xabc123"));
        }

        @Test
        @DisplayName("Should reject status request with invalid API key")
        void shouldRejectStatusRequestWithInvalidApiKey() throws Exception {
            mockMvc.perform(get("/intents/req-123")
                    .header("x-api-key", INVALID_API_KEY))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should get status with Bearer authorization")
        void shouldGetStatusWithBearerAuthorization() throws Exception {
            IntentStatusResponse statusResponse = createStatusResponse("req-456", "QUEUED", null);

            when(intentService.getStatus("req-456")).thenReturn(statusResponse);

            mockMvc.perform(get("/intents/req-456")
                    .header("Authorization", "Bearer " + VALID_API_KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("QUEUED"));
        }

        @Test
        @DisplayName("Should return status for failed intent")
        void shouldReturnStatusForFailedIntent() throws Exception {
            IntentStatusResponse statusResponse = createStatusResponse("req-failed", "FAILED", null);
            statusResponse.setError("Insufficient balance");

            when(intentService.getStatus("req-failed")).thenReturn(statusResponse);

            mockMvc.perform(get("/intents/req-failed")
                    .header("x-api-key", VALID_API_KEY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.error").value("Insufficient balance"));
        }
    }

    @Nested
    @DisplayName("API Key Validation Tests")
    class ApiKeyValidationTests {

        @Test
        @DisplayName("Should reject invalid bearer format")
        void shouldRejectInvalidBearerFormat() throws Exception {
            IntentSubmission submission = createValidSubmission();

            mockMvc.perform(post("/intents")
                    .header("Authorization", "Basic " + VALID_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("Should handle null API key configuration")
        void shouldHandleNullApiKeyConfiguration() throws Exception {
            ReflectionTestUtils.setField(intentController, "configuredApiKey", null);

            IntentSubmission submission = createValidSubmission();
            IntentAckResponse ack = createAckResponse("req-null", "QUEUED");

            when(intentService.processIntent(any(IntentSubmission.class))).thenReturn(ack);

            mockMvc.perform(post("/intents")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(submission)))
                .andExpect(status().isOk());
        }
    }

    private IntentSubmission createValidSubmission() {
        IntentSubmission submission = new IntentSubmission();
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("0x" + "a".repeat(64)); // bytes32 hex
        meta.setSigner("0x" + "1".repeat(40)); // address
        meta.setExecutor("0x" + "1".repeat(40)); // address
        meta.setAction(1); // uint8
        meta.setPayloadHash("0x" + "b".repeat(64)); // bytes32 hex
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
