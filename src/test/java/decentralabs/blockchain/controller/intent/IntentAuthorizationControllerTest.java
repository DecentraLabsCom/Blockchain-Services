package decentralabs.blockchain.controller.intent;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentAuthorizationCompleteRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationStatusResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.exception.GlobalExceptionHandler;
import decentralabs.blockchain.service.intent.IntentAuthService;
import decentralabs.blockchain.service.intent.IntentAuthorizationService;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class IntentAuthorizationControllerTest {

    @Mock
    private IntentAuthorizationService authorizationService;

    @Mock
    private IntentAuthService intentAuthService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        IntentAuthorizationController controller = new IntentAuthorizationController(authorizationService, intentAuthService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
        objectMapper = new ObjectMapper();
    }

    @Test
    void authorizeIntent_returnsSessionPayload() throws Exception {
        IntentAuthorizationRequest request = validAuthorizationRequest();
        IntentAuthorizationService.AuthorizationSession session = session("session-123", "request-123", Instant.parse("2026-03-11T10:00:00Z"));

        doNothing().when(intentAuthService).enforceSubmitAuthorization("Bearer jwt");
        when(authorizationService.createSession(any(IntentAuthorizationRequest.class))).thenReturn(session);
        when(authorizationService.buildCeremonyUrl("session-123")).thenReturn("https://backend/intents/authorize/ceremony/session-123");

        mockMvc.perform(post("/intents/authorize")
                .header("Authorization", "Bearer jwt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionId").value("session-123"))
            .andExpect(jsonPath("$.ceremonyUrl").value("https://backend/intents/authorize/ceremony/session-123"))
            .andExpect(jsonPath("$.requestId").value("request-123"))
            .andExpect(jsonPath("$.expiresAt").value("2026-03-11T10:00:00Z"));

        verify(intentAuthService).enforceSubmitAuthorization("Bearer jwt");
        verify(authorizationService).createSession(any(IntentAuthorizationRequest.class));
        verify(authorizationService).buildCeremonyUrl("session-123");
    }

    @Test
    void authorizeIntent_rejectsInvalidRequestBody() throws Exception {
        String invalidRequest = """
            {"signature":"sig","samlAssertion":"assertion"}
            """;

        mockMvc.perform(post("/intents/authorize")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidRequest))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Validation failed"))
            .andExpect(jsonPath("$.errors.meta").exists());

        verify(intentAuthService, never()).enforceSubmitAuthorization(any());
        verify(authorizationService, never()).createSession(any());
    }

    @Test
    void getStatus_returnsControllerPayload() throws Exception {
        IntentAuthorizationStatusResponse response = IntentAuthorizationStatusResponse.builder()
            .sessionId("session-123")
            .requestId("request-123")
            .status("PENDING")
            .build();

        doNothing().when(intentAuthService).enforceStatusAuthorization("Bearer jwt");
        when(authorizationService.getStatus("session-123")).thenReturn(response);

        mockMvc.perform(get("/intents/authorize/status/session-123")
                .header("Authorization", "Bearer jwt"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionId").value("session-123"))
            .andExpect(jsonPath("$.requestId").value("request-123"))
            .andExpect(jsonPath("$.status").value("PENDING"));

        verify(intentAuthService).enforceStatusAuthorization("Bearer jwt");
        verify(authorizationService).getStatus("session-123");
    }

    @Test
    void getStatus_translatesResponseStatusException() throws Exception {
        doNothing().when(intentAuthService).enforceStatusAuthorization("Bearer jwt");
        when(authorizationService.getStatus("missing"))
            .thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found"));

        mockMvc.perform(get("/intents/authorize/status/missing")
                .header("Authorization", "Bearer jwt"))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.message").value("Session not found"))
            .andExpect(jsonPath("$.status").value(404));
    }

    @Test
    void getCeremonyPage_returnsHtmlWithSessionData() throws Exception {
        IntentAuthorizationService.AuthorizationSession session = session("session-abc", "request-xyz", Instant.parse("2026-03-11T10:00:00Z"));
        session.setChallenge("challenge-b64");
        session.setCredentialIds(List.of("cred-1", "cred-2"));
        session.setReturnUrl("https://app.example/callback");

        when(authorizationService.getSession("session-abc")).thenReturn(session);
        when(authorizationService.getRelyingPartyId()).thenReturn("example.com");

        mockMvc.perform(get("/intents/authorize/ceremony/session-abc"))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Authorize Intent")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("\"sessionId\":\"session-abc\"")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("\"requestId\":\"request-xyz\"")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("\"allowCredentials\":[\"cred-1\",\"cred-2\"]")))
            .andExpect(content().string(org.hamcrest.Matchers.containsString("\"rpId\":\"example.com\"")));
    }

    @Test
    void completeAuthorization_returnsAckPayload() throws Exception {
        IntentAuthorizationCompleteRequest request = validCompleteRequest();
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId("request-123");
        ack.setStatus("accepted");

        when(authorizationService.completeAuthorization(any(IntentAuthorizationCompleteRequest.class))).thenReturn(ack);

        mockMvc.perform(post("/intents/authorize/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.requestId").value("request-123"))
            .andExpect(jsonPath("$.status").value("accepted"));
    }

    @Test
    void completeAuthorization_rejectsInvalidCeremonyState() throws Exception {
        IntentAuthorizationCompleteRequest request = validCompleteRequest();
        when(authorizationService.completeAuthorization(any(IntentAuthorizationCompleteRequest.class)))
            .thenThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired session"));

        mockMvc.perform(post("/intents/authorize/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Invalid or expired session"))
            .andExpect(jsonPath("$.status").value(400));
    }

    private IntentAuthorizationRequest validAuthorizationRequest() {
        IntentAuthorizationRequest request = new IntentAuthorizationRequest();
        request.setMeta(validMeta());
        request.setActionPayload(validActionPayload());
        request.setSignature("0xsig");
        request.setSamlAssertion("assertion");
        request.setReturnUrl("https://app.example/callback");
        return request;
    }

    private IntentAuthorizationCompleteRequest validCompleteRequest() {
        IntentAuthorizationCompleteRequest request = new IntentAuthorizationCompleteRequest();
        request.setSessionId("session-123");
        request.setCredentialId("cred-1");
        request.setClientDataJSON("client-data");
        request.setAuthenticatorData("auth-data");
        request.setSignature("signature");
        return request;
    }

    private IntentMeta validMeta() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("request-123");
        meta.setSigner("0xsigner");
        meta.setExecutor("0xexecutor");
        meta.setAction(3);
        meta.setPayloadHash("0xpayload");
        meta.setNonce(7L);
        meta.setRequestedAt(100L);
        meta.setExpiresAt(200L);
        return meta;
    }

    private ActionIntentPayload validActionPayload() {
        ActionIntentPayload payload = new ActionIntentPayload();
        payload.setExecutor("0xexecutor");
        payload.setPuc("user@example.edu");
        payload.setLabId(BigInteger.ONE);
        return payload;
    }

    private IntentAuthorizationService.AuthorizationSession session(String sessionId, String requestId, Instant expiresAt) {
        IntentSubmission submission = new IntentSubmission();
        IntentMeta meta = validMeta();
        meta.setRequestId(requestId);
        submission.setMeta(meta);
        return new IntentAuthorizationService.AuthorizationSession(
            sessionId,
            submission,
            List.of("cred-1"),
            "challenge",
            "https://app.example/callback",
            expiresAt
        );
    }
}
