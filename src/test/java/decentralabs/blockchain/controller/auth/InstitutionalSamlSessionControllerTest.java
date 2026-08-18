package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.InstitutionalSessionRequest;
import decentralabs.blockchain.dto.auth.InstitutionalSessionResponse;
import decentralabs.blockchain.exception.GlobalExceptionHandler;
import decentralabs.blockchain.service.auth.InstitutionalSamlSessionService;
import decentralabs.blockchain.service.intent.IntentAuthService;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class InstitutionalSamlSessionControllerTest {

    @Mock
    private InstitutionalSamlSessionService sessionService;

    @Mock
    private IntentAuthService intentAuthService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(
                new InstitutionalSamlSessionController(sessionService, intentAuthService)
            )
            .setControllerAdvice(new GlobalExceptionHandler())
            .build();
        objectMapper = new ObjectMapper();
    }

    @Test
    void createSession_requiresMarketplaceServiceAuthorizationAndReturnsCredential() throws Exception {
        InstitutionalSessionRequest request = new InstitutionalSessionRequest();
        request.setSamlAssertion("fresh-saml-assertion");
        request.setStableUserIdMode("principal");
        InstitutionalSessionResponse response = InstitutionalSessionResponse.builder()
            .sessionToken("backend-session-token")
            .expiresAt(Instant.parse("2026-08-18T14:00:00Z"))
            .reauthenticationAt(Instant.parse("2026-08-18T14:00:00Z"))
            .samlAssertionHash("0x" + "a".repeat(64))
            .build();

        when(intentAuthService.enforceSessionAuthorization("Bearer marketplace-token"))
            .thenReturn(new IntentAuthService.SessionAuthorization(
                true,
                Map.of("puc", "user@institution.edu", "affiliation", "institution.edu")
            ));
        when(sessionService.create(any(InstitutionalSessionRequest.class), anyMap(), anyBoolean()))
            .thenReturn(response);

        mockMvc.perform(post("/auth/saml/session")
                .header("Authorization", "Bearer marketplace-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionToken").value("backend-session-token"))
            .andExpect(jsonPath("$.expiresAt").value("2026-08-18T14:00:00Z"))
            .andExpect(jsonPath("$.reauthenticationAt").value("2026-08-18T14:00:00Z"))
            .andExpect(jsonPath("$.samlAssertionHash").value("0x" + "a".repeat(64)));

        verify(intentAuthService).enforceSessionAuthorization("Bearer marketplace-token");
        verify(sessionService).create(any(InstitutionalSessionRequest.class), anyMap(), org.mockito.ArgumentMatchers.eq(true));
    }

    @Test
    void createSession_allowsSignedSamlAsIdentityAuthorityWhenMarketplaceAuthIsDisabled() throws Exception {
        InstitutionalSessionRequest request = new InstitutionalSessionRequest();
        request.setSamlAssertion("fresh-saml-assertion");
        request.setStableUserIdMode("principal");
        InstitutionalSessionResponse response = InstitutionalSessionResponse.builder()
            .sessionToken("backend-session-token")
            .expiresAt(Instant.parse("2026-08-18T14:00:00Z"))
            .reauthenticationAt(Instant.parse("2026-08-18T14:00:00Z"))
            .samlAssertionHash("0x" + "a".repeat(64))
            .build();

        when(intentAuthService.enforceSessionAuthorization(null))
            .thenReturn(new IntentAuthService.SessionAuthorization(false, Map.of()));
        when(sessionService.create(any(InstitutionalSessionRequest.class), anyMap(), anyBoolean()))
            .thenReturn(response);

        mockMvc.perform(post("/auth/saml/session")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionToken").value("backend-session-token"));

        verify(sessionService).create(
            any(InstitutionalSessionRequest.class),
            anyMap(),
            org.mockito.ArgumentMatchers.eq(false)
        );
    }

    @Test
    void createSession_rejectsMissingAssertionBeforeCallingServices() throws Exception {
        mockMvc.perform(post("/auth/saml/session")
                .header("Authorization", "Bearer marketplace-token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"stableUserIdMode\":\"principal\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Validation failed"))
            .andExpect(jsonPath("$.errors.samlAssertion").exists());

        verify(intentAuthService, never()).enforceSessionAuthorization(any());
        verify(sessionService, never()).create(any(), any(), anyBoolean());
    }
}
