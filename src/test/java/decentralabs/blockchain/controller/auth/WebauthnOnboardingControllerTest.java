package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


import decentralabs.blockchain.controller.TestSecurityConfig;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.PubKeyCredParam;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.RelyingParty;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.User;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingStatusResponse;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnOnboardingService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@SpringBootTest(classes = WebauthnOnboardingController.class)
@Import(TestSecurityConfig.class)
@TestPropertySource(properties = "webauthn.rp.id=localhost")
class WebauthnOnboardingControllerTest {

    @Autowired
    private WebApplicationContext wac;

    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        WebauthnOnboardingController controller = this.wac.getBean(WebauthnOnboardingController.class);
        this.mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(new decentralabs.blockchain.config.JacksonHttpMessageConverter(objectMapper))
            .setControllerAdvice(new decentralabs.blockchain.exception.GlobalExceptionHandler())
            .defaultRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/").accept(org.springframework.http.MediaType.APPLICATION_JSON))
            .build();
    }

    private com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper().registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());

    @MockitoBean
    private WebauthnOnboardingService onboardingService;

    @MockitoBean
    private WebauthnCredentialService credentialService;

    @Test
    @WithMockUser
    void getOptions_validRequest_returnsOptions() throws Exception {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId("user@institution.edu");
        request.setInstitutionId("institution.edu");
        request.setDisplayName("Test User");

        WebauthnOnboardingOptionsResponse response = WebauthnOnboardingOptionsResponse.builder()
            .sessionId("session123")
            .challenge("base64url-challenge")
            .rp(RelyingParty.builder().id("localhost").name("Test").build())
            .user(User.builder().id("userHandle").name("user@institution.edu").displayName("Test User").build())
            .pubKeyCredParams(List.of(PubKeyCredParam.builder().type("public-key").alg(-7).build()))
            .timeout(120000L)
            .attestation("none")
            .build();

        when(onboardingService.generateOptions(any())).thenReturn(response);

        mockMvc.perform(post("/onboarding/webauthn/options")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionId").value("session123"))
            .andExpect(jsonPath("$.challenge").value("base64url-challenge"))
            .andExpect(jsonPath("$.rp.id").value("localhost"))
            .andExpect(jsonPath("$.user.name").value("user@institution.edu"))
            .andExpect(jsonPath("$.pubKeyCredParams[0].alg").value(-7));
    }

    @Test
    @WithMockUser
    void getOptions_missingStableUserId_returnsBadRequest() throws Exception {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setInstitutionId("institution.edu");

        mockMvc.perform(post("/onboarding/webauthn/options")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void complete_validRequest_returnsSuccess() throws Exception {
        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId("session123");
        request.setCredentialId("credId123");
        request.setAttestationObject("attestationBase64");
        request.setClientDataJSON("clientDataBase64");

        WebauthnOnboardingCompleteResponse response = WebauthnOnboardingCompleteResponse.builder()
            .success(true)
            .stableUserId("user@institution.edu")
            .credentialId("credId123")
            .aaguid("00000000000000000000000000000000")
            .message("Credential registered successfully")
            .build();

        when(onboardingService.completeOnboarding(any())).thenReturn(response);

        mockMvc.perform(post("/onboarding/webauthn/complete")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.stableUserId").value("user@institution.edu"))
            .andExpect(jsonPath("$.credentialId").value("credId123"));
    }

    @Test
    @WithMockUser
    void complete_missingSessionId_returnsBadRequest() throws Exception {
        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setCredentialId("credId123");
        request.setAttestationObject("attestationBase64");
        request.setClientDataJSON("clientDataBase64");

        mockMvc.perform(post("/onboarding/webauthn/complete")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    @Test
    void getOptions_withoutAuth_stillAccessible() throws Exception {
        // WebAuthn endpoints should be publicly accessible (browser needs to reach them)
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId("user@institution.edu");
        request.setInstitutionId("institution.edu");

        WebauthnOnboardingOptionsResponse response = WebauthnOnboardingOptionsResponse.builder()
            .sessionId("session123")
            .challenge("challenge")
            .rp(RelyingParty.builder().id("localhost").name("Test").build())
            .user(User.builder().id("userHandle").name("user").displayName("User").build())
            .pubKeyCredParams(List.of())
            .timeout(120000L)
            .build();

        when(onboardingService.generateOptions(any())).thenReturn(response);

        // This test verifies that the endpoint is accessible without authentication
        // TestSecurityConfig permits all requests but requires CSRF token
        mockMvc.perform(post("/onboarding/webauthn/options")
                .with(SecurityMockMvcRequestPostProcessors.csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser
    void getStatus_pendingSession_returnsPending() throws Exception {
        WebauthnOnboardingStatusResponse response = WebauthnOnboardingStatusResponse.builder()
            .status("PENDING")
            .stableUserId("user@institution.edu")
            .institutionId("institution.edu")
            .build();

        when(onboardingService.getStatus(eq("session123"))).thenReturn(response);

        mockMvc.perform(get("/onboarding/webauthn/status/session123")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("PENDING"))
            .andExpect(jsonPath("$.stableUserId").value("user@institution.edu"));
    }

    @Test
    @WithMockUser
    void getStatus_successfulSession_returnsSuccess() throws Exception {
        WebauthnOnboardingStatusResponse response = WebauthnOnboardingStatusResponse.builder()
            .status("SUCCESS")
            .stableUserId("user@institution.edu")
            .institutionId("institution.edu")
            .credentialId("credId123")
            .completedAt(Instant.now())
            .build();

        when(onboardingService.getStatus(eq("session123"))).thenReturn(response);

        mockMvc.perform(get("/onboarding/webauthn/status/session123")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("SUCCESS"))
            .andExpect(jsonPath("$.credentialId").value("credId123"));
    }

    @Test
    @WithMockUser
    void getStatus_failedSession_returnsFailed() throws Exception {
        WebauthnOnboardingStatusResponse response = WebauthnOnboardingStatusResponse.builder()
            .status("FAILED")
            .error("Attestation verification failed")
            .completedAt(Instant.now())
            .build();

        when(onboardingService.getStatus(eq("session123"))).thenReturn(response);

        mockMvc.perform(get("/onboarding/webauthn/status/session123")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("FAILED"))
            .andExpect(jsonPath("$.error").value("Attestation verification failed"));
    }

    // ==================== Key Status Tests ====================

    @Test
    @WithMockUser
    void getKeyStatus_userWithCredentials_returnsHasCredential() throws Exception {
        WebauthnCredentialService.KeyStatus keyStatus = new WebauthnCredentialService.KeyStatus(
            true, 2, false, 1702400000L, true, false, true
        );
        
        when(credentialService.getKeyStatus(eq("user@institution.edu"))).thenReturn(keyStatus);

        mockMvc.perform(get("/onboarding/webauthn/key-status/user@institution.edu")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hasCredential").value(true))
            .andExpect(jsonPath("$.credentialCount").value(2))
            .andExpect(jsonPath("$.stableUserId").value("user@institution.edu"))
            .andExpect(jsonPath("$.hasRevokedCredentials").value(false));
    }

    @Test
    @WithMockUser
    void getKeyStatus_userWithoutCredentials_returnsNoCredential() throws Exception {
        WebauthnCredentialService.KeyStatus keyStatus = new WebauthnCredentialService.KeyStatus(
            false, 0, false, null, false, false, false
        );
        
        when(credentialService.getKeyStatus(eq("newuser@institution.edu"))).thenReturn(keyStatus);

        mockMvc.perform(get("/onboarding/webauthn/key-status/newuser@institution.edu")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hasCredential").value(false))
            .andExpect(jsonPath("$.credentialCount").value(0))
            .andExpect(jsonPath("$.stableUserId").value("newuser@institution.edu"))
            .andExpect(jsonPath("$.lastRegistered").doesNotExist());
    }

    @Test
    @WithMockUser
    void getKeyStatus_withInstitutionId_includesInstitutionInResponse() throws Exception {
        WebauthnCredentialService.KeyStatus keyStatus = new WebauthnCredentialService.KeyStatus(
            true, 1, true, 1702400000L, true, true, false
        );
        
        when(credentialService.getKeyStatus(eq("user@institution.edu"))).thenReturn(keyStatus);

        mockMvc.perform(get("/onboarding/webauthn/key-status/user@institution.edu")
                .param("institutionId", "institution.edu")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hasCredential").value(true))
            .andExpect(jsonPath("$.institutionId").value("institution.edu"))
            .andExpect(jsonPath("$.hasRevokedCredentials").value(true));
    }

    @Test
    void getKeyStatus_withoutAuth_stillAccessible() throws Exception {
        WebauthnCredentialService.KeyStatus keyStatus = new WebauthnCredentialService.KeyStatus(
            true, 1, false, 1702400000L, false, true, false
        );
        
        when(credentialService.getKeyStatus(any())).thenReturn(keyStatus);

        // This endpoint should be publicly accessible for SP integration
        mockMvc.perform(get("/onboarding/webauthn/key-status/user@institution.edu")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk());
    }
}
