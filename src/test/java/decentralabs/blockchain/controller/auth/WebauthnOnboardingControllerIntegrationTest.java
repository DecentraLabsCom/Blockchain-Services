package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
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

import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnOnboardingService;

@WebMvcTest(controllers = WebauthnOnboardingController.class)
@AutoConfigureMockMvc(addFilters = false)
class WebauthnOnboardingControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private WebauthnOnboardingService webauthnOnboardingService;

    @MockitoBean
    private WebauthnCredentialService webauthnCredentialService;

    @Test
    void shouldRequestCredentialCreationOptions() throws Exception {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId("user123@university.edu");
        request.setInstitutionId("university.edu");
        request.setDisplayName("John Doe");

        WebauthnOnboardingOptionsResponse response = WebauthnOnboardingOptionsResponse.builder()
            .challenge("challenge123")
            .rp(WebauthnOnboardingOptionsResponse.RelyingParty.builder()
                .id("decentralabs.edu")
                .name("DecentraLabs")
                .build())
            .user(WebauthnOnboardingOptionsResponse.User.builder()
                .id("user123")
                .name("user123@university.edu")
                .displayName("John Doe")
                .build())
            .build();

        when(webauthnOnboardingService.generateOptions(any(WebauthnOnboardingOptionsRequest.class)))
            .thenReturn(response);

        mockMvc.perform(post("/onboarding/webauthn/options")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.challenge").value("challenge123"))
            .andExpect(jsonPath("$.rp.id").value("decentralabs.edu"))
            .andExpect(jsonPath("$.user.id").value("user123"));
    }

    @Test
    void shouldHandleInvalidUserId() throws Exception {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId(""); // Invalid empty user ID
        request.setDisplayName("John Doe");

        when(webauthnOnboardingService.generateOptions(any(WebauthnOnboardingOptionsRequest.class)))
            .thenThrow(new IllegalArgumentException("Invalid stable user ID"));

        mockMvc.perform(post("/onboarding/webauthn/options")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    @Test
    void shouldCompleteCredentialRegistration() throws Exception {
        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId("session123");
        request.setCredentialId("cred123");
        request.setAttestationObject("attestation-data");
        request.setClientDataJSON("client-data");

        WebauthnOnboardingCompleteResponse response = new WebauthnOnboardingCompleteResponse();
        response.setCredentialId("cred123");
        response.setSuccess(true);

        when(webauthnOnboardingService.completeOnboarding(any(WebauthnOnboardingCompleteRequest.class)))
            .thenReturn(response);

        mockMvc.perform(post("/onboarding/webauthn/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.credentialId").value("cred123"))
            .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void shouldHandleInvalidAttestation() throws Exception {
        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId("session123");
        request.setCredentialId("cred123");
        request.setAttestationObject("invalid-attestation");
        request.setClientDataJSON("client-data");

        when(webauthnOnboardingService.completeOnboarding(any(WebauthnOnboardingCompleteRequest.class)))
            .thenThrow(new SecurityException("Invalid attestation signature"));

        mockMvc.perform(post("/onboarding/webauthn/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isForbidden());
    }

    @Test
    void shouldCheckCredentialStatus() throws Exception {
        when(webauthnCredentialService.getKeyStatus("user123@university.edu"))
            .thenReturn(new WebauthnCredentialService.KeyStatus(true, 1, false, 1234567890L));

        mockMvc.perform(get("/onboarding/webauthn/key-status/user123@university.edu"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hasCredential").value(true))
            .andExpect(jsonPath("$.credentialCount").value(1))
            .andExpect(jsonPath("$.stableUserId").value("user123@university.edu"));
    }

    @Test
    void shouldHandleNonexistentUser() throws Exception {
        when(webauthnCredentialService.getKeyStatus("nonexistent@university.edu"))
            .thenReturn(new WebauthnCredentialService.KeyStatus(false, 0, false, null));

        mockMvc.perform(get("/onboarding/webauthn/key-status/nonexistent@university.edu"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hasCredential").value(false))
            .andExpect(jsonPath("$.credentialCount").value(0))
            .andExpect(jsonPath("$.stableUserId").value("nonexistent@university.edu"));
    }

    @Test
    void shouldHandleChallengeReplayAttack() throws Exception {
        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId("session123");
        request.setCredentialId("cred123");
        request.setAttestationObject("replay-attestation");
        request.setClientDataJSON("client-data");

        when(webauthnOnboardingService.completeOnboarding(any(WebauthnOnboardingCompleteRequest.class)))
            .thenThrow(new SecurityException("Challenge already used"));

        mockMvc.perform(post("/onboarding/webauthn/complete")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isForbidden());
    }
}
