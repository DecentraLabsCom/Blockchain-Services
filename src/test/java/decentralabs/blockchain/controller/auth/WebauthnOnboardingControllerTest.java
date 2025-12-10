package decentralabs.blockchain.controller.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.PubKeyCredParam;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.RelyingParty;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.User;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingStatusResponse;
import decentralabs.blockchain.service.auth.WebauthnOnboardingService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(WebauthnOnboardingController.class)
@Import(WebauthnOnboardingControllerTest.TestSecurityConfig.class)
@TestPropertySource(properties = "webauthn.rp.id=localhost")
class WebauthnOnboardingControllerTest {
    /**
     * Test security configuration that permits all requests to the onboarding endpoints.
     * This mimics the actual SecurityConfig behavior for /onboarding/** paths.
     */
    @Configuration
    static class TestSecurityConfig {
        @Bean
        public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/onboarding/**").permitAll()
                    .anyRequest().authenticated()
                );
            return http.build();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private WebauthnOnboardingService onboardingService;

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
        // TestSecurityConfig disables CSRF for /onboarding/** paths
        mockMvc.perform(post("/onboarding/webauthn/options")
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
}
