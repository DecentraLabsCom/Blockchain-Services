package decentralabs.blockchain.controller.auth;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

import decentralabs.blockchain.dto.auth.WebauthnRegisterRequest;
import decentralabs.blockchain.dto.auth.WebauthnRevokeRequest;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;

/**
 * Unit tests for WebauthnController.
 * Tests WebAuthn credential registration and revocation endpoints.
 */
@ExtendWith(MockitoExtension.class)
class WebauthnControllerTest {

    @Mock
    private WebauthnCredentialService credentialService;

    @InjectMocks
    private WebauthnController webauthnController;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(webauthnController).build();
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("Register Credential Endpoint Tests")
    class RegisterCredentialTests {

        @Test
        @DisplayName("Should register credential successfully")
        void shouldRegisterCredentialSuccessfully() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();

            doNothing().when(credentialService).register(
                request.getPuc(),
                request.getCredentialId(),
                request.getPublicKey(),
                request.getAaguid(),
                request.getSignCount()
            );

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

            verify(credentialService).register(
                request.getPuc(),
                request.getCredentialId(),
                request.getPublicKey(),
                request.getAaguid(),
                request.getSignCount()
            );
        }

        @Test
        @DisplayName("Should reject registration with missing puc")
        void shouldRejectRegistrationWithMissingPuc() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();
            request.setPuc(null);

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should reject registration with empty puc")
        void shouldRejectRegistrationWithEmptyPuc() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();
            request.setPuc("");

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should reject registration with missing credentialId")
        void shouldRejectRegistrationWithMissingCredentialId() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();
            request.setCredentialId(null);

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should reject registration with missing publicKey")
        void shouldRejectRegistrationWithMissingPublicKey() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();
            request.setPublicKey(null);

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should register without optional aaguid")
        void shouldRegisterWithoutAaguid() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();
            request.setAaguid(null);

            doNothing().when(credentialService).register(
                request.getPuc(),
                request.getCredentialId(),
                request.getPublicKey(),
                null,
                request.getSignCount()
            );

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("Should register without optional signCount")
        void shouldRegisterWithoutSignCount() throws Exception {
            WebauthnRegisterRequest request = createValidRegisterRequest();
            request.setSignCount(null);

            doNothing().when(credentialService).register(
                request.getPuc(),
                request.getCredentialId(),
                request.getPublicKey(),
                request.getAaguid(),
                null
            );

            mockMvc.perform(post("/webauthn/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Revoke Credential Endpoint Tests")
    class RevokeCredentialTests {

        @Test
        @DisplayName("Should revoke credential successfully")
        void shouldRevokeCredentialSuccessfully() throws Exception {
            WebauthnRevokeRequest request = createValidRevokeRequest();

            doNothing().when(credentialService).revoke(
                request.getPuc(),
                request.getCredentialId()
            );

            mockMvc.perform(post("/webauthn/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

            verify(credentialService).revoke(request.getPuc(), request.getCredentialId());
        }

        @Test
        @DisplayName("Should reject revocation with missing puc")
        void shouldRejectRevocationWithMissingPuc() throws Exception {
            WebauthnRevokeRequest request = createValidRevokeRequest();
            request.setPuc(null);

            mockMvc.perform(post("/webauthn/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Should reject revocation with empty credentialId")
        void shouldRejectRevocationWithEmptyCredentialId() throws Exception {
            WebauthnRevokeRequest request = createValidRevokeRequest();
            request.setCredentialId("");

            mockMvc.perform(post("/webauthn/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
        }
    }

    private WebauthnRegisterRequest createValidRegisterRequest() {
        WebauthnRegisterRequest request = new WebauthnRegisterRequest();
        request.setPuc("user-principal-claim-123");
        request.setCredentialId("credential-id-abc");
        request.setPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...");
        request.setAaguid("00000000-0000-0000-0000-000000000000");
        request.setSignCount(0L);
        return request;
    }

    private WebauthnRevokeRequest createValidRevokeRequest() {
        WebauthnRevokeRequest request = new WebauthnRevokeRequest();
        request.setPuc("user-principal-claim-123");
        request.setCredentialId("credential-id-abc");
        return request;
    }
}
