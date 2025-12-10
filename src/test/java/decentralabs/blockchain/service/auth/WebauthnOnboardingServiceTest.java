package decentralabs.blockchain.service.auth;

import static org.junit.jupiter.api.Assertions.*;

import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class WebauthnOnboardingServiceTest {

    @Mock
    private WebauthnCredentialService credentialService;

    @Mock
    private ObjectProvider<SamlValidationService> samlValidationServiceProvider;

    private WebauthnOnboardingService service;

    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    @BeforeEach
    void setUp() throws Exception {
        service = new WebauthnOnboardingService(credentialService, samlValidationServiceProvider);
        
        // Set configuration via reflection (normally done by Spring)
        setField("rpId", "localhost");
        setField("rpName", "Test Gateway");
        setField("allowedOriginsConfig", "https://localhost,https://localhost:443");
        setField("timeoutMs", 120000L);
        setField("sessionTtlSeconds", 300L);
        setField("cleanupIntervalSeconds", 60L);
        setField("attestationConveyance", "none");
        setField("authenticatorAttachment", "");
        setField("residentKey", "preferred");
        setField("userVerification", "preferred");
        setField("validateSaml", false);
        setField("completedSessionTtlSeconds", 3600L);
        
        // Initialize the service (starts cleanup scheduler)
        service.init();
    }

    private void setField(String fieldName, Object value) throws Exception {
        Field field = WebauthnOnboardingService.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(service, value);
    }

    @Test
    void generateOptions_validRequest_returnsOptions() {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId("user@institution.edu");
        request.setInstitutionId("institution.edu");
        request.setDisplayName("Test User");

        WebauthnOnboardingOptionsResponse response = service.generateOptions(request);

        assertNotNull(response);
        assertNotNull(response.getSessionId());
        assertNotNull(response.getChallenge());
        assertEquals("localhost", response.getRp().getId());
        assertEquals("Test Gateway", response.getRp().getName());
        assertEquals("user@institution.edu", response.getUser().getName());
        assertEquals("Test User", response.getUser().getDisplayName());
        assertNotNull(response.getUser().getId()); // User handle
        assertEquals(120000L, response.getTimeout());
        assertEquals("none", response.getAttestation());
        assertFalse(response.getPubKeyCredParams().isEmpty());
        assertEquals(-7, response.getPubKeyCredParams().get(0).getAlg()); // ES256
    }

    @Test
    void generateOptions_missingStableUserId_throwsException() {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setInstitutionId("institution.edu");

        assertThrows(ResponseStatusException.class, () -> service.generateOptions(request));
    }

    @Test
    void generateOptions_missingInstitutionId_throwsException() {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId("user@institution.edu");

        assertThrows(ResponseStatusException.class, () -> service.generateOptions(request));
    }

    @Test
    void generateOptions_eachCallGeneratesUniqueChallenge() {
        WebauthnOnboardingOptionsRequest request = new WebauthnOnboardingOptionsRequest();
        request.setStableUserId("user@institution.edu");
        request.setInstitutionId("institution.edu");

        WebauthnOnboardingOptionsResponse response1 = service.generateOptions(request);
        WebauthnOnboardingOptionsResponse response2 = service.generateOptions(request);

        assertNotEquals(response1.getChallenge(), response2.getChallenge());
        assertNotEquals(response1.getSessionId(), response2.getSessionId());
    }

    @Test
    void completeOnboarding_invalidSession_throwsException() {
        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId("nonexistent-session");
        request.setCredentialId("cred123");
        request.setAttestationObject("dummy");
        request.setClientDataJSON("dummy");

        assertThrows(ResponseStatusException.class, () -> service.completeOnboarding(request));
    }

    @Test
    void completeOnboarding_invalidClientDataType_throwsException() throws Exception {
        // First generate options
        WebauthnOnboardingOptionsRequest optionsRequest = new WebauthnOnboardingOptionsRequest();
        optionsRequest.setStableUserId("user@institution.edu");
        optionsRequest.setInstitutionId("institution.edu");
        WebauthnOnboardingOptionsResponse options = service.generateOptions(optionsRequest);

        // Create invalid client data (wrong type)
        String clientDataJson = String.format(
            "{\"type\":\"webauthn.get\",\"challenge\":\"%s\",\"origin\":\"https://localhost\"}",
            options.getChallenge()
        );

        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId(options.getSessionId());
        request.setCredentialId(BASE64URL_ENCODER.encodeToString("cred123".getBytes()));
        request.setClientDataJSON(BASE64URL_ENCODER.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8)));
        request.setAttestationObject(BASE64URL_ENCODER.encodeToString(createMinimalAttestationObject()));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, 
            () -> service.completeOnboarding(request));
        assertTrue(ex.getReason().contains("Invalid client data type"));
    }

    @Test
    void completeOnboarding_challengeMismatch_throwsException() throws Exception {
        // First generate options
        WebauthnOnboardingOptionsRequest optionsRequest = new WebauthnOnboardingOptionsRequest();
        optionsRequest.setStableUserId("user@institution.edu");
        optionsRequest.setInstitutionId("institution.edu");
        WebauthnOnboardingOptionsResponse options = service.generateOptions(optionsRequest);

        // Create client data with wrong challenge
        String wrongChallenge = BASE64URL_ENCODER.encodeToString("wrong-challenge".getBytes());
        String clientDataJson = String.format(
            "{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"https://localhost\"}",
            wrongChallenge
        );

        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId(options.getSessionId());
        request.setCredentialId(BASE64URL_ENCODER.encodeToString("cred123".getBytes()));
        request.setClientDataJSON(BASE64URL_ENCODER.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8)));
        request.setAttestationObject(BASE64URL_ENCODER.encodeToString(createMinimalAttestationObject()));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, 
            () -> service.completeOnboarding(request));
        assertTrue(ex.getReason().contains("Challenge mismatch"));
    }

    @Test
    void completeOnboarding_invalidOrigin_throwsException() throws Exception {
        // First generate options
        WebauthnOnboardingOptionsRequest optionsRequest = new WebauthnOnboardingOptionsRequest();
        optionsRequest.setStableUserId("user@institution.edu");
        optionsRequest.setInstitutionId("institution.edu");
        WebauthnOnboardingOptionsResponse options = service.generateOptions(optionsRequest);

        // Create client data with invalid origin
        String clientDataJson = String.format(
            "{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"https://evil.com\"}",
            options.getChallenge()
        );

        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId(options.getSessionId());
        request.setCredentialId(BASE64URL_ENCODER.encodeToString("cred123".getBytes()));
        request.setClientDataJSON(BASE64URL_ENCODER.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8)));
        request.setAttestationObject(BASE64URL_ENCODER.encodeToString(createMinimalAttestationObject()));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, 
            () -> service.completeOnboarding(request));
        assertTrue(ex.getReason().contains("Origin not allowed"));
    }

    @Test
    void completeOnboarding_sessionCanOnlyBeUsedOnce() throws Exception {
        // First generate options
        WebauthnOnboardingOptionsRequest optionsRequest = new WebauthnOnboardingOptionsRequest();
        optionsRequest.setStableUserId("user@institution.edu");
        optionsRequest.setInstitutionId("institution.edu");
        WebauthnOnboardingOptionsResponse options = service.generateOptions(optionsRequest);

        String clientDataJson = String.format(
            "{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"https://localhost\"}",
            options.getChallenge()
        );

        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId(options.getSessionId());
        request.setCredentialId(BASE64URL_ENCODER.encodeToString("cred123".getBytes()));
        request.setClientDataJSON(BASE64URL_ENCODER.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8)));
        request.setAttestationObject(BASE64URL_ENCODER.encodeToString(createMinimalAttestationObject()));

        // First attempt will fail due to attestation parsing, but session is consumed
        assertThrows(ResponseStatusException.class, () -> service.completeOnboarding(request));

        // Second attempt should fail with invalid session
        ResponseStatusException ex = assertThrows(ResponseStatusException.class, 
            () -> service.completeOnboarding(request));
        assertTrue(ex.getReason().contains("Invalid or expired session"));
    }

    /**
     * Create a minimal CBOR-encoded attestation object for testing.
     * This is not a valid attestation, just enough to trigger parsing code paths.
     */
    private byte[] createMinimalAttestationObject() throws Exception {
        // Create a minimal CBOR map with authData
        // The authData needs:
        // - 32 bytes rpIdHash
        // - 1 byte flags (0x41 = UP + AT flags set)
        // - 4 bytes signCount
        // - 16 bytes aaguid
        // - 2 bytes credIdLen
        // - credId bytes
        // - public key CBOR

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] rpIdHash = sha256.digest("localhost".getBytes(StandardCharsets.UTF_8));
        
        // Build authData manually
        byte[] authData = new byte[37 + 16 + 2 + 4 + 10]; // minimum size
        System.arraycopy(rpIdHash, 0, authData, 0, 32); // rpIdHash
        authData[32] = 0x41; // flags: UP + AT
        // signCount = 0 (bytes 33-36)
        // aaguid = zeros (bytes 37-52)
        // credIdLen = 4 (bytes 53-54)
        authData[53] = 0;
        authData[54] = 4;
        // credId = "test" (bytes 55-58)
        authData[55] = 't';
        authData[56] = 'e';
        authData[57] = 's';
        authData[58] = 't';
        // minimal public key CBOR (will fail validation but triggers parsing)
        authData[59] = (byte) 0xA0; // empty CBOR map

        // Wrap in CBOR map: {"fmt": "none", "authData": <bytes>, "attStmt": {}}
        // This is a simplified manual CBOR encoding
        // Real implementation would use a CBOR library
        return new byte[] {
            (byte) 0xA3, // map of 3 items
            0x63, 'f', 'm', 't', // text string "fmt"
            0x64, 'n', 'o', 'n', 'e', // text string "none"
            0x67, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', // text string "authData"
            0x58, (byte) authData.length, // byte string with 1-byte length prefix
        };
    }
}
