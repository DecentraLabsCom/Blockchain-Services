package decentralabs.blockchain.service.auth;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.service.BackendUrlResolver;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
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

    @Mock
    private BackendUrlResolver backendUrlResolver;

    private WebauthnOnboardingService service;

    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    @BeforeEach
    void setUp() throws Exception {
        // Configure BackendUrlResolver mock to return a valid base URL
        // Use lenient() because not all tests use this mock
        lenient().when(backendUrlResolver.resolveBaseDomain()).thenReturn("https://localhost");
        
        service = new WebauthnOnboardingService(credentialService, samlValidationServiceProvider, backendUrlResolver);
        
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

    @AfterEach
    void tearDown() {
        // Shutdown the service to stop the cleanup scheduler and prevent memory leaks
        if (service != null) {
            service.shutdown();
        }
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
        // Mock credential service to return no existing credential
        WebauthnCredentialService.KeyStatus noCredential = new WebauthnCredentialService.KeyStatus(
            false, 0, false, 0L
        );
        when(credentialService.getKeyStatus(anyString())).thenReturn(noCredential);

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
        String message = ex.getReason() != null ? ex.getReason() : ex.getMessage();
        assertTrue(message.contains("Invalid client data type"));
    }

    @Test
    void completeOnboarding_challengeMismatch_throwsException() throws Exception {
        // Mock credential service to return no existing credential
        WebauthnCredentialService.KeyStatus noCredential = new WebauthnCredentialService.KeyStatus(
            false, 0, false, 0L
        );
        when(credentialService.getKeyStatus(anyString())).thenReturn(noCredential);

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
        String message = ex.getReason() != null ? ex.getReason() : ex.getMessage();
        assertTrue(message.contains("Challenge mismatch"));
    }

    @Test
    void completeOnboarding_invalidOrigin_throwsException() throws Exception {
        // Mock credential service to return no existing credential
        WebauthnCredentialService.KeyStatus noCredential = new WebauthnCredentialService.KeyStatus(
            false, 0, false, 0L
        );
        when(credentialService.getKeyStatus(anyString())).thenReturn(noCredential);

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
        String message = ex.getReason() != null ? ex.getReason() : ex.getMessage();
        assertTrue(message.contains("Origin not allowed"));
    }

    @Test
    void completeOnboarding_sessionCanOnlyBeUsedOnce() throws Exception {
        // Mock credential service to return no existing credential
        WebauthnCredentialService.KeyStatus noCredential = new WebauthnCredentialService.KeyStatus(
            false, 0, false, 0L
        );
        when(credentialService.getKeyStatus(anyString())).thenReturn(noCredential);

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
        String message = ex.getReason() != null ? ex.getReason() : ex.getMessage();
        assertTrue(message.contains("Invalid or expired session"));
    }

    /**
     * Create a minimal CBOR-encoded attestation object for testing.
     * Creates a properly formatted (but not valid) CBOR map to avoid memory leaks in the decoder.
     * 
     * Structure: {
     *   "fmt": "none",
     *   "authData": <37 bytes minimum>,
     *   "attStmt": {}
     * }
     */
    private byte[] createMinimalAttestationObject() throws Exception {
        // Use a simple ByteArrayOutputStream to build valid CBOR manually
        // to avoid memory leaks from malformed CBOR that causes infinite loops
        
        // Create minimal authData (37 bytes minimum without attestedCredentialData)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] rpIdHash = sha256.digest("localhost".getBytes(StandardCharsets.UTF_8));
        
        byte[] authData = new byte[37];
        System.arraycopy(rpIdHash, 0, authData, 0, 32); // rpIdHash (32 bytes)
        authData[32] = 0x01; // flags: only UP (User Present), no AT flag
        // signCount = 0 (bytes 33-36, already zero from array initialization)
        
        // Build a valid CBOR map manually:
        // Map with 3 entries: fmt, authData, attStmt
        byte[] fmt = "none".getBytes(StandardCharsets.UTF_8);
        
        // Calculate total size
        // CBOR map header (1) + 
        // "fmt" key (1 + 3) + "none" value (1 + 4) +
        // "authData" key (1 + 8) + authData value (1 + 1 + 37) +
        // "attStmt" key (1 + 7) + empty map value (1)
        
        // Create a minimal valid CBOR structure
        byte[] result = new byte[128]; // Fixed size buffer
        int pos = 0;
        
        result[pos++] = (byte) 0xA3; // CBOR map with 3 items
        
        // Item 1: "fmt": "none"
        result[pos++] = 0x63; // text string of length 3
        result[pos++] = 'f'; result[pos++] = 'm'; result[pos++] = 't';
        result[pos++] = 0x64; // text string of length 4
        result[pos++] = 'n'; result[pos++] = 'o'; result[pos++] = 'n'; result[pos++] = 'e';
        
        // Item 2: "authData": <bytes>
        result[pos++] = 0x68; // text string of length 8
        result[pos++] = 'a'; result[pos++] = 'u'; result[pos++] = 't'; result[pos++] = 'h';
        result[pos++] = 'D'; result[pos++] = 'a'; result[pos++] = 't'; result[pos++] = 'a';
        result[pos++] = 0x58; // byte string, 1-byte length follows
        result[pos++] = (byte) authData.length;
        System.arraycopy(authData, 0, result, pos, authData.length);
        pos += authData.length;
        
        // Item 3: "attStmt": {}
        result[pos++] = 0x67; // text string of length 7
        result[pos++] = 'a'; result[pos++] = 't'; result[pos++] = 't'; result[pos++] = 'S';
        result[pos++] = 't'; result[pos++] = 'm'; result[pos++] = 't';
        result[pos++] = (byte) 0xA0; // empty CBOR map
        
        // Return only the used portion
        byte[] finalResult = new byte[pos];
        System.arraycopy(result, 0, finalResult, 0, pos);
        return finalResult;
    }

    @Test
    void completeOnboarding_duplicateCredential_throwsConflict() {
        // Setup: User already has a credential
        WebauthnCredentialService.KeyStatus existingStatus = new WebauthnCredentialService.KeyStatus(
            true,  // hasCredential
            1,     // credentialCount
            false, // hasRevokedCredentials
            System.currentTimeMillis() / 1000  // lastRegisteredEpoch
        );
        when(credentialService.getKeyStatus("user@institution.edu")).thenReturn(existingStatus);

        // Generate options first to create a session
        WebauthnOnboardingOptionsRequest optionsRequest = new WebauthnOnboardingOptionsRequest();
        optionsRequest.setStableUserId("user@institution.edu");
        optionsRequest.setInstitutionId("institution.edu");
        optionsRequest.setDisplayName("Test User");
        
        WebauthnOnboardingOptionsResponse options = service.generateOptions(optionsRequest);

        // Try to complete onboarding with a duplicate credential
        WebauthnOnboardingCompleteRequest completeRequest = new WebauthnOnboardingCompleteRequest();
        completeRequest.setSessionId(options.getSessionId());
        completeRequest.setCredentialId("new-credential-id");
        completeRequest.setClientDataJSON(BASE64URL_ENCODER.encodeToString("{}".getBytes()));
        completeRequest.setAttestationObject(BASE64URL_ENCODER.encodeToString(new byte[0]));

        // Should throw CONFLICT (409) exception
        ResponseStatusException exception = assertThrows(
            ResponseStatusException.class,
            () -> service.completeOnboarding(completeRequest)
        );
        
        assertEquals(409, exception.getStatusCode().value());
        assertTrue(exception.getReason().contains("already has an active credential"));
    }
}
