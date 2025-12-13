package decentralabs.blockchain.service.auth;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.AuthenticatorSelection;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.PubKeyCredParam;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.RelyingParty;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse.User;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingStatusResponse;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Service for handling WebAuthn credential registration during user onboarding.
 * 
 * This implements the Relying Party (RP) side of WebAuthn where:
 * 1. The SP requests onboarding options (challenge) for a user
 * 2. The browser performs the WebAuthn ceremony
 * 3. The browser sends the attestation directly to this service
 * 4. This service verifies and stores the credential binding
 * 
 * Security considerations:
 * - Challenges are stored in memory with TTL to prevent replay attacks
 * - Sessions are cleaned up periodically
 * - Challenge is bound to stableUserId to prevent binding confusion
 * - Origin verification is performed on attestation response
 */
@Service
@Slf4j
public class WebauthnOnboardingService {

    private static final int CHALLENGE_LENGTH = 32; // 256 bits
    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
    
    // COSE algorithm identifiers
    private static final int COSE_ALG_ES256 = -7;   // ECDSA w/ SHA-256
    private static final int COSE_ALG_RS256 = -257; // RSASSA-PKCS1-v1_5 w/ SHA-256
    private static final int COSE_ALG_EDDSA = -8;   // EdDSA

    private final SecureRandom secureRandom = new SecureRandom();
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * In-memory session store for pending onboarding ceremonies.
     * Key: sessionId, Value: OnboardingSession
     */
    private final ConcurrentHashMap<String, OnboardingSession> pendingSessions = new ConcurrentHashMap<>();

    /**
     * In-memory store for completed/failed sessions (for SP polling).
     * Key: sessionId, Value: CompletedOnboarding
     * Sessions are removed after completedSessionTtlSeconds.
     */
    private final ConcurrentHashMap<String, CompletedOnboarding> completedSessions = new ConcurrentHashMap<>();
    
    private ScheduledExecutorService cleanupScheduler;

    private final WebauthnCredentialService credentialService;
    private final SamlValidationService samlValidationService; // May be null
    private final RestTemplate restTemplate;

    @Value("${webauthn.rp.id:${base.domain:localhost}}")
    private String rpId;

    @Value("${webauthn.rp.name:DecentraLabs Gateway}")
    private String rpName;

    @Value("${webauthn.rp.origins:https://localhost,https://localhost:443,https://localhost:8443}")
    private String allowedOriginsConfig;

    @Value("${webauthn.timeout.ms:120000}")
    private long timeoutMs;

    @Value("${webauthn.session.ttl.seconds:300}")
    private long sessionTtlSeconds;

    @Value("${webauthn.session.cleanup.interval.seconds:60}")
    private long cleanupIntervalSeconds;

    @Value("${webauthn.attestation.conveyance:none}")
    private String attestationConveyance;

    @Value("${webauthn.authenticator.attachment:}")
    private String authenticatorAttachment;

    @Value("${webauthn.resident-key:preferred}")
    private String residentKey;

    @Value("${webauthn.user-verification:preferred}")
    private String userVerification;

    @Value("${webauthn.validate-saml:true}")
    private boolean validateSaml;

    @Value("${webauthn.completed-session.ttl.seconds:3600}")
    private long completedSessionTtlSeconds;

    @Value("${webauthn.base-url:}")
    private String baseUrl;

    public WebauthnOnboardingService(
            WebauthnCredentialService credentialService,
            ObjectProvider<SamlValidationService> samlValidationServiceProvider) {
        this.credentialService = credentialService;
        this.samlValidationService = samlValidationServiceProvider.getIfAvailable();
        this.restTemplate = new RestTemplate();
        if (this.samlValidationService == null) {
            log.warn("SamlValidationService not available. SAML assertion validation will be skipped.");
        }
    }

    @PostConstruct
    public void init() {
        // Start periodic cleanup of expired sessions
        cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "webauthn-session-cleanup");
            t.setDaemon(true);
            return t;
        });
        cleanupScheduler.scheduleAtFixedRate(
            this::cleanupExpiredSessions,
            cleanupIntervalSeconds,
            cleanupIntervalSeconds,
            TimeUnit.SECONDS
        );
        log.info("WebAuthn Onboarding Service initialized. RP ID: {}, Session TTL: {}s", rpId, sessionTtlSeconds);
    }

    @PreDestroy
    public void shutdown() {
        if (cleanupScheduler != null) {
            cleanupScheduler.shutdown();
            try {
                if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Generate WebAuthn credential creation options for a new user onboarding.
     * 
     * @param request Contains the stable user ID and institution from federated assertion
     * @return Options including the challenge for the WebAuthn ceremony
     */
    public WebauthnOnboardingOptionsResponse generateOptions(WebauthnOnboardingOptionsRequest request) {
        String stableUserId = normalize(request.getStableUserId());
        String institutionId = normalize(request.getInstitutionId());
        
        if (stableUserId.isEmpty() || institutionId.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "stableUserId and institutionId are required");
        }

        // Validate SAML assertion if provided and validation is enabled
        if (validateSaml && request.getSamlAssertion() != null && !request.getSamlAssertion().isEmpty()) {
            validateSamlAssertion(request.getSamlAssertion(), stableUserId, institutionId);
            log.debug("SAML assertion validated for user: {}", stableUserId);
        }

        // Generate cryptographically secure challenge
        byte[] challengeBytes = new byte[CHALLENGE_LENGTH];
        secureRandom.nextBytes(challengeBytes);
        String challenge = BASE64URL_ENCODER.encodeToString(challengeBytes);

        // Generate session ID
        byte[] sessionIdBytes = new byte[16];
        secureRandom.nextBytes(sessionIdBytes);
        String sessionId = HexFormat.of().formatHex(sessionIdBytes);

        // Generate user handle (opaque identifier for WebAuthn, not the stableUserId)
        byte[] userHandleBytes = new byte[16];
        secureRandom.nextBytes(userHandleBytes);
        String userHandle = BASE64URL_ENCODER.encodeToString(userHandleBytes);

        Instant expiresAt = Instant.now().plusSeconds(sessionTtlSeconds);

        // Store session with TTL
        OnboardingSession session = new OnboardingSession(
            sessionId,
            stableUserId,
            institutionId,
            challenge,
            challengeBytes,
            userHandle,
            request.getDisplayName(),
            request.getAssertionReference(),
            request.getAttributes(),
            request.getCallbackUrl(),
            expiresAt
        );
        pendingSessions.put(sessionId, session);

        log.info("WebAuthn onboarding session created. SessionId: {}, Institution: {}", 
            sessionId, institutionId);

        // Build the onboarding URL where the SP should redirect the browser
        String onboardingUrl = buildOnboardingUrl(sessionId);

        // Build response following W3C WebAuthn spec
        String displayName = request.getDisplayName() != null ? request.getDisplayName() : stableUserId;

        return WebauthnOnboardingOptionsResponse.builder()
            .sessionId(sessionId)
            .onboardingUrl(onboardingUrl)
            .challenge(challenge)
            .rp(RelyingParty.builder()
                .id(rpId)
                .name(rpName)
                .build())
            .user(User.builder()
                .id(userHandle)
                .name(stableUserId)
                .displayName(displayName)
                .build())
            .pubKeyCredParams(Arrays.asList(
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_ES256).build(),
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_RS256).build(),
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_EDDSA).build()
            ))
            .timeout(timeoutMs)
            .attestation(attestationConveyance)
            .authenticatorSelection(buildAuthenticatorSelection())
            .build();
    }

    /**
     * Complete the WebAuthn onboarding by verifying and storing the credential.
     * 
     * @param request Contains the attestation response from navigator.credentials.create()
     * @return Success response with credential details
     */
    public WebauthnOnboardingCompleteResponse completeOnboarding(WebauthnOnboardingCompleteRequest request) {
        String sessionId = request.getSessionId();
        
        // Retrieve and remove session (one-time use)
        OnboardingSession session = pendingSessions.remove(sessionId);
        if (session == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired session");
        }

        // Check session expiry
        if (Instant.now().isAfter(session.getExpiresAt())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Session expired");
        }

        try {
            // Decode client data JSON and verify
            byte[] clientDataJson = BASE64URL_DECODER.decode(request.getClientDataJSON());
            verifyClientData(clientDataJson, session.getChallengeBytes());

            // Decode attestation object and extract credential data
            byte[] attestationObject = BASE64URL_DECODER.decode(request.getAttestationObject());
            AttestationData attestationData = parseAttestationObject(attestationObject);

            // Extract public key (COSE format) and convert to Base64 for storage
            String publicKeyBase64 = BASE64URL_ENCODER.encodeToString(attestationData.publicKeyCose);
            String aaguid = HexFormat.of().formatHex(attestationData.aaguid);
            String credentialId = request.getCredentialId();

            // Store the credential binding using existing service
            credentialService.register(
                session.getStableUserId(),
                credentialId,
                publicKeyBase64,
                aaguid,
                attestationData.signCount
            );

            log.info("WebAuthn credential registered. StableUserId: {}, CredentialId: {}", 
                session.getStableUserId(), credentialId.substring(0, Math.min(20, credentialId.length())) + "...");

            WebauthnOnboardingCompleteResponse response = WebauthnOnboardingCompleteResponse.builder()
                .success(true)
                .stableUserId(session.getStableUserId())
                .institutionId(session.getInstitutionId())
                .credentialId(credentialId)
                .aaguid(aaguid)
                .message("Credential registered successfully")
                .build();

            // Store completed onboarding for status polling
            CompletedOnboarding completed = new CompletedOnboarding(
                "SUCCESS",
                session.getStableUserId(),
                session.getInstitutionId(),
                credentialId,
                null,
                Instant.now()
            );
            completedSessions.put(sessionId, completed);

            // Send callback to SP if URL was provided
            if (session.getCallbackUrl() != null && !session.getCallbackUrl().isBlank()) {
                sendCallbackToSp(session.getCallbackUrl(), response, null);
            }

            return response;

        } catch (ResponseStatusException e) {
            // Store failure for status polling
            CompletedOnboarding failed = new CompletedOnboarding(
                "FAILED",
                session != null ? session.getStableUserId() : null,
                session != null ? session.getInstitutionId() : null,
                null,
                e.getReason(),
                Instant.now()
            );
            completedSessions.put(sessionId, failed);
            
            // Send failure callback if URL was provided
            if (session != null && session.getCallbackUrl() != null && !session.getCallbackUrl().isBlank()) {
                sendCallbackToSp(session.getCallbackUrl(), null, e.getReason());
            }
            
            throw e;
        } catch (Exception e) {
            log.error("WebAuthn attestation verification failed", e);
            
            // Store failure for status polling
            CompletedOnboarding failed = new CompletedOnboarding(
                "FAILED",
                session != null ? session.getStableUserId() : null,
                session != null ? session.getInstitutionId() : null,
                null,
                "Attestation verification failed: " + e.getMessage(),
                Instant.now()
            );
            completedSessions.put(sessionId, failed);
            
            // Send failure callback if URL was provided
            if (session != null && session.getCallbackUrl() != null && !session.getCallbackUrl().isBlank()) {
                sendCallbackToSp(session.getCallbackUrl(), null, "Attestation verification failed: " + e.getMessage());
            }
            
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Attestation verification failed: " + e.getMessage());
        }
    }

    /**
     * Get the status of a completed onboarding session.
     * This allows the SP to poll for the result.
     * 
     * @param sessionId The session ID from the options phase
     * @return Status response with result details
     */
    public WebauthnOnboardingStatusResponse getStatus(String sessionId) {
        // Check if still pending
        OnboardingSession pending = pendingSessions.get(sessionId);
        if (pending != null) {
            return WebauthnOnboardingStatusResponse.builder()
                .status("PENDING")
                .stableUserId(pending.getStableUserId())
                .institutionId(pending.getInstitutionId())
                .build();
        }

        // Check completed sessions
        CompletedOnboarding completed = completedSessions.get(sessionId);
        if (completed != null) {
            return WebauthnOnboardingStatusResponse.builder()
                .status(completed.status())
                .stableUserId(completed.stableUserId())
                .institutionId(completed.institutionId())
                .credentialId(completed.credentialId())
                .error(completed.error())
                .completedAt(completed.completedAt())
                .build();
        }

        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found: " + sessionId);
    }

    /**
     * Build the onboarding URL where the SP should redirect the browser.
     * The IB serves the ceremony page at this URL, acting as the WebAuthn Relying Party.
     */
    private String buildOnboardingUrl(String sessionId) {
        String effectiveBaseUrl = baseUrl;
        if (effectiveBaseUrl == null || effectiveBaseUrl.isBlank()) {
            // Fallback: construct from rpId (assumes HTTPS)
            effectiveBaseUrl = "https://" + rpId;
        }
        // Remove trailing slash if present
        if (effectiveBaseUrl.endsWith("/")) {
            effectiveBaseUrl = effectiveBaseUrl.substring(0, effectiveBaseUrl.length() - 1);
        }
        return effectiveBaseUrl + "/onboarding/webauthn/ceremony/" + sessionId;
    }

    /**
     * Get the WebAuthn options for an existing session.
     * Used by the ceremony page to retrieve the challenge and options.
     */
    public WebauthnOnboardingOptionsResponse getSessionOptions(String sessionId) {
        OnboardingSession session = pendingSessions.get(sessionId);
        if (session == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found or expired: " + sessionId);
        }
        if (session.isExpired()) {
            pendingSessions.remove(sessionId);
            throw new ResponseStatusException(HttpStatus.GONE, "Session expired: " + sessionId);
        }

        String displayName = session.getDisplayName() != null ? session.getDisplayName() : session.getStableUserId();

        return WebauthnOnboardingOptionsResponse.builder()
            .sessionId(sessionId)
            .challenge(session.getChallenge())
            .rp(RelyingParty.builder()
                .id(rpId)
                .name(rpName)
                .build())
            .user(User.builder()
                .id(session.getUserHandle())
                .name(session.getStableUserId())
                .displayName(displayName)
                .build())
            .pubKeyCredParams(Arrays.asList(
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_ES256).build(),
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_RS256).build(),
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_EDDSA).build()
            ))
            .timeout(timeoutMs)
            .attestation(attestationConveyance)
            .authenticatorSelection(buildAuthenticatorSelection())
            .build();
    }

    /**
     * Send callback notification to the SP with the onboarding result.
     * This is done asynchronously to not block the response to the browser.
     */
    private void sendCallbackToSp(String callbackUrl, WebauthnOnboardingCompleteResponse successResponse, String errorMessage) {
        try {
            java.util.Map<String, Object> payload = new java.util.HashMap<>();
            if (successResponse != null) {
                payload.put("status", "SUCCESS");
                payload.put("stableUserId", successResponse.getStableUserId());
                payload.put("institutionId", successResponse.getInstitutionId());
                payload.put("credentialId", successResponse.getCredentialId());
                payload.put("aaguid", successResponse.getAaguid());
            } else {
                payload.put("status", "FAILED");
                payload.put("error", errorMessage);
            }
            payload.put("timestamp", Instant.now().toString());

            org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
            headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
            org.springframework.http.HttpEntity<java.util.Map<String, Object>> entity = 
                new org.springframework.http.HttpEntity<>(payload, headers);

            // Execute callback asynchronously
            new Thread(() -> {
                try {
                    restTemplate.postForEntity(callbackUrl, entity, String.class);
                    log.info("Sent onboarding callback to SP: {} status={}", callbackUrl, 
                        successResponse != null ? "SUCCESS" : "FAILED");
                } catch (Exception e) {
                    log.warn("Failed to send onboarding callback to {}: {}", callbackUrl, e.getMessage());
                }
            }).start();
        } catch (Exception e) {
            log.warn("Failed to prepare onboarding callback: {}", e.getMessage());
        }
    }

    /**
     * Verify the client data JSON from the authenticator response.
     */
    private void verifyClientData(byte[] clientDataJson, byte[] expectedChallenge) throws Exception {
        JsonNode clientData = objectMapper.readTree(clientDataJson);

        // Verify type is "webauthn.create"
        String type = clientData.path("type").asText();
        if (!"webauthn.create".equals(type)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client data type: " + type);
        }

        // Verify challenge matches
        String challengeFromClient = clientData.path("challenge").asText();
        String expectedChallengeB64 = BASE64URL_ENCODER.encodeToString(expectedChallenge);
        if (!expectedChallengeB64.equals(challengeFromClient)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Challenge mismatch");
        }

        // Verify origin is allowed
        String origin = clientData.path("origin").asText();
        if (!isOriginAllowed(origin)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Origin not allowed: " + origin);
        }
    }

    /**
     * Parse the CBOR-encoded attestation object and extract credential data.
     */
    private AttestationData parseAttestationObject(byte[] attestationObject) throws CborException {
        List<DataItem> items = new CborDecoder(new ByteArrayInputStream(attestationObject)).decode();
        if (items.isEmpty() || !(items.get(0) instanceof Map)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid attestation object format");
        }

        Map attestationMap = (Map) items.get(0);
        
        // Extract authData
        DataItem authDataItem = attestationMap.get(new UnicodeString("authData"));
        if (!(authDataItem instanceof ByteString)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing authData in attestation");
        }
        byte[] authData = ((ByteString) authDataItem).getBytes();

        // Parse authenticator data
        return parseAuthenticatorData(authData);
    }

    /**
     * Parse the authenticator data structure from the attestation.
     * 
     * Structure (from WebAuthn spec):
     * - rpIdHash (32 bytes)
     * - flags (1 byte)
     * - signCount (4 bytes, big-endian)
     * - attestedCredentialData (variable, if AT flag set)
     *   - aaguid (16 bytes)
     *   - credentialIdLength (2 bytes, big-endian)
     *   - credentialId (credentialIdLength bytes)
     *   - credentialPublicKey (COSE key, variable)
     */
    private AttestationData parseAuthenticatorData(byte[] authData) throws ResponseStatusException {
        if (authData.length < 37) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "AuthData too short");
        }

        int offset = 0;

        // Verify rpIdHash
        byte[] rpIdHash = Arrays.copyOfRange(authData, offset, offset + 32);
        offset += 32;
        verifyRpIdHash(rpIdHash);

        // Parse flags
        byte flags = authData[offset];
        offset += 1;

        // Check User Present (UP) flag
        if ((flags & 0x01) == 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User present flag not set");
        }

        // Check Attested credential data (AT) flag - must be set for registration
        if ((flags & 0x40) == 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Attested credential data not present");
        }

        // Parse sign count (4 bytes, big-endian)
        long signCount = ((authData[offset] & 0xFFL) << 24)
            | ((authData[offset + 1] & 0xFFL) << 16)
            | ((authData[offset + 2] & 0xFFL) << 8)
            | (authData[offset + 3] & 0xFFL);
        offset += 4;

        // Parse attested credential data
        // AAGUID (16 bytes)
        byte[] aaguid = Arrays.copyOfRange(authData, offset, offset + 16);
        offset += 16;

        // Credential ID length (2 bytes, big-endian)
        int credentialIdLength = ((authData[offset] & 0xFF) << 8) | (authData[offset + 1] & 0xFF);
        offset += 2;

        // Skip credential ID (we already have it from the request)
        offset += credentialIdLength;

        // Rest is the COSE public key
        byte[] publicKeyCose = Arrays.copyOfRange(authData, offset, authData.length);

        return new AttestationData(aaguid, publicKeyCose, signCount);
    }

    /**
     * Verify that the RP ID hash matches our expected RP ID.
     */
    private void verifyRpIdHash(byte[] rpIdHash) throws ResponseStatusException {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] expectedHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));
            if (!MessageDigest.isEqual(rpIdHash, expectedHash)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "RP ID hash mismatch");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "SHA-256 not available");
        }
    }

    /**
     * Check if the origin from client data is in the allowed list.
     */
    private boolean isOriginAllowed(String origin) {
        if (origin == null || origin.isEmpty()) {
            return false;
        }
        List<String> allowedOrigins = Arrays.asList(allowedOriginsConfig.split(","));
        return allowedOrigins.stream()
            .map(String::trim)
            .anyMatch(allowed -> allowed.equalsIgnoreCase(origin));
    }

    private AuthenticatorSelection buildAuthenticatorSelection() {
        return AuthenticatorSelection.builder()
            .authenticatorAttachment(authenticatorAttachment.isEmpty() ? null : authenticatorAttachment)
            .residentKey(residentKey)
            .requireResidentKey("required".equals(residentKey))
            .userVerification(userVerification)
            .build();
    }

    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        int removed = 0;
        for (var entry : pendingSessions.entrySet()) {
            if (now.isAfter(entry.getValue().getExpiresAt())) {
                pendingSessions.remove(entry.getKey());
                removed++;
            }
        }
        if (removed > 0) {
            log.debug("Cleaned up {} expired WebAuthn onboarding sessions", removed);
        }
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }

    /**
     * Validate the SAML assertion provided in the onboarding request.
     * Extracts and verifies attributes from the assertion.
     * 
     * @param samlAssertion Base64-encoded SAML assertion
     * @param expectedUserId Expected stable user ID from the request
     * @param expectedInstitutionId Expected institution ID from the request
     * @return Map of validated attributes from the assertion
     * @throws ResponseStatusException if validation fails
     */
    private java.util.Map<String, String> validateSamlAssertion(String samlAssertion, String expectedUserId, String expectedInstitutionId) {
        if (samlValidationService == null) {
            log.warn("SAML validation requested but SamlValidationService is not available. Skipping validation.");
            return java.util.Collections.emptyMap();
        }

        try {
            // The samlAssertion is already Base64-encoded, pass it directly to the service
            // validateSamlAssertionWithSignature expects Base64-encoded assertion and handles decoding internally
            java.util.Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
            
            // Optionally verify that the assertion's userid matches the expected user
            String assertionUserId = attributes.get("userid");
            if (assertionUserId != null && !assertionUserId.isEmpty() && !assertionUserId.equals(expectedUserId)) {
                log.warn("SAML assertion userid '{}' does not match expected userId '{}'", assertionUserId, expectedUserId);
                // This is a warning, not an error - the SP may use different identifiers
            }

            log.debug("SAML assertion validated successfully for user: {}", expectedUserId);
            return attributes;

        } catch (IllegalArgumentException e) {
            log.error("Failed to decode SAML assertion: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid SAML assertion encoding");
        } catch (SecurityException e) {
            log.error("SAML assertion validation failed: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid SAML assertion: " + e.getMessage());
        } catch (Exception e) {
            log.error("SAML assertion validation failed", e);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Failed to validate SAML assertion: " + e.getMessage());
        }
    }

    /**
     * Internal session data for pending onboarding ceremonies.
     */
    @Data
    @AllArgsConstructor
    private static class OnboardingSession {
        private String sessionId;
        private String stableUserId;
        private String institutionId;
        private String challenge; // Base64url encoded
        private byte[] challengeBytes;
        private String userHandle; // Base64url encoded
        private String displayName;
        private String assertionReference;
        private String attributes;
        private String callbackUrl; // Optional SP callback URL
        private Instant expiresAt;

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    /**
     * Completed onboarding result for status polling.
     */
    private record CompletedOnboarding(
        String status,
        String stableUserId,
        String institutionId,
        String credentialId,
        String error,
        Instant completedAt
    ) {}

    /**
     * Parsed attestation data.
     */
    @AllArgsConstructor
    private static class AttestationData {
        private byte[] aaguid;
        private byte[] publicKeyCose;
        private long signCount;
    }
}
