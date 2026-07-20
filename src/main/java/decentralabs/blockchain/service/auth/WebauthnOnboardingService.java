package decentralabs.blockchain.service.auth;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
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
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.util.LogSanitizer;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
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
    private final BackendUrlResolver backendUrlResolver;

    @Value("${webauthn.rp.id:}")
    private String rpId;

    @Value("${webauthn.rp.name:DecentraLabs Gateway}")
    private String rpName;

    @Value("${webauthn.rp.origins:#{null}}")
    private String allowedOriginsConfig;

    @Value("${gateway.server.name:localhost}")
    private String serverName;

    @Value("${gateway.server.https-port:443}")
    private String httpsPort;

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

    @Value("${webauthn.user-verification:required}")
    private String userVerification;

    @Value("${webauthn.validate-saml:true}")
    private boolean validateSaml;

    @Value("${webauthn.completed-session.ttl.seconds:3600}")
    private long completedSessionTtlSeconds;

    @Value("${webauthn.base-url:}")
    private String baseUrl;

    public WebauthnOnboardingService(
            WebauthnCredentialService credentialService,
            ObjectProvider<SamlValidationService> samlValidationServiceProvider,
            BackendUrlResolver backendUrlResolver) {
        this.credentialService = credentialService;
        this.samlValidationService = samlValidationServiceProvider.getIfAvailable();
        this.backendUrlResolver = backendUrlResolver;
        if (this.samlValidationService == null) {
            log.warn("SamlValidationService not available. SAML assertion validation will be skipped.");
        }
    }

    @PostConstruct
    public void init() {
        if (!"none".equalsIgnoreCase(attestationConveyance)) {
            throw new IllegalStateException("Only attestation=none is supported by the WebAuthn RP");
        }
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
        log.info("WebAuthn Onboarding Service initialized. RP ID: {}, Session TTL: {}s", getEffectiveRpId(), sessionTtlSeconds);
    }

    /**
     * Returns the effective Relying Party ID.
     * Falls back to extracting hostname from BackendUrlResolver if not explicitly configured.
     */
    private String getEffectiveRpId() {
        if (rpId != null && !rpId.isBlank()) {
            return rpId;
        }
        // Extract hostname from the resolved base domain (e.g., "https://your.gateway.example" -> "your.gateway.example")
        String baseDomain = backendUrlResolver.resolveBaseDomain();
        try {
            java.net.URI uri = new java.net.URI(baseDomain);
            String host = uri.getHost();
            return (host != null && !host.isBlank()) ? host : "localhost";
        } catch (Exception e) {
            log.warn("Failed to extract host from base domain '{}', using 'localhost': {}",
                LogSanitizer.sanitize(baseDomain), LogSanitizer.sanitize(e.getMessage()));
            return "localhost";
        }
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
                log.debug("Interrupted while stopping WebAuthn cleanup scheduler", e);
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
            validateSamlAssertion(
                request.getSamlAssertion(),
                stableUserId,
                request.getStableUserIdMode(),
                institutionId
            );
            // codeql[java/log-injection]
            log.debug("SAML assertion validated for user: {}", LogSanitizer.maskIdentifier(stableUserId));
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
            expiresAt
        );
        pendingSessions.put(sessionId, session);

        log.info("WebAuthn onboarding session created");

        // Build the onboarding URL where the SP should redirect the browser
        String onboardingUrl = buildOnboardingUrl(sessionId);

        // Build response following W3C WebAuthn spec
        String displayName = request.getDisplayName() != null ? request.getDisplayName() : stableUserId;

        return WebauthnOnboardingOptionsResponse.builder()
            .sessionId(sessionId)
            .onboardingUrl(onboardingUrl)
            .challenge(challenge)
            .rp(RelyingParty.builder()
                .id(getEffectiveRpId())
                .name(rpName)
                .build())
            .user(User.builder()
                .id(userHandle)
                .name(stableUserId)
                .displayName(displayName)
                .build())
            .pubKeyCredParams(Arrays.asList(
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_ES256).build(),
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_RS256).build()
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
            byte[] requestedCredentialId = decodeCredentialId(request.getCredentialId());
            if (!MessageDigest.isEqual(requestedCredentialId, attestationData.credentialId)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential ID mismatch");
            }
            String credentialId = BASE64URL_ENCODER.encodeToString(attestationData.credentialId);

            String transports = normalizeTransports(request.getTransports());
            String attachment = inferAuthenticatorAttachment(request.getTransports());

            // Store the credential binding using existing service
            credentialService.register(
                session.getStableUserId(),
                credentialId,
                publicKeyBase64,
                aaguid,
                attestationData.signCount,
                attachment,
                attestationData.residentKey,
                transports
            );

            // codeql[java/log-injection]
            log.info("WebAuthn credential registered. stableUserIdPresent={} credentialIdLength={}",
                session.getStableUserId() != null && !session.getStableUserId().isBlank(),
                credentialId.length());

            WebauthnOnboardingCompleteResponse response = WebauthnOnboardingCompleteResponse.builder()
                .success(true)
                .stableUserId(session.getStableUserId())
                .institutionId(session.getInstitutionId())
                .credentialId(credentialId)
                .publicKey(publicKeyBase64)
                .rpId(getEffectiveRpId())
                .aaguid(aaguid)
                .message("Credential registered successfully")
                .timestamp(Instant.now().getEpochSecond())
                .build();

            // Store completed onboarding for status polling
            CompletedOnboarding completed = new CompletedOnboarding(
                "SUCCESS",
                session.getStableUserId(),
                session.getInstitutionId(),
                credentialId,
                publicKeyBase64,
                getEffectiveRpId(),
                null,
                Instant.now()
            );
            completedSessions.put(sessionId, completed);

            return response;

        } catch (ResponseStatusException e) {
            // Store failure for status polling
            CompletedOnboarding failed = new CompletedOnboarding(
                "FAILED",
                session.getStableUserId(),
                session.getInstitutionId(),
                null,
                null,
                null,
                e.getReason(),
                Instant.now()
            );
            completedSessions.put(sessionId, failed);
            
            throw e;
        } catch (Exception e) {
            log.error("WebAuthn attestation verification failed", e);
            
            // Store failure for status polling
            CompletedOnboarding failed = new CompletedOnboarding(
                "FAILED",
                session.getStableUserId(),
                session.getInstitutionId(),
                null,
                null,
                null,
                "Attestation verification failed: " + e.getMessage(),
                Instant.now()
            );
            completedSessions.put(sessionId, failed);
            
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
                .publicKey(completed.publicKey())
                .rpId(completed.rpId())
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
            // Use BackendUrlResolver which resolves from SERVER_NAME/BASE_DOMAIN
            effectiveBaseUrl = backendUrlResolver.resolveBaseDomain();
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
                .id(getEffectiveRpId())
                .name(rpName)
                .build())
            .user(User.builder()
                .id(session.getUserHandle())
                .name(session.getStableUserId())
                .displayName(displayName)
                .build())
            .pubKeyCredParams(Arrays.asList(
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_ES256).build(),
                PubKeyCredParam.builder().type("public-key").alg(COSE_ALG_RS256).build()
            ))
            .timeout(timeoutMs)
            .attestation(attestationConveyance)
            .authenticatorSelection(buildAuthenticatorSelection())
            .build();
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
        if (items.size() != 1 || !(items.get(0) instanceof Map)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid attestation object format");
        }

        Map attestationMap = (Map) items.get(0);

        DataItem fmtItem = attestationMap.get(new UnicodeString("fmt"));
        if (!(fmtItem instanceof UnicodeString) || !"none".equals(((UnicodeString) fmtItem).getString())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported attestation format");
        }

        DataItem attStmtItem = attestationMap.get(new UnicodeString("attStmt"));
        if (!(attStmtItem instanceof Map) || !((Map) attStmtItem).getKeys().isEmpty()) {
            // The RP deliberately requests attestation=none. Any non-empty
            // statement would require a format-specific trust policy and
            // cryptographic verification that this service does not provide.
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Attestation statement is not allowed");
        }
        
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

        // Institutional credentials are later used to authorize spending
        // intents, so registration must establish user verification too.
        if ((flags & 0x04) == 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User verification flag not set");
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
        if (authData.length < offset + 16 + 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Attested credential data truncated");
        }

        // AAGUID (16 bytes)
        byte[] aaguid = Arrays.copyOfRange(authData, offset, offset + 16);
        offset += 16;

        // Credential ID length (2 bytes, big-endian)
        int credentialIdLength = ((authData[offset] & 0xFF) << 8) | (authData[offset + 1] & 0xFF);
        offset += 2;

        if (credentialIdLength == 0 || authData.length < offset + credentialIdLength) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credential ID in authenticator data");
        }

        byte[] credentialId = Arrays.copyOfRange(authData, offset, offset + credentialIdLength);
        offset += credentialIdLength;

        // Rest is the COSE public key
        if (offset >= authData.length) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing credential public key");
        }
        byte[] publicKeyCose = Arrays.copyOfRange(authData, offset, authData.length);
        validateCosePublicKey(publicKeyCose);

        boolean residentKey = (flags & 0x20) != 0;

        return new AttestationData(aaguid, credentialId, publicKeyCose, signCount, residentKey);
    }

    private byte[] decodeCredentialId(String credentialId) throws ResponseStatusException {
        if (credentialId == null || credentialId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential ID is required");
        }
        try {
            byte[] decoded = BASE64URL_DECODER.decode(credentialId);
            if (decoded.length == 0 || decoded.length > 1023) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credential ID");
            }
            String canonical = BASE64URL_ENCODER.encodeToString(decoded);
            if (!canonical.equals(credentialId)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential ID is not canonical base64url");
            }
            return decoded;
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credential ID", ex);
        }
    }

    private void validateCosePublicKey(byte[] publicKeyCose) throws ResponseStatusException {
        try {
            List<DataItem> items = new CborDecoder(new ByteArrayInputStream(publicKeyCose)).decode();
            if (items.size() != 1 || !(items.get(0) instanceof Map coseKey)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credential public key");
            }
            Long keyType = getCoseLong(coseKey, 1);
            Long algorithm = getCoseLong(coseKey, 3);
            if (keyType == null || algorithm == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential public key is missing type or algorithm");
            }
            if (keyType == 2L && algorithm == COSE_ALG_ES256) {
                if (!Long.valueOf(1L).equals(getCoseLong(coseKey, -1))
                    || !hasCoseBytes(coseKey, -2, 32)
                    || !hasCoseBytes(coseKey, -3, 32)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid ES256 credential public key");
                }
                return;
            }
            if (keyType == 3L && algorithm == COSE_ALG_RS256) {
                if (!hasCoseBytesAtLeast(coseKey, -1, 256 / 8)
                    || !hasCoseBytesAtLeast(coseKey, -2, 3)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid RS256 credential public key");
                }
                return;
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported credential public key algorithm");
        } catch (CborException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credential public key", ex);
        }
    }

    private Long getCoseLong(Map coseKey, long key) {
        DataItem item = coseKey.get(key >= 0 ? new UnsignedInteger(key) : new NegativeInteger(key));
        if (item instanceof UnsignedInteger unsignedInteger) {
            return unsignedInteger.getValue().longValue();
        }
        if (item instanceof NegativeInteger negativeInteger) {
            return negativeInteger.getValue().longValue();
        }
        return null;
    }

    private boolean hasCoseBytes(Map coseKey, long key, int expectedLength) {
        DataItem item = coseKey.get(key >= 0 ? new UnsignedInteger(key) : new NegativeInteger(key));
        return item instanceof ByteString byteString && byteString.getBytes().length == expectedLength;
    }

    private boolean hasCoseBytesAtLeast(Map coseKey, long key, int minimumLength) {
        DataItem item = coseKey.get(key >= 0 ? new UnsignedInteger(key) : new NegativeInteger(key));
        return item instanceof ByteString byteString && byteString.getBytes().length >= minimumLength;
    }

    /**
     * Verify that the RP ID hash matches our expected RP ID.
     */
    private void verifyRpIdHash(byte[] rpIdHash) throws ResponseStatusException {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] expectedHash = sha256.digest(getEffectiveRpId().getBytes(StandardCharsets.UTF_8));
            if (!MessageDigest.isEqual(rpIdHash, expectedHash)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "RP ID hash mismatch");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "SHA-256 not available", e);
        }
    }

    /**
     * Check if the origin from client data is in the allowed list.
     */
    private boolean isOriginAllowed(String origin) {
        if (origin == null || origin.isEmpty()) {
            return false;
        }

        List<String> allowedOrigins = buildAllowedOrigins();
        boolean allowed = allowedOrigins.stream()
            .anyMatch(candidate -> candidate.equalsIgnoreCase(origin));

        if (!allowed) {
            log.warn("WebAuthn origin is not in the allowed list");
        }

        return allowed;
    }

    private List<String> buildAllowedOrigins() {
        Set<String> origins = new HashSet<>();

        // 0) Include explicitly configured values (even if they are the defaults)
        if (allowedOriginsConfig != null && !allowedOriginsConfig.trim().isEmpty()) {
            origins.addAll(Arrays.stream(allowedOriginsConfig.split(","))
                .map(origin -> origin.trim())
                .filter(s -> !s.isEmpty())
                .toList());
        }

        // 1) Derive from effective RP ID + HTTPS port
        String rpHost = getEffectiveRpId();
        if (rpHost != null && !rpHost.isBlank()) {
            String portSegment = "443".equals(httpsPort) ? "" : ":" + httpsPort;
            origins.add("https://" + rpHost + portSegment);
        }

        // 2) Derive from SERVER_NAME if present
        if (serverName != null && !serverName.isBlank()) {
            String portSegment = "443".equals(httpsPort) ? "" : ":" + httpsPort;
            origins.add("https://" + serverName + portSegment);
        }

        // 3) Derive from backend base domain (may include scheme)
        String baseDomain = backendUrlResolver.resolveBaseDomain();
        if (baseDomain != null && !baseDomain.isBlank()) {
            try {
                java.net.URI uri = new java.net.URI(baseDomain);
                if (uri.getScheme() != null && uri.getHost() != null) {
                    String portSegment = uri.getPort() > 0 && uri.getPort() != 443 ? ":" + uri.getPort() : "";
                    origins.add(uri.getScheme() + "://" + uri.getHost() + portSegment);
                } else {
                    // If no scheme, assume https
                    origins.add("https://" + baseDomain);
                }
            } catch (Exception e) {
                log.warn("Failed to parse base domain for WebAuthn origins {}: {}",
                    LogSanitizer.sanitize(baseDomain), LogSanitizer.sanitize(e.getMessage()));
            }
        }

        // Fallback to localhost if nothing else is available
        if (origins.isEmpty()) {
            origins.add("https://localhost");
            origins.add("https://localhost:443");
        }

        List<String> result = new ArrayList<>(origins);
        log.info("WebAuthn allowed origins configured. count={}", result.size());
        return result;
    }

    private AuthenticatorSelection buildAuthenticatorSelection() {
        return AuthenticatorSelection.builder()
            .authenticatorAttachment(authenticatorAttachment.isEmpty() ? null : authenticatorAttachment)
            .residentKey(residentKey)
            .requireResidentKey("required".equals(residentKey))
            .userVerification("required")
            .build();
    }

    private String normalizeTransports(String[] transports) {
        if (transports == null || transports.length == 0) return null;
        return Arrays.stream(transports)
            .filter(t -> t != null && !t.trim().isEmpty())
            .map(t -> t.trim().toLowerCase())
            .distinct()
            .reduce((a, b) -> a + "," + b)
            .orElse(null);
    }

    private String inferAuthenticatorAttachment(String[] transports) {
        if (transports == null || transports.length == 0) return null;
        List<String> normalized = Arrays.stream(transports)
            .filter(t -> t != null && !t.trim().isEmpty())
            .map(t -> t.trim().toLowerCase())
            .distinct()
            .toList();
        if (normalized.isEmpty()) return null;
        boolean hasInternal = normalized.contains("internal");
        boolean hasExternal = normalized.stream().anyMatch(t -> !"internal".equals(t));
        if (hasInternal && hasExternal) return "mixed";
        if (hasInternal) return "platform";
        return "cross-platform";
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
        // Also clean up completed sessions past their TTL
        Instant completedCutoff = now.minusSeconds(completedSessionTtlSeconds);
        int completedRemoved = 0;
        for (var entry : completedSessions.entrySet()) {
            if (entry.getValue().completedAt() != null && entry.getValue().completedAt().isBefore(completedCutoff)) {
                completedSessions.remove(entry.getKey());
                completedRemoved++;
            }
        }
        if (completedRemoved > 0) {
            log.debug("Cleaned up {} expired completed WebAuthn sessions", completedRemoved);
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
     * @param expectedPuc Expected PUC from the request
     * @param stableUserIdMode PUC derivation mode used by Marketplace
     * @param expectedInstitutionId Expected institution ID from the request
     * @return Map of validated attributes from the assertion
     * @throws ResponseStatusException if validation fails
     */
    private java.util.Map<String, String> validateSamlAssertion(
            String samlAssertion,
            String expectedPuc,
            String stableUserIdMode,
            String expectedInstitutionId) {
        if (samlValidationService == null) {
            log.warn("SAML validation requested but SamlValidationService is not available. Skipping validation.");
            return java.util.Collections.emptyMap();
        }

        try {
            // The samlAssertion is already Base64-encoded, pass it directly to the service
            // validateSamlAssertionWithSignature expects Base64-encoded assertion and handles decoding internally
            java.util.Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
            
            String assertionPuc = samlValidationService.resolveStableUserId(attributes, stableUserIdMode, null);
            if (assertionPuc != null && !assertionPuc.isBlank() && !assertionPuc.equals(expectedPuc)) {
                log.warn("SAML assertion PUC does not match expected PUC");
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "saml_puc_mismatch");
            }
            String assertionInstitutionId = attributes.get("institutionId");
            if (assertionInstitutionId != null
                && !assertionInstitutionId.isBlank()
                && expectedInstitutionId != null
                && !expectedInstitutionId.isBlank()
                && !assertionInstitutionId.equals(expectedInstitutionId)) {
                log.warn("SAML assertion institutionId does not match expected institutionId");
            }

            log.debug("SAML assertion validated successfully");
            return attributes;

        } catch (IllegalArgumentException e) {
            log.error("Failed to decode SAML assertion");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid SAML assertion encoding");
        } catch (SecurityException e) {
            log.error("SAML assertion validation failed");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid SAML assertion: " + e.getMessage());
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            log.error("SAML assertion validation failed");
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
        String publicKey,
        String rpId,
        String error,
        Instant completedAt
    ) {}

    /**
     * Parsed attestation data.
     */
    @AllArgsConstructor
    private static class AttestationData {
        private byte[] aaguid;
        private byte[] credentialId;
        private byte[] publicKeyCose;
        private long signCount;
        private boolean residentKey;
    }
}
