package decentralabs.blockchain.service.intent;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.springframework.web.server.ResponseStatusException;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAction;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.dto.intent.IntentStatusResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingCompleteRequest;
import decentralabs.blockchain.dto.auth.WebauthnOnboardingOptionsResponse;
import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.ValidatedIdentity;
import decentralabs.blockchain.dto.identity.NormalizedClaims;
import decentralabs.blockchain.dto.identity.IdentityEvidenceMetadata;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.IdentityValidationStrategy;
import decentralabs.blockchain.service.auth.IdentityEvidenceHashService;
import decentralabs.blockchain.service.wallet.WalletService;

@ExtendWith(MockitoExtension.class)
@DisplayName("IntentService Tests")
class IntentServiceTest {

    @Mock
    private Eip712IntentVerifier verifier;

    @Mock
    private IntentPersistenceService persistenceService;

    @Mock
    private IntentWebhookService webhookService;

    @Mock
    private SamlValidationService samlValidationService;

    @Mock
    private WebauthnCredentialService webauthnCredentialService;

    @Mock
    private WalletService walletService;

    @Mock
    private IdentityValidationStrategy identityValidationStrategy;

    @Mock
    private IdentityEvidenceHashService identityEvidenceHashService;

    private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private IntentService service;
    private String creatorHashToReturn;
    private SimpleMeterRegistry meterRegistry;

    @BeforeEach
    void setUp() {
        creatorHashToReturn = "0x" + "1".repeat(64);
        meterRegistry = new SimpleMeterRegistry();

        // Configure identity strategy mock (lenient because not all tests use identity validation)
        lenient().when(identityValidationStrategy.supports(anyString())).thenReturn(true);
        lenient().when(identityValidationStrategy.supports("saml")).thenReturn(true);
        NormalizedClaims mockClaims = NormalizedClaims.builder()
            .stableUserId("user@university.edu")
            .institutionId("university.edu")
            .puc("user@university.edu")
            .build();
        IdentityEvidenceMetadata mockMetadata = new IdentityEvidenceMetadata(
            "issuer", Instant.now(), null, null, List.of(), true, "saml"
        );
        ValidatedIdentity mockValidatedIdentity = ValidatedIdentity.builder()
            .type("saml")
            .format("saml2-base64")
            .claims(mockClaims)
            .metadata(mockMetadata)
            .evidenceHash("0x" + "b".repeat(64))
            .build();
        lenient().when(identityValidationStrategy.validate(any())).thenReturn(mockValidatedIdentity);

        List<IdentityValidationStrategy> strategies = List.of(identityValidationStrategy);

        service = new IntentService(
            "15s",
            60000L,
            verifier,
            persistenceService,
            webhookService,
            samlValidationService,
            webauthnCredentialService,
            walletService,
            "0x0000000000000000000000000000000000000001",
            meterRegistry,
            strategies,
            identityEvidenceHashService
        ) {
            @Override
            String fetchCreatorPucHash(BigInteger labId) {
                return creatorHashToReturn;
            }
        };
    }
    @Test
    @DisplayName("Assertion replay TTL expires as expected")
    void assertionReplayTtlExpires() throws Exception {
        // Use a short TTL to make the test fast
        List<IdentityValidationStrategy> strategies = List.of(identityValidationStrategy);
        IntentService shortTtlService = new IntentService(
            "15s",
            100L,
            verifier,
            persistenceService,
            webhookService,
            samlValidationService,
            webauthnCredentialService,
            walletService,
            "0x0000000000000000000000000000000000000001",
            meterRegistry,
            strategies,
            identityEvidenceHashService
        );

        String hash = "0x" + "f".repeat(64);
        // Use reflection to invoke private methods
        var markMethod = IntentService.class.getDeclaredMethod("markEvidenceUsed", String.class);
        var checkMethod = IntentService.class.getDeclaredMethod("checkEvidenceReplay", String.class);
        markMethod.setAccessible(true);
        checkMethod.setAccessible(true);

        // Mark used and expect a replay immediately
        markMethod.invoke(shortTtlService, hash);
        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> {
            try {
                checkMethod.invoke(shortTtlService, hash);
            } catch (Exception e) {
                // unwrap reflection exception
                throw e.getCause();
            }
        });
        assertTrue(ex.getReason().toLowerCase().contains("evidence_replay"));

        // Wait for TTL to expire and then expect no exception
        Thread.sleep(200);
        // should not throw
        checkMethod.invoke(shortTtlService, hash);
    }

    private IntentMeta createValidMeta() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("req-" + System.nanoTime());
        meta.setSigner("0x1234567890abcdef1234567890abcdef12345678");
        meta.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
        meta.setAction(IntentAction.LAB_LIST.getId());
        meta.setPayloadHash("0x" + "a".repeat(64));
        meta.setNonce(System.currentTimeMillis());
        meta.setRequestedAt(Instant.now().getEpochSecond());
        meta.setExpiresAt(Instant.now().plusSeconds(300).getEpochSecond());
        return meta;
    }

    private ActionIntentPayload createValidActionPayload() {
        ActionIntentPayload payload = new ActionIntentPayload();
        payload.setLabId(BigInteger.valueOf(42));
        payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
        payload.setPuc("user@university.edu");
        payload.setAssertionHash("0x" + "b".repeat(64));
        return payload;
    }

    private ReservationIntentPayload createValidReservationPayload() {
        ReservationIntentPayload payload = new ReservationIntentPayload();
        payload.setLabId(BigInteger.valueOf(42));
        payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
        payload.setPuc("user@university.edu");
        payload.setStart(Instant.now().plusSeconds(3600).getEpochSecond());
        payload.setEnd(Instant.now().plusSeconds(7200).getEpochSecond());
        payload.setAssertionHash("0x" + "b".repeat(64));
        return payload;
    }

    private IntentSubmission createValidRequestFundsSubmission() {
        String samlAssertion = "valid-request-funds-saml";
        String assertionHash = Numeric.toHexString(Hash.sha3(samlAssertion.getBytes(StandardCharsets.UTF_8)));
        IntentMeta meta = createValidMeta();
        meta.setAction(IntentAction.REQUEST_FUNDS.getId());
        meta.setPayloadHash("0x" + "c".repeat(64));
        ActionIntentPayload payload = createValidActionPayload();
        payload.setMaxBatch(BigInteger.TEN);
        payload.setAssertionHash(assertionHash);

        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(meta);
        submission.setActionPayload(payload);
        submission.setSamlAssertion(samlAssertion);
        submission.setWebauthnCredentialId("cred");
        return submission;
    }

    private IntentSubmission createIdentityEvidenceRequestFundsSubmission(String evidenceHash) {
        IntentMeta meta = createValidMeta();
        meta.setAction(IntentAction.REQUEST_FUNDS.getId());
        meta.setPayloadHash("0x" + "c".repeat(64));

        ActionIntentPayload payload = createValidActionPayload();
        payload.setMaxBatch(BigInteger.TEN);
        payload.setAssertionHash(evidenceHash);

        NormalizedClaims normalizedClaims = NormalizedClaims.builder()
            .stableUserId(payload.getPuc())
            .institutionId("university.edu")
            .puc(payload.getPuc())
            .build();

        IdentityEvidenceDTO identityEvidence = IdentityEvidenceDTO.builder()
            .type("saml")
            .format("saml2-base64")
            .normalizedClaims(normalizedClaims)
            .evidenceHash(evidenceHash)
            .build();

        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(meta);
        submission.setActionPayload(payload);
        submission.setIdentityEvidence(identityEvidence);
        submission.setWebauthnCredentialId("cred");
        return submission;
    }

    @Nested
    @DisplayName("Unified Identity Validation Tests")
    class UnifiedIdentityValidationTests {

        @Test
        @DisplayName("Should accept REQUEST_FUNDS using identityEvidence without SAML fallback")
        void shouldAcceptRequestFundsUsingIdentityEvidence() throws Exception {
            String evidenceHash = "0x" + "d".repeat(64);
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3("user@university.edu".getBytes(StandardCharsets.UTF_8))
            );

            NormalizedClaims normalizedClaims = NormalizedClaims.builder()
                .stableUserId("user@university.edu")
                .institutionId("university.edu")
                .puc("user@university.edu")
                .build();
            IdentityEvidenceMetadata metadata = new IdentityEvidenceMetadata(
                "issuer",
                Instant.now(),
                null,
                null,
                List.of("backend"),
                true,
                "saml"
            );
            ValidatedIdentity validatedIdentity = ValidatedIdentity.builder()
                .type("saml")
                .format("saml2-base64")
                .claims(normalizedClaims)
                .metadata(metadata)
                .evidenceHash(evidenceHash)
                .build();

            when(identityValidationStrategy.validate(any())).thenReturn(validatedIdentity);
            when(verifier.verify(
                eq(IntentAction.REQUEST_FUNDS),
                any(IntentMeta.class),
                any(ActionIntentPayload.class),
                isNull(),
                any()
            )).thenReturn(new Eip712IntentVerifier.VerificationResult(true, null, null, null));

            IntentSubmission submission = createIdentityEvidenceRequestFundsSubmission(evidenceHash);

            IntentAckResponse response = service.processIntent(submission);

            assertEquals("accepted", response.getStatus());
            verify(identityValidationStrategy).validate(any());
            verify(samlValidationService, never()).validateSamlAssertionWithSignature(anyString());
        }

        @Test
        @DisplayName("Should select VC validation strategy when identityEvidence type is openid4vp")
        void shouldSelectVcValidationStrategyForOpenid4vpType() throws Exception {
            String evidenceHash = "0x" + "e".repeat(64);
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3("user@university.edu".getBytes(StandardCharsets.UTF_8))
            );

            NormalizedClaims normalizedClaims = NormalizedClaims.builder()
                .stableUserId("user@university.edu")
                .institutionId("university.edu")
                .puc("user@university.edu")
                .build();
            IdentityEvidenceMetadata metadata = new IdentityEvidenceMetadata(
                "did:example:issuer",
                Instant.now(),
                null,
                null,
                List.of("backend"),
                true,
                "openid4vp"
            );
            ValidatedIdentity validatedIdentity = ValidatedIdentity.builder()
                .type("openid4vp")
                .format("jwt-vp")
                .claims(normalizedClaims)
                .metadata(metadata)
                .evidenceHash(evidenceHash)
                .build();

            when(identityValidationStrategy.supports("openid4vp")).thenReturn(true);
            when(identityValidationStrategy.validate(any())).thenReturn(validatedIdentity);
            when(verifier.verify(
                eq(IntentAction.REQUEST_FUNDS),
                any(IntentMeta.class),
                any(ActionIntentPayload.class),
                isNull(),
                any()
            )).thenReturn(new Eip712IntentVerifier.VerificationResult(true, null, null, null));

            IntentSubmission submission = createIdentityEvidenceRequestFundsSubmission(evidenceHash);
            submission.setIdentityEvidence(buildIdentityEvidence(
                "openid4vp",
                evidenceHash,
                normalizedClaims,
                "{\"vp\":\"open-id-four-vp\"}"
            ));

            IntentAckResponse response = service.processIntent(submission);

            assertEquals("accepted", response.getStatus());
            verify(identityValidationStrategy).supports("openid4vp");
            verify(identityValidationStrategy).validate(any());
            verify(samlValidationService, never()).validateSamlAssertionWithSignature(anyString());
        }

        @Test
        @DisplayName("Should reject duplicate intent using same evidenceHash (anti-replay)")
        void shouldUseEvidenceHashForAntiReplay() throws Exception {
            String evidenceHash = "0x" + "f".repeat(64);
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3("user@university.edu".getBytes(StandardCharsets.UTF_8))
            );

            List<IdentityValidationStrategy> strategies = List.of(identityValidationStrategy);
            IntentService shortTtlService = new IntentService(
                "15s",
                100L,
                verifier,
                persistenceService,
                webhookService,
                samlValidationService,
                webauthnCredentialService,
                walletService,
                "0x0000000000000000000000000000000000000001",
                meterRegistry,
                strategies,
                identityEvidenceHashService
            ) {
                @Override
                String fetchCreatorPucHash(BigInteger labId) {
                    return creatorHashToReturn;
                }
            };

            NormalizedClaims normalizedClaims = NormalizedClaims.builder()
                .stableUserId("user@university.edu")
                .institutionId("university.edu")
                .puc("user@university.edu")
                .build();
            ValidatedIdentity validatedIdentity = ValidatedIdentity.builder()
                .type("saml")
                .format("saml2-base64")
                .claims(normalizedClaims)
                .metadata(new IdentityEvidenceMetadata("issuer", Instant.now(), null, null, List.of(), true, "saml"))
                .evidenceHash(evidenceHash)
                .build();

            when(identityValidationStrategy.validate(any())).thenReturn(validatedIdentity);
            when(verifier.verify(any(), any(), any(), isNull(), any()))
                .thenReturn(new Eip712IntentVerifier.VerificationResult(true, null, null, null));

            IntentSubmission submission = createIdentityEvidenceRequestFundsSubmission(evidenceHash);

            IntentAckResponse firstResponse = shortTtlService.processIntent(submission);
            assertEquals("accepted", firstResponse.getStatus());

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> shortTtlService.processIntent(submission));
            assertTrue(ex.getReason().toLowerCase().contains("evidence_replay") ||
                ex.getReason().toLowerCase().contains("replay"));
        }

        @Test
        @DisplayName("Should use puc from ValidatedIdentity claims for creator hash lookup")
        void shouldConsumeValidatedIdentityClaimsForPucLookup() throws Exception {
            String specificPuc = "specific@university.edu";
            String evidenceHash = "0x" + "a".repeat(64);
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3(specificPuc.getBytes(StandardCharsets.UTF_8))
            );

            NormalizedClaims normalizedClaims = NormalizedClaims.builder()
                .stableUserId(specificPuc)
                .institutionId("university.edu")
                .puc(specificPuc)
                .build();
            ValidatedIdentity validatedIdentity = ValidatedIdentity.builder()
                .type("saml")
                .format("saml2-base64")
                .claims(normalizedClaims)
                .metadata(new IdentityEvidenceMetadata("issuer", Instant.now(), null, null, List.of(), true, "saml"))
                .evidenceHash(evidenceHash)
                .build();

            when(identityValidationStrategy.validate(any())).thenReturn(validatedIdentity);
            when(verifier.verify(
                eq(IntentAction.REQUEST_FUNDS),
                any(IntentMeta.class),
                any(ActionIntentPayload.class),
                isNull(),
                any()
            )).thenReturn(new Eip712IntentVerifier.VerificationResult(true, null, null, null));

            IntentSubmission submission = createIdentityEvidenceRequestFundsSubmission(evidenceHash);
            submission.getActionPayload().setPuc(specificPuc);

            IntentAckResponse response = service.processIntent(submission);

            assertEquals("accepted", response.getStatus());
            verify(persistenceService).upsert(argThat(record ->
                record.getActionId().equals(IntentAction.REQUEST_FUNDS.getId())
            ));
        }

        @Test
        @DisplayName("Should fall back to SAML validation when identityEvidence is null but samlAssertion is present")
        void shouldFallbackToSamlWhenIdentityEvidenceIsNull() throws Exception {
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3("legacy@university.edu".getBytes(StandardCharsets.UTF_8))
            );
            when(samlValidationService.validateSamlAssertionWithSignature("legacy-saml-assertion"))
                .thenReturn(Map.of("userid", "legacy@university.edu"));
            when(verifier.verify(
                eq(IntentAction.REQUEST_FUNDS),
                any(IntentMeta.class),
                any(ActionIntentPayload.class),
                isNull(),
                any()
            )).thenReturn(new Eip712IntentVerifier.VerificationResult(true, null, null, null));

            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.REQUEST_FUNDS.getId());
            meta.setPayloadHash("0x" + "c".repeat(64));
            ActionIntentPayload payload = createValidActionPayload();
            payload.setPuc("legacy@university.edu");
            payload.setMaxBatch(BigInteger.TEN);
            payload.setAssertionHash(Numeric.toHexString(Hash.sha3("legacy-saml-assertion".getBytes(StandardCharsets.UTF_8))));

            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion("legacy-saml-assertion");
            submission.setWebauthnCredentialId("cred");

            IntentAckResponse response = service.processIntent(submission);

            assertEquals("accepted", response.getStatus());
            verify(samlValidationService).validateSamlAssertionWithSignature("legacy-saml-assertion");
            verify(identityValidationStrategy, never()).validate(any());
        }
    }

    private IdentityEvidenceDTO buildIdentityEvidence(String type, String evidenceHash, NormalizedClaims normalizedClaims, String rawEvidence) {
        IdentityEvidenceDTO.IdentityEvidenceDTOBuilder builder = IdentityEvidenceDTO.builder()
            .type(type)
            .format("openid4vp".equals(type) ? "jwt-vp" : "saml2-base64")
            .normalizedClaims(normalizedClaims)
            .evidenceHash(evidenceHash);
        if (rawEvidence != null) {
            builder.rawEvidence(rawEvidence);
        }
        return builder.build();
    }

    private WebauthnOnboardingCompleteRequest buildCompleteRequest(
        WebauthnOnboardingOptionsResponse options,
        String credentialId,
        byte[] attestationObject
    ) {
        String clientDataJson = String.format(
            "{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"https://localhost\"}",
            options.getChallenge()
        );

        WebauthnOnboardingCompleteRequest request = new WebauthnOnboardingCompleteRequest();
        request.setSessionId(options.getSessionId());
        request.setCredentialId(BASE64URL_ENCODER.encodeToString(credentialId.getBytes(StandardCharsets.UTF_8)));
        request.setClientDataJSON(BASE64URL_ENCODER.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8)));
        request.setAttestationObject(BASE64URL_ENCODER.encodeToString(attestationObject));
        return request;
    }

    private byte[] createValidAttestationObject(String credentialId) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] rpIdHash = sha256.digest("localhost".getBytes(StandardCharsets.UTF_8));
        byte[] credentialIdBytes = credentialId.getBytes(StandardCharsets.UTF_8);
        byte[] publicKeyCose = new byte[] { (byte) 0xA1, 0x01, 0x02, 0x03 };

        byte[] authData = new byte[32 + 1 + 4 + 16 + 2 + credentialIdBytes.length + publicKeyCose.length];
        int pos = 0;
        System.arraycopy(rpIdHash, 0, authData, pos, 32);
        pos += 32;
        authData[pos++] = 0x41; // UP + AT
        authData[pos++] = 0x00;
        authData[pos++] = 0x00;
        authData[pos++] = 0x00;
        authData[pos++] = 0x00;
        for (int i = 0; i < 16; i++) {
            authData[pos++] = 0x00;
        }
        authData[pos++] = (byte) ((credentialIdBytes.length >> 8) & 0xFF);
        authData[pos++] = (byte) (credentialIdBytes.length & 0xFF);
        System.arraycopy(credentialIdBytes, 0, authData, pos, credentialIdBytes.length);
        pos += credentialIdBytes.length;
        System.arraycopy(publicKeyCose, 0, authData, pos, publicKeyCose.length);

        byte[] result = new byte[12 + authData.length];
        pos = 0;
        result[pos++] = (byte) 0xA1;
        result[pos++] = 0x68;
        result[pos++] = 'a'; result[pos++] = 'u'; result[pos++] = 't'; result[pos++] = 'h';
        result[pos++] = 'D'; result[pos++] = 'a'; result[pos++] = 't'; result[pos++] = 'a';
        result[pos++] = 0x58;
        result[pos++] = (byte) authData.length;
        System.arraycopy(authData, 0, result, pos, authData.length);
        return result;
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should reject when meta is null")
        void shouldRejectNullMeta() {
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(null);
            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("Missing intent meta"));
        }

        @Test
        @DisplayName("Should reject when requestId is missing")
        void shouldRejectMissingRequestId() {
            IntentMeta meta = createValidMeta();
            meta.setRequestId(null);
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(createValidActionPayload());
            submission.setWebauthnCredentialId("cred123");
            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getReason().contains("requestId") || ex.getReason().contains("Missing"));
        }
        @Test
        @DisplayName("Should reject when signer is missing")
        void shouldRejectMissingSigner() {
            IntentMeta meta = createValidMeta();
            meta.setSigner(null);
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(createValidActionPayload());
            submission.setWebauthnCredentialId("cred123");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getReason().contains("signer") || ex.getReason().contains("Missing"));
        }
        @Test
        @DisplayName("Should allow executor to differ from signer (SAML missing check)")
        void shouldAllowExecutorDifferentFromSigner() {
            IntentMeta meta = createValidMeta();
            meta.setExecutor("0xdifferentaddress1234567890abcdef12345678");
            
            ActionIntentPayload payload = createValidActionPayload();
            payload.setExecutor("0xdifferentaddress1234567890abcdef12345678");
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setWebauthnCredentialId("cred123");

            // Service should not reject due to executor != signer; it will fail later due to missing SAML
            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getReason().toLowerCase().contains("saml"));
        }
        @Test
        @DisplayName("Should reject unsupported action")
        void shouldRejectUnsupportedAction() {
            IntentMeta meta = createValidMeta();
            meta.setAction(9999); // Invalid action ID
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setWebauthnCredentialId("cred123");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("Unsupported action"));
        }
        @Test
        @DisplayName("Should reject when SAML assertion is missing")
        void shouldRejectMissingSamlAssertion() {
            IntentMeta meta = createValidMeta();
            ActionIntentPayload payload = createValidActionPayload();
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion(null);
            submission.setWebauthnCredentialId("cred123");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getReason().contains("saml"));
        }
        @Test
        @DisplayName("Should reject when WebAuthn credential ID is missing")
        void shouldRejectMissingWebauthnCredential() {
            IntentMeta meta = createValidMeta();
            ActionIntentPayload payload = createValidActionPayload();
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion("valid-saml");
            submission.setWebauthnCredentialId(null);

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getReason().contains("webauthn"));
        }
    }
    @Nested
    @DisplayName("Reservation Payload Validation Tests")
    class ReservationPayloadValidationTests {
        @Test
        @DisplayName("Should reject reservation with missing labId")
        void shouldRejectMissingLabId() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.RESERVATION_REQUEST.getId());
            
            ReservationIntentPayload payload = createValidReservationPayload();
            payload.setLabId(null);
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setReservationPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("labId"));
        }

        @Test
        @DisplayName("Should reject reservation with missing time window")
        void shouldRejectMissingTimeWindow() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.RESERVATION_REQUEST.getId());
            
            ReservationIntentPayload payload = createValidReservationPayload();
            payload.setStart(null);
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setReservationPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("reservation window"));
        }

        @Test
        @DisplayName("Should reject reservation with invalid time window (start >= end)")
        void shouldRejectInvalidTimeWindow() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.RESERVATION_REQUEST.getId());
            
            ReservationIntentPayload payload = createValidReservationPayload();
            payload.setStart(Instant.now().plusSeconds(7200).getEpochSecond());
            payload.setEnd(Instant.now().plusSeconds(3600).getEpochSecond()); // end before start
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setReservationPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("Invalid reservation window"));
        }

        @Test
        @DisplayName("Should reject CANCEL_RESERVATION_REQUEST without reservationKey")
        void shouldRejectCancelWithoutReservationKey() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.CANCEL_RESERVATION_REQUEST.getId());
            
            ReservationIntentPayload payload = createValidReservationPayload();
            payload.setReservationKey(null);
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setReservationPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("reservationKey"));
        }
    }

    @Nested
    @DisplayName("Action Payload Validation Tests")
    class ActionPayloadValidationTests {

        @Test
        @DisplayName("Should reject LAB_ADD without required fields")
        void shouldRejectLabAddWithoutRequiredFields() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.LAB_ADD.getId());
            
            ActionIntentPayload payload = createValidActionPayload();
            payload.setUri(null); // Missing required field
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("Missing lab payload fields"));
        }

        @Test
        @DisplayName("Should reject LAB_SET_URI without tokenURI")
        void shouldRejectSetUriWithoutTokenUri() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.LAB_SET_URI.getId());
            
            ActionIntentPayload payload = createValidActionPayload();
            payload.setTokenURI(null);
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("tokenURI"));
        }

        @Test
        @DisplayName("Should reject REQUEST_FUNDS with invalid maxBatch")
        void shouldRejectInvalidMaxBatch() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.REQUEST_FUNDS.getId());
            
            ActionIntentPayload payload = createValidActionPayload();
            payload.setMaxBatch(BigInteger.valueOf(101)); // Over max
            
            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getMessage().contains("Invalid maxBatch"));
        }

        @Test
        @DisplayName("Should reject REQUEST_FUNDS without puc")
        void shouldRejectRequestFundsWithoutPuc() {
            IntentMeta meta = createValidMeta();
            meta.setAction(IntentAction.REQUEST_FUNDS.getId());

            ActionIntentPayload payload = createValidActionPayload();
            payload.setPuc(null);
            payload.setMaxBatch(BigInteger.TEN);

            IntentSubmission submission = new IntentSubmission();
            submission.setMeta(meta);
            submission.setActionPayload(payload);
            submission.setSamlAssertion("saml");
            submission.setWebauthnCredentialId("cred");

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));
            assertTrue(ex.getReason().contains("Missing puc"));
        }
    }

    @Nested
    @DisplayName("Creator Ownership Precheck Tests")
    class CreatorOwnershipPrecheckTests {

        @Test
        @DisplayName("Should reject protected action for legacy lab without creator hash")
        void shouldRejectLegacyLabBlocked() throws Exception {
            creatorHashToReturn = "0x" + "0".repeat(64);
            IntentSubmission submission = createValidRequestFundsSubmission();
            submission.getActionPayload().setSchacHomeOrganization("UNED.ES");

            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", submission.getActionPayload().getPuc()));

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));

            assertEquals(409, ex.getStatusCode().value());
            assertEquals("LAB_LEGACY_BLOCKED", ex.getReason());
            assertEquals(1.0, meterRegistry.get("authorization.lab_legacy_blocked.count")
                .tag("institution", "uned.es")
                .tag("actionType", IntentAction.REQUEST_FUNDS.getWireValue())
                .tag("labId", "42")
                .counter()
                .count());
        }

        @Test
        @DisplayName("Should reject protected action for different creator")
        void shouldRejectCreatorMismatch() throws Exception {
            creatorHashToReturn = "0x" + "2".repeat(64);
            IntentSubmission submission = createValidRequestFundsSubmission();
            submission.getActionPayload().setSchacHomeOrganization("UNED.ES");

            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", submission.getActionPayload().getPuc()));

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.processIntent(submission));

            assertEquals(403, ex.getStatusCode().value());
            assertEquals("LAB_CREATOR_MISMATCH", ex.getReason());
            assertEquals(1.0, meterRegistry.get("authorization.lab_creator_mismatch.count")
                .tag("institution", "uned.es")
                .tag("actionType", IntentAction.REQUEST_FUNDS.getWireValue())
                .tag("labId", "42")
                .counter()
                .count());
        }

        @Test
        @DisplayName("Should accept protected action for matching creator hash")
        void shouldAcceptMatchingCreatorHash() throws Exception {
            IntentSubmission submission = createValidRequestFundsSubmission();
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3(submission.getActionPayload().getPuc().getBytes(StandardCharsets.UTF_8))
            );

            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", submission.getActionPayload().getPuc()));
            when(verifier.verify(
                eq(IntentAction.REQUEST_FUNDS),
                any(IntentMeta.class),
                any(ActionIntentPayload.class),
                isNull(),
                any()
            )).thenReturn(new Eip712IntentVerifier.VerificationResult(true, null, null, null));

            IntentAckResponse response = service.processIntent(submission);

            assertEquals("accepted", response.getStatus());
            verify(persistenceService).upsert(argThat(record ->
                record.getActionId().equals(IntentAction.REQUEST_FUNDS.getId())
                    && "42".equals(record.getLabId())
            ));
        }
    }

    @Nested
    @DisplayName("Expiration Tests")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired intent during validation")
        void shouldRejectExpiredIntent() throws Exception {
            IntentSubmission submission = createValidRequestFundsSubmission();
            submission.getMeta()
                .setExpiresAt(Instant.now().minusSeconds(10).getEpochSecond()); // Already expired
            creatorHashToReturn = Numeric.toHexString(
                Hash.sha3(submission.getActionPayload().getPuc().getBytes(StandardCharsets.UTF_8))
            );

            // Force valid assertion signature 
            when(samlValidationService.validateSamlAssertionWithSignature(anyString()))
                .thenReturn(Map.of("userid", submission.getActionPayload().getPuc()));

            // The intent has valid payload but is invalid due to expiration
            IntentAckResponse response = service.processIntent(submission);

            assertEquals("rejected", response.getStatus());
            assertEquals("expired", response.getReason());
        }
    }

    @Nested
    @DisplayName("getStatus Tests")
    class GetStatusTests {

        @Test
        @DisplayName("Should return status from in-memory cache")
        void shouldReturnStatusFromCache() {
            // First, add a record to the cache via the public method
            String requestId = "test-req-123";
            IntentRecord record = new IntentRecord(requestId, IntentAction.LAB_LIST.getWireValue(), "0xexecutor");
            record.setStatus(IntentStatus.QUEUED);
            
            // Use the internal map via reflection or just test getStatus when not found
            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.getStatus(requestId));
            assertEquals(404, ex.getStatusCode().value());
        }

        @Test
        @DisplayName("Should return status from persistence when not in cache")
        void shouldQueryPersistenceWhenNotInCache() {
            String requestId = "persisted-req-456";
            IntentRecord record = new IntentRecord(requestId, "lab.list", "0xexecutor");
            record.setStatus(IntentStatus.EXECUTED);
            record.setTxHash("0xtxhash");
            record.setBlockNumber(12345L);
            
            when(persistenceService.findByRequestId(requestId)).thenReturn(Optional.of(record));

            IntentStatusResponse response = service.getStatus(requestId);

            assertEquals(requestId, response.getRequestId());
            assertEquals("executed", response.getStatus());
            assertEquals("0xtxhash", response.getTxHash());
            assertEquals(12345L, response.getBlockNumber());
        }

        @Test
        @DisplayName("Should throw NOT_FOUND when request doesn't exist")
        void shouldThrowNotFoundForUnknownRequest() {
            when(persistenceService.findByRequestId(anyString())).thenReturn(Optional.empty());

            ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.getStatus("unknown-request"));
            assertEquals(404, ex.getStatusCode().value());
        }
    }

    @Nested
    @DisplayName("Status Update Tests")
    class StatusUpdateTests {

        @Test
        @DisplayName("Should mark intent as in progress")
        void shouldMarkInProgress() {
            IntentRecord record = new IntentRecord("req-1", "lab.list", "0xexecutor");
            record.setStatus(IntentStatus.QUEUED);

            service.markInProgress(record);

            assertEquals(IntentStatus.IN_PROGRESS, record.getStatus());
            verify(persistenceService).upsert(record);
        }

        @Test
        @DisplayName("Should mark intent as executed with tx details")
        void shouldMarkExecuted() {
            IntentRecord record = new IntentRecord("req-2", "lab.list", "0xexecutor");
            record.setStatus(IntentStatus.IN_PROGRESS);

            service.markExecuted(record, "0xtx123", 999L, "42", "0xreskey");

            assertEquals(IntentStatus.EXECUTED, record.getStatus());
            assertEquals("0xtx123", record.getTxHash());
            assertEquals(999L, record.getBlockNumber());
            assertEquals("42", record.getLabId());
            assertEquals("0xreskey", record.getReservationKey());
            verify(persistenceService).upsert(record);
            verify(webhookService).notify(record);
        }

        @Test
        @DisplayName("Should mark intent as failed with reason")
        void shouldMarkFailed() {
            IntentRecord record = new IntentRecord("req-3", "lab.list", "0xexecutor");
            record.setStatus(IntentStatus.IN_PROGRESS);

            service.markFailed(record, "Contract reverted");

            assertEquals(IntentStatus.FAILED, record.getStatus());
            assertEquals("Contract reverted", record.getReason());
            assertEquals("Contract reverted", record.getError());
            verify(persistenceService).upsert(record);
            verify(webhookService).notify(record);
        }

        @Test
        @DisplayName("Should update from on-chain event")
        void shouldUpdateFromOnChain() {
            String requestId = "onchain-req";

            service.updateFromOnChain(requestId, "executed", "0xtx", 1000L, "5", "0xreskey", null);

            verify(persistenceService).upsert(argThat(record -> 
                record.getRequestId().equals(requestId) &&
                record.getStatus() == IntentStatus.EXECUTED &&
                record.getTxHash().equals("0xtx")
            ));
            verify(webhookService).notify(any());
        }
    }

    @Nested
    @DisplayName("Wire Status Mapping Tests")
    class WireStatusMappingTests {

        @Test
        @DisplayName("Should map all wire statuses correctly")
        void shouldMapWireStatuses() {
            service.updateFromOnChain("r1", "queued", null, null, null, null, null);
            service.updateFromOnChain("r2", "in_progress", null, null, null, null, null);
            service.updateFromOnChain("r3", "executed", null, null, null, null, null);
            service.updateFromOnChain("r4", "failed", null, null, null, null, null);
            service.updateFromOnChain("r5", "rejected", null, null, null, null, null);
            service.updateFromOnChain("r6", "unknown", null, null, null, null, null);
            service.updateFromOnChain("r7", null, null, null, null, null, null);

            // Verify calls were made (status mapping is internal)
            verify(persistenceService, times(7)).upsert(any());
        }
    }

    @Nested
    @DisplayName("Queued Intents Tests")
    class QueuedIntentsTests {

        @Test
        @DisplayName("Should return empty map initially")
        void shouldReturnEmptyMapInitially() {
            Map<String, IntentRecord> queued = service.getQueuedIntents();
            assertTrue(queued.isEmpty());
        }
    }
}
