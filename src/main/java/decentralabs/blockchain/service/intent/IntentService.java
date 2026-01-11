package decentralabs.blockchain.service.intent;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
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
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.extern.slf4j.Slf4j;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@Slf4j
public class IntentService {

    private final Map<String, IntentRecord> intents = new ConcurrentHashMap<>();
    private final Map<String, String> nonceIndex = new ConcurrentHashMap<>();
    private final Map<String, Long> assertionReplayCache = new ConcurrentHashMap<>();

    private final String defaultEta;
    private final long samlReplayTtlMs;
    private final Eip712IntentVerifier verifier;
    private final IntentPersistenceService persistenceService;
    private final IntentWebhookService webhookService;
    private final SamlValidationService samlValidationService;
    private final WebauthnCredentialService webauthnCredentialService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public IntentService(
        @Value("${intent.default-eta:15s}") String defaultEta,
        @Value("${intent.saml.replay-ttl-ms:300000}") long samlReplayTtlMs,
        Eip712IntentVerifier verifier,
        IntentPersistenceService persistenceService,
        IntentWebhookService webhookService,
        SamlValidationService samlValidationService,
        WebauthnCredentialService webauthnCredentialService
    ) {
        this.defaultEta = defaultEta;
        this.samlReplayTtlMs = samlReplayTtlMs;
        this.verifier = verifier;
        this.persistenceService = persistenceService;
        this.webhookService = webhookService;
        this.samlValidationService = samlValidationService;
        this.webauthnCredentialService = webauthnCredentialService;
    }

    @PostConstruct
    public void loadPendingIntents() {
        List<IntentRecord> pending = persistenceService.findPending();
        if (pending.isEmpty()) {
            return;
        }
        int loaded = 0;
        for (IntentRecord record : pending) {
            if (record == null || record.getRequestId() == null) {
                continue;
            }
            intents.put(record.getRequestId(), record);
            if (record.getSigner() != null && record.getNonce() != null) {
                nonceIndex.put(buildNonceKey(record.getSigner(), record.getNonce()), record.getRequestId());
            }
            loaded++;
        }
        if (loaded > 0) {
            log.info("Loaded {} pending intents from persistence", loaded);
        }
    }

    public IntentAckResponse processIntent(IntentSubmission submission) {
        IntentMeta meta = Optional.ofNullable(submission.getMeta())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing intent meta"));
        IntentAction action = resolveAction(meta);
        ActionIntentPayload actionPayload = submission.getActionPayload();
        ReservationIntentPayload reservationPayload = submission.getReservationPayload();
        String credentialId = requireWebauthnCredentialId(submission);

        validatePayload(action, meta, actionPayload, reservationPayload);

        String samlAssertion = requireSamlAssertion(submission);
        String expectedAssertionHash = computeAssertionHash(samlAssertion);
        ensurePayloadAssertionHash(actionPayload, reservationPayload, expectedAssertionHash);
        validateSamlAssertion(actionPayload, reservationPayload, samlAssertion);
        checkAssertionReplay(expectedAssertionHash);

        String puc = resolvePuc(actionPayload, reservationPayload);
        if (action != IntentAction.REQUEST_FUNDS) {
            validateWebauthnAssertion(puc, credentialId, meta, submission);
        }

        if (isExpired(meta.getExpiresAt())) {
            return buildRejectedAck(meta.getRequestId(), "expired");
        }

        if (isNonceReplay(meta)) {
            return buildRejectedAck(meta.getRequestId(), "nonce_replay");
        }

        Eip712IntentVerifier.VerificationResult verification = verifier.verify(
            action,
            meta,
            actionPayload,
            reservationPayload,
            submission.getSignature()
        );

        if (!verification.valid()) {
            return buildRejectedAck(meta.getRequestId(), "invalid_signature");
        }
        markAssertionUsed(expectedAssertionHash);

        // Idempotent behavior: if already stored, return current ack status
        IntentRecord existing = intents.get(meta.getRequestId());
        if (existing != null) {
            return buildAck(meta.getRequestId(),
                existing.getStatus() == IntentStatus.REJECTED ? "rejected" : "accepted",
                existing.getReason());
        }

        IntentRecord record = new IntentRecord(meta.getRequestId(), action.getWireValue(), meta.getExecutor());
        record.setSigner(meta.getSigner());
        record.setExecutor(meta.getExecutor());
        record.setActionId(meta.getAction());
        record.setPayloadHash(meta.getPayloadHash());
        record.setRequestedAt(meta.getRequestedAt());
        record.setExpiresAt(meta.getExpiresAt());
        record.setNonce(meta.getNonce());
        record.setSignature(submission.getSignature());

        if (action.usesReservationPayload()) {
            record.setReservationPayload(reservationPayload);
            record.setReservationKey(normalizeBytes32(reservationPayload.getReservationKey()));
            record.setLabId(reservationPayload.getLabId() != null ? reservationPayload.getLabId().toString() : null);
            record.setPuc(reservationPayload.getPuc());
        } else {
            record.setActionPayload(actionPayload);
            record.setReservationKey(normalizeBytes32(actionPayload.getReservationKey()));
            record.setLabId(actionPayload.getLabId() != null ? actionPayload.getLabId().toString() : null);
            record.setPuc(actionPayload.getPuc());
        }

        record.setPayloadJson(serializePayload(submission));

        intents.put(meta.getRequestId(), record);
        nonceIndex.put(buildNonceKey(meta), meta.getRequestId());
        persistenceService.upsert(record);

        log.info("Intent {} queued (action={}, provider={}, labId={}, reservationKey={})",
            LogSanitizer.sanitize(meta.getRequestId()), action.getWireValue(), 
            LogSanitizer.maskIdentifier(meta.getExecutor()), 
            LogSanitizer.sanitize(record.getLabId()), 
            LogSanitizer.sanitize(record.getReservationKey()));

        return buildAcceptedAck(meta.getRequestId());
    }

    public IntentStatusResponse getStatus(String requestId) {
        IntentRecord record = intents.get(requestId);
        if (record == null) {
            record = persistenceService.findByRequestId(requestId).orElse(null);
            if (record != null) {
                intents.put(requestId, record);
            }
        }
        if (record == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown requestId");
        }

        IntentStatusResponse response = new IntentStatusResponse();
        response.setRequestId(record.getRequestId());
        response.setStatus(record.getStatus().getWireValue());
        response.setTxHash(record.getTxHash());
        response.setBlockNumber(record.getBlockNumber());
        response.setLabId(record.getLabId());
        response.setReservationKey(record.getReservationKey());
        response.setError(record.getError() != null ? record.getError() : record.getReason());
        response.setUpdatedAt(DateTimeFormatter.ISO_INSTANT.format(record.getUpdatedAt()));
        return response;
    }

    @Scheduled(fixedDelayString = "${intent.reconciliation-interval-ms:10000}")
    public void reconcile() {
        long now = Instant.now().getEpochSecond();
        intents.values().stream()
            .filter(r -> r.getStatus() == IntentStatus.QUEUED || r.getStatus() == IntentStatus.IN_PROGRESS)
            .forEach(record -> {
                if (record.getExpiresAt() != null && record.getExpiresAt() <= now) {
                    record.setStatus(IntentStatus.REJECTED);
                    record.setReason("expired");
                    persistenceService.upsert(record);
                    webhookService.notify(record);
                    log.info("Intent {} expired during reconciliation", record.getRequestId());
                }
            });

        purgeExpiredAssertions(now * 1000); // convert seconds -> millis
    }

    private IntentAction resolveAction(IntentMeta meta) {
        IntentAction action = IntentAction.fromId(meta.getAction())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported action"));
        if (action == IntentAction.LAB_ADD_AND_LIST) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unsupported_action");
        }
        return action;
    }

    private void validatePayload(
        IntentAction action,
        IntentMeta meta,
        ActionIntentPayload actionPayload,
        ReservationIntentPayload reservationPayload
    ) {
        if (meta.getRequestId() == null || meta.getRequestId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing requestId");
        }
        if (meta.getSigner() == null || meta.getSigner().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing signer");
        }
        if (meta.getExecutor() == null || meta.getExecutor().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing executor");
        }
        if (meta.getAction() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing action id");
        }
        if (meta.getNonce() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing nonce");
        }
        if (meta.getRequestedAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing requestedAt");
        }
        if (meta.getExpiresAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing expiresAt");
        }
        if (meta.getPayloadHash() == null || meta.getPayloadHash().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing payloadHash");
        }
        if (action.usesReservationPayload()) {
            if (reservationPayload == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing reservation payload");
            }
            if (reservationPayload.getLabId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing labId");
            }
            if (reservationPayload.getStart() == null || reservationPayload.getEnd() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing reservation window");
            }
            if (!meta.getExecutor().equalsIgnoreCase(reservationPayload.getExecutor())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Executor mismatch");
            }
            if (isBlank(reservationPayload.getPuc())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing puc");
            }
            if (action == IntentAction.CANCEL_RESERVATION_REQUEST && (reservationPayload.getReservationKey() == null || reservationPayload.getReservationKey().isBlank())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing reservationKey");
            }
            if (reservationPayload.getStart() != null && reservationPayload.getEnd() != null && reservationPayload.getStart() >= reservationPayload.getEnd()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid reservation window");
            }
        } else {
            if (actionPayload == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing action payload");
            }
            if (actionPayload.getLabId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing labId");
            }
            if (!meta.getExecutor().equalsIgnoreCase(actionPayload.getExecutor())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Executor mismatch");
            }
            if (action != IntentAction.REQUEST_FUNDS && isBlank(actionPayload.getPuc())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing puc");
            }
            switch (action) {
                case LAB_ADD -> {
                    if (isBlank(actionPayload.getUri()) || actionPayload.getPrice() == null || isBlank(actionPayload.getAccessURI()) || isBlank(actionPayload.getAccessKey())) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing lab payload fields");
                    }
                }
                case LAB_SET_URI -> {
                    if (isBlank(actionPayload.getTokenURI())) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing tokenURI");
                    }
                }
                case CANCEL_BOOKING -> {
                    if (actionPayload.getReservationKey() == null || actionPayload.getReservationKey().isBlank()) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing reservationKey");
                    }
                }
                case REQUEST_FUNDS -> {
                    if (actionPayload.getMaxBatch() == null) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing maxBatch");
                    }
                    if (actionPayload.getMaxBatch().compareTo(BigInteger.ONE) < 0
                        || actionPayload.getMaxBatch().compareTo(BigInteger.valueOf(100)) > 0) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid maxBatch");
                    }
                }
                default -> { }
            }
        }
    }

    private boolean isExpired(Long expiresAt) {
        long now = Instant.now().getEpochSecond();
        return expiresAt <= now;
    }

    private boolean isNonceReplay(IntentMeta meta) {
        String key = buildNonceKey(meta);
        String existingRequest = nonceIndex.get(key);
        return existingRequest != null && !existingRequest.equals(meta.getRequestId());
    }

    private String buildNonceKey(IntentMeta meta) {
        String signer = meta.getSigner() == null ? "" : meta.getSigner();
        return signer.toLowerCase(Locale.ROOT) + ":" + meta.getNonce();
    }

    private String buildNonceKey(String signer, Long nonce) {
        String safeSigner = signer == null ? "" : signer;
        String safeNonce = nonce == null ? "" : nonce.toString();
        return safeSigner.toLowerCase(Locale.ROOT) + ":" + safeNonce;
    }

    private IntentAckResponse buildAcceptedAck(String requestId) {
        return buildAck(requestId, "accepted", null);
    }

    private IntentAckResponse buildRejectedAck(String requestId, String reason) {
        IntentRecord record = intents.computeIfAbsent(requestId, id -> new IntentRecord(id, null, null));
        record.setStatus(IntentStatus.REJECTED);
        record.setReason(reason);
        persistenceService.upsert(record);
        webhookService.notify(record);
        return buildAck(requestId, "rejected", reason);
    }

    private IntentAckResponse buildAck(String requestId, String status, String reason) {
        IntentAckResponse ack = new IntentAckResponse();
        ack.setRequestId(requestId);
        ack.setStatus(status);
        ack.setReason(reason);
        ack.setEta(defaultEta);
        ack.setReceivedAt(DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
        return ack;
    }

    private String requireSamlAssertion(IntentSubmission submission) {
        String samlAssertion = submission.getSamlAssertion();
        if (samlAssertion == null || samlAssertion.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_saml_for_intent");
        }
        return samlAssertion;
    }

    private String computeAssertionHash(String samlAssertion) {
        byte[] digest = Hash.sha3(samlAssertion.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(digest));
    }

    private void ensurePayloadAssertionHash(
        ActionIntentPayload actionPayload,
        ReservationIntentPayload reservationPayload,
        String expectedHash
    ) {
        if (actionPayload != null) {
            String payloadHash = normalizeBytes32(actionPayload.getAssertionHash());
            if (payloadHash == null || !expectedHash.equalsIgnoreCase(payloadHash)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "assertion_hash_mismatch");
            }
        }
        if (reservationPayload != null) {
            String payloadHash = normalizeBytes32(reservationPayload.getAssertionHash());
            if (payloadHash == null || !expectedHash.equalsIgnoreCase(payloadHash)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "assertion_hash_mismatch");
            }
        }
    }

    private void validateSamlAssertion(
        ActionIntentPayload actionPayload,
        ReservationIntentPayload reservationPayload,
        String samlAssertion
    ) {
        try {
            Map<String, String> samlAttrs = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
            String samlUser = samlAttrs.get("userid");
            if (samlUser == null || samlUser.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml");
            }
            String puc = resolvePuc(actionPayload, reservationPayload);
            if (puc != null && !puc.isBlank() && !puc.equals(samlUser)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "puc_saml_mismatch");
            }
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Invalid SAML assertion for intent: {}", ex.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml");
        }
    }

    private String normalizeBytes32(String hex) {
        if (hex == null || hex.isBlank()) {
            return null;
        }
        String clean = Numeric.cleanHexPrefix(hex);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    private void checkAssertionReplay(String assertionHash) {
        if (assertionHash == null || assertionHash.isBlank()) {
            return;
        }
        long nowMs = Instant.now().toEpochMilli();
        purgeExpiredAssertions(nowMs);
        Long expiresAt = assertionReplayCache.get(assertionHash);
        if (expiresAt != null && expiresAt > nowMs) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "assertion_replay");
        }
    }

    private void markAssertionUsed(String assertionHash) {
        if (assertionHash == null || assertionHash.isBlank()) {
            return;
        }
        long nowMs = Instant.now().toEpochMilli();
        long ttl = samlReplayTtlMs <= 0 ? 0 : samlReplayTtlMs;
        assertionReplayCache.put(assertionHash, nowMs + ttl);
    }

    private void purgeExpiredAssertions(long nowMs) {
        assertionReplayCache.entrySet().removeIf(entry -> entry.getValue() <= nowMs);
    }

    private String requireWebauthnCredentialId(IntentSubmission submission) {
        String credentialId = submission.getWebauthnCredentialId();
        if (isBlank(credentialId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_webauthn_credential");
        }
        return credentialId;
    }

    private void validateWebauthnAssertion(String puc, String credentialId, IntentMeta meta, IntentSubmission submission) {
        if (isBlank(puc)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_puc_for_webauthn");
        }
        if (isBlank(submission.getWebauthnClientDataJSON()) || isBlank(submission.getWebauthnAuthenticatorData()) || isBlank(submission.getWebauthnSignature())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_webauthn_assertion");
        }
        WebauthnCredential cred = webauthnCredentialService.findCredential(puc, credentialId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered"));
        if (!cred.isActive()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_revoked");
        }

        String expectedChallenge = buildWebauthnChallenge(puc, credentialId, meta);
        
        // WebAuthn assertion verification requires user-provided data by design.
        // This is NOT a security bypass because:
        // 1. The expected challenge is generated server-side from trusted data
        // 2. The credential's public key is retrieved from our database
        // 3. Cryptographic signature verification will fail if data is tampered
        // 4. All inputs are validated for size and format before processing
        // CodeQL flags this as "user-controlled bypass" but it's the correct WebAuthn flow.
        // lgtm[java/user-controlled-bypass]
        verifyWebauthnAssertion(
            cred,
            validateWebauthnField(submission.getWebauthnClientDataJSON(), "clientDataJSON"),
            validateWebauthnField(submission.getWebauthnAuthenticatorData(), "authenticatorData"),
            validateWebauthnField(submission.getWebauthnSignature(), "signature"),
            expectedChallenge
        );
    }
    
    /**
     * Validates a WebAuthn field for presence and size constraints.
     * This is a security validation step, not a bypass.
     * 
     * @param value the field value to validate
     * @param fieldName the field name for error messages
     * @return the validated value (unchanged if valid)
     * @throws ResponseStatusException if validation fails
     */
    private String validateWebauthnField(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_webauthn_" + fieldName);
        }
        // Limit field size to prevent resource exhaustion (16KB is generous for WebAuthn)
        final int MAX_FIELD_SIZE = 16384;
        if (value.length() > MAX_FIELD_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_" + fieldName + "_too_large");
        }
        return value;
    }

    private String buildWebauthnChallenge(String puc, String credentialId, IntentMeta meta) {
        return String.join("|",
            puc.toLowerCase(Locale.ROOT),
            credentialId,
            meta.getRequestId(),
            meta.getPayloadHash(),
            String.valueOf(meta.getNonce()),
            String.valueOf(meta.getRequestedAt()),
            String.valueOf(meta.getExpiresAt()),
            String.valueOf(meta.getAction())
        );
    }

    /**
     * Verifies a WebAuthn assertion against the stored credential.
     * This method intentionally receives user-provided data because WebAuthn
     * requires the client's assertion to be verified against the server's challenge.
     * Security is ensured by cryptographic signature verification.
     */
    @SuppressWarnings("java:S2583") // User data flow is intentional for WebAuthn
    private void verifyWebauthnAssertion(
        WebauthnCredential cred,
        String clientDataJSONb64,
        String authenticatorDatab64,
        String signatureB64,
        String expectedChallenge
    ) {
        try {
            byte[] clientData = Base64.getUrlDecoder().decode(clientDataJSONb64);
            byte[] authenticatorData = Base64.getUrlDecoder().decode(authenticatorDatab64);
            byte[] signature = Base64.getUrlDecoder().decode(signatureB64);

            String challengeFromClient = extractChallengeFromClientData(clientData);
            String expectedChallengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedChallenge.getBytes(StandardCharsets.UTF_8));
            if (!expectedChallengeB64.equals(challengeFromClient)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_challenge_mismatch");
            }

            byte[] clientHash = sha256(clientData);
            byte[] signed = concat(authenticatorData, clientHash);

            PublicKey publicKey = decodePublicKey(cred.getPublicKey());
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(signed);
            if (!sig.verify(signature)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_signature_invalid");
            }
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_validation_error");
        }
    }

    private String extractChallengeFromClientData(byte[] clientData) {
        try {
            Map<?,?> parsed = objectMapper.readValue(clientData, Map.class);
            Object challenge = parsed.get("challenge");
            if (challenge == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_missing_challenge");
            }
            return challenge.toString();
        } catch (IOException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_clientdata_invalid");
        }
    }

    private byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "hash_error");
        }
    }

    private byte[] concat(byte[] a, byte[] b) {
        // Validate array lengths to prevent integer overflow and excessive allocation
        // Max reasonable size for WebAuthn signature data is 64KB
        final int MAX_COMBINED_SIZE = 65536;
        if (a.length > MAX_COMBINED_SIZE || b.length > MAX_COMBINED_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_data_too_large");
        }
        int combinedLength = a.length + b.length;
        if (combinedLength < 0 || combinedLength > MAX_COMBINED_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_data_too_large");
        }
        byte[] out = new byte[combinedLength];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private PublicKey decodePublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(spec);
    }

    private String resolvePuc(ActionIntentPayload actionPayload, ReservationIntentPayload reservationPayload) {
        if (reservationPayload != null && !isBlank(reservationPayload.getPuc())) {
            return reservationPayload.getPuc();
        }
        if (actionPayload != null) {
            return actionPayload.getPuc();
        }
        return null;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public Map<String, IntentRecord> getQueuedIntents() {
        return intents;
    }

    public void markInProgress(IntentRecord record) {
        record.setStatus(IntentStatus.IN_PROGRESS);
        persistenceService.upsert(record);
    }

    public void markExecuted(IntentRecord record, String txHash, Long blockNumber, String labId, String reservationKey) {
        record.setStatus(IntentStatus.EXECUTED);
        record.setTxHash(txHash);
        record.setBlockNumber(blockNumber);
        if (labId != null) {
            record.setLabId(labId);
        }
        if (reservationKey != null) {
            record.setReservationKey(reservationKey);
        }
        persistenceService.upsert(record);
        webhookService.notify(record);
    }

    public void markFailed(IntentRecord record, String reason) {
        record.setStatus(IntentStatus.FAILED);
        record.setReason(reason);
        record.setError(reason);
        persistenceService.upsert(record);
        webhookService.notify(record);
    }

    public void updateFromOnChain(String requestId, String status, String txHash, Long blockNumber, String labId, String reservationKey, String reason) {
        IntentRecord record = intents.computeIfAbsent(requestId, key -> new IntentRecord(requestId, null, null));
        record.setStatus(mapWireStatus(status));
        record.setTxHash(txHash);
        record.setBlockNumber(blockNumber);
        if (labId != null) {
            record.setLabId(labId);
        }
        if (reservationKey != null) {
            record.setReservationKey(reservationKey);
        }
        record.setReason(reason);
        record.setError(reason);
        persistenceService.upsert(record);
        webhookService.notify(record);
    }

    private IntentStatus mapWireStatus(String status) {
        if (status == null) {
            return IntentStatus.FAILED;
        }
        return switch (status.toLowerCase()) {
            case "queued" -> IntentStatus.QUEUED;
            case "in_progress" -> IntentStatus.IN_PROGRESS;
            case "executed" -> IntentStatus.EXECUTED;
            case "failed" -> IntentStatus.FAILED;
            case "rejected" -> IntentStatus.REJECTED;
            default -> IntentStatus.FAILED;
        };
    }

    private String serializePayload(Object payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception ex) {
            return null;
        }
    }
}
