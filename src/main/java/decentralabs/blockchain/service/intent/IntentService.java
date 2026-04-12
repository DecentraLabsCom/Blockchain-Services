package decentralabs.blockchain.service.intent;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;
import java.io.ByteArrayInputStream;
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
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAction;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentStatus;
import decentralabs.blockchain.dto.intent.IntentStatusResponse;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.dto.identity.IdentityEvidenceDTO;
import decentralabs.blockchain.dto.identity.IdentityEvidenceMetadata;
import decentralabs.blockchain.dto.identity.ValidatedIdentity;
import decentralabs.blockchain.service.auth.IdentityEvidenceHashService;
import decentralabs.blockchain.service.auth.IdentityValidationStrategy;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.PucNormalizer;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.extern.slf4j.Slf4j;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.IOException;
import java.util.Base64;

@Service
@Slf4j
public class IntentService {

    private final Map<String, IntentRecord> intents = new ConcurrentHashMap<>();
    private final Map<String, String> nonceIndex = new ConcurrentHashMap<>();
    private final Map<String, Long> evidenceReplayCache = new ConcurrentHashMap<>();

    private final String defaultEta;
    private final long evidenceReplayTtlMs;
    private final Eip712IntentVerifier verifier;
    private final IntentPersistenceService persistenceService;
    private final IntentWebhookService webhookService;
    private final SamlValidationService samlValidationService;
    private final WebauthnCredentialService webauthnCredentialService;
    private final WalletService walletService;
    private final String contractAddress;
    private final MeterRegistry meterRegistry;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // XXX: LEGACY - Identity validation strategy injection for unified identity model
    // TODO: Once the new identity flow is validated, remove legacy SAML-only validation
    private final List<IdentityValidationStrategy> identityStrategies;
    private final IdentityEvidenceHashService identityHashService;

    public IntentService(
        @Value("${intent.default-eta:15s}") String defaultEta,
        @Value("${intent.saml.replay-ttl-ms:60000}") long evidenceReplayTtlMs,
        Eip712IntentVerifier verifier,
        IntentPersistenceService persistenceService,
        IntentWebhookService webhookService,
        SamlValidationService samlValidationService,
        WebauthnCredentialService webauthnCredentialService,
        WalletService walletService,
        @Value("${contract.address}") String contractAddress,
        MeterRegistry meterRegistry,
        // XXX: LEGACY - These dependencies will replace SAML-only validation once new flow is validated
        List<IdentityValidationStrategy> identityStrategies,
        IdentityEvidenceHashService identityHashService
    ) {
        this.defaultEta = defaultEta;
        this.evidenceReplayTtlMs = evidenceReplayTtlMs;
        this.verifier = verifier;
        this.persistenceService = persistenceService;
        this.webhookService = webhookService;
        this.samlValidationService = samlValidationService;
        this.webauthnCredentialService = webauthnCredentialService;
        this.walletService = walletService;
        this.contractAddress = contractAddress;
        this.meterRegistry = meterRegistry;
        this.identityStrategies = identityStrategies != null ? identityStrategies : List.of();
        this.identityHashService = identityHashService;
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

        // XXX: LEGACY - Unified identity validation with strategy pattern.
        // This path uses the new ValidatedIdentity model when identityEvidence is present,
        // and falls back to legacy SAML validation when it's not.
        // TODO: Remove SAML fallback once the new flow is validated.
        ValidatedIdentity validatedIdentity = resolveValidatedIdentity(submission);
        String evidenceHash = validatedIdentity.evidenceHash();

        // Validate evidence hash matches the one in payload
        ensurePayloadEvidenceHash(actionPayload, reservationPayload, evidenceHash);

        // Anti-replay check using canonical evidence hash
        checkEvidenceReplay(evidenceHash);

        // Extract PUC from validated identity
        String puc = resolvePucFromIdentity(validatedIdentity, actionPayload, reservationPayload);

        enforceLabCreatorOwnershipPrecheck(action, actionPayload, puc);
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
        markEvidenceUsed(evidenceHash);

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

        log.info("Intent {} queued (action={}, provider={}, labId={}, reservationKey={}, identityType={})",
            LogSanitizer.sanitize(meta.getRequestId()), action.getWireValue(), 
            LogSanitizer.maskIdentifier(meta.getExecutor()), 
            LogSanitizer.sanitize(record.getLabId()), 
            LogSanitizer.sanitize(record.getReservationKey()),
            validatedIdentity.type());

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

    @Observed(name = "intent.reconciliation", contextualName = "reconcile-intents")
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

        purgeExpiredEvidence(now * 1000);
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
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "executor mismatch");
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
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "executor mismatch");
            }
            if (isBlank(actionPayload.getPuc())) {
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

    private void enforceLabCreatorOwnershipPrecheck(
        IntentAction action,
        ActionIntentPayload actionPayload,
        String puc
    ) {
        if (!requiresLabCreatorOwnershipPrecheck(action) || actionPayload == null || actionPayload.getLabId() == null) {
            return;
        }

        String normalizedPuc = PucNormalizer.normalize(puc);
        if (normalizedPuc == null || normalizedPuc.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing puc");
        }

        String expectedHash = normalizeBytes32(Numeric.toHexString(Hash.sha3(normalizedPuc.getBytes(StandardCharsets.UTF_8))));
        String storedHash = fetchCreatorPucHash(actionPayload.getLabId());

        if (storedHash == null || Numeric.toBigInt(storedHash).equals(BigInteger.ZERO)) {
            recordCreatorOwnershipMetric("authorization.lab_legacy_blocked.count", action, actionPayload);
            log.warn(
                "Intent rejected: legacy lab blocked (action={}, labId={})",
                action.getWireValue(),
                LogSanitizer.sanitize(actionPayload.getLabId().toString())
            );
            throw new ResponseStatusException(HttpStatus.CONFLICT, "LAB_LEGACY_BLOCKED");
        }

        if (!storedHash.equalsIgnoreCase(expectedHash)) {
            recordCreatorOwnershipMetric("authorization.lab_creator_mismatch.count", action, actionPayload);
            log.warn(
                "Intent rejected: creator mismatch (action={}, labId={})",
                action.getWireValue(),
                LogSanitizer.sanitize(actionPayload.getLabId().toString())
            );
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "LAB_CREATOR_MISMATCH");
        }
    }

    private void recordCreatorOwnershipMetric(String metricName, IntentAction action, ActionIntentPayload actionPayload) {
        if (meterRegistry == null) {
            return;
        }

        String institution = "unknown";
        String labId = "unknown";
        String actionType = action == null ? "unknown" : action.getWireValue();

        if (actionPayload != null) {
            if (actionPayload.getSchacHomeOrganization() != null && !actionPayload.getSchacHomeOrganization().isBlank()) {
                institution = actionPayload.getSchacHomeOrganization().trim().toLowerCase(Locale.ROOT);
            }
            if (actionPayload.getLabId() != null) {
                labId = actionPayload.getLabId().toString();
            }
        }

        meterRegistry.counter(
            metricName,
            "institution", institution,
            "actionType", actionType,
            "labId", labId
        ).increment();
    }

    private boolean requiresLabCreatorOwnershipPrecheck(IntentAction action) {
        return action == IntentAction.LAB_SET_URI
            || action == IntentAction.LAB_UPDATE
            || action == IntentAction.LAB_DELETE
            || action == IntentAction.LAB_LIST
            || action == IntentAction.LAB_UNLIST
            || action == IntentAction.REQUEST_FUNDS;
    }

    String fetchCreatorPucHash(BigInteger labId) {
        try {
            Web3j web3j = walletService.getWeb3jInstance();
            Diamond diamond = Diamond.load(
                contractAddress,
                web3j,
                new ReadonlyTransactionManager(web3j, contractAddress),
                new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
            );
            return normalizeBytes32(Numeric.toHexString(diamond.getCreatorPucHash(labId).send()));
        } catch (Exception ex) {
            log.warn("Unable to fetch creator hash for lab {}: {}", labId, LogSanitizer.sanitize(ex.getMessage()));
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "creator_hash_lookup_failed");
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

    // =========================================================================
    // XXX: LEGACY - Unified Identity Validation
    // These methods implement the strategy pattern for identity validation.
    // TODO: Remove SAML fallback code once the new flow is validated.
    // =========================================================================

    /**
     * Resolves validated identity from submission using the unified identity model.
     * If identityEvidence is present, uses the strategy pattern for validation.
     * Otherwise, falls back to legacy SAML validation.
     *
     * @param submission the intent submission containing identity evidence
     * @return ValidatedIdentity containing validated claims, metadata and evidence hash
     * @throws ResponseStatusException if identity validation fails
     */
    private ValidatedIdentity resolveValidatedIdentity(IntentSubmission submission) {
        IdentityEvidenceDTO identityEvidence = submission.getIdentityEvidence();

        if (identityEvidence != null) {
            // New unified identity flow: use strategy pattern
            String evidenceType = identityEvidence.type();
            if (evidenceType == null || evidenceType.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "identity_evidence_missing_type");
            }

            IdentityValidationStrategy strategy = findStrategyForType(evidenceType);
            if (strategy == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "unsupported_identity_evidence_type: " + evidenceType);
            }

            try {
                ValidatedIdentity validated = strategy.validate(identityEvidence);
                log.debug("Identity validated via strategy {}: type={}, userId={}",
                    strategy.getClass().getSimpleName(),
                    validated.type(),
                    validated.claims() != null ? validated.claims().stableUserId() : "unknown");
                return validated;
            } catch (IllegalArgumentException ex) {
                log.warn("Identity validation failed for type {}: {}",
                    evidenceType, ex.getMessage());
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "invalid_identity_evidence: " + ex.getMessage());
            }
        }

        // XXX: LEGACY - Fallback to SAML-only validation until new flow is validated.
        // TODO: This fallback should be removed once the new identityEvidence flow
        // is proven to work correctly in production.
        return validateSamlLegacy(submission);
    }

    /**
     * Finds an identity validation strategy for the given evidence type.
     *
     * @param type the evidence type (e.g., "saml", "openid4vp")
     * @return the matching strategy, or null if not found
     */
    private IdentityValidationStrategy findStrategyForType(String type) {
        if (identityStrategies == null || identityStrategies.isEmpty()) {
            return null;
        }
        return identityStrategies.stream()
            .filter(s -> s.supports(type))
            .findFirst()
            .orElse(null);
    }

    /**
     * Legacy SAML validation that bypasses the strategy pattern.
     * This method should be removed once all deployments use the new identity flow.
     *
     * XXX: LEGACY - Direct SAML validation without strategy pattern.
     * TODO: Remove this method once all callers migrate to resolveValidatedIdentity().
     */
    private ValidatedIdentity validateSamlLegacy(IntentSubmission submission) {
        String samlAssertion = submission.getSamlAssertion();
        if (samlAssertion == null || samlAssertion.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_saml_for_intent");
        }

        // Compute evidence hash from SAML assertion using legacy method
        String evidenceHash = computeLegacyAssertionHash(samlAssertion);

        // Validate SAML and extract claims
        Map<String, String> samlAttrs;
        try {
            samlAttrs = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
        } catch (Exception ex) {
            log.warn("Legacy SAML validation failed: {}", ex.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml");
        }

        String userId = samlAttrs.get("userid");
        if (userId == null || userId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml");
        }

        String puc = resolvePuc(submission.getActionPayload(), submission.getReservationPayload());
        String normalizedPuc = PucNormalizer.normalize(puc);
        String normalizedUserId = PucNormalizer.normalize(userId);

        if (normalizedPuc != null && !normalizedPuc.isBlank()
            && normalizedUserId != null && !normalizedUserId.isBlank()
            && !normalizedPuc.equals(normalizedUserId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "puc_saml_mismatch");
        }

        decentralabs.blockchain.dto.identity.NormalizedClaims claims =
            decentralabs.blockchain.dto.identity.NormalizedClaims.builder()
                .stableUserId(userId)
                .institutionId(samlAttrs.get("schacHomeOrganization"))
                .role(samlAttrs.get("role"))
                .scopedRole(samlAttrs.get("scopedRole"))
                .puc(puc)
                .email(samlAttrs.get("email"))
                .name(samlAttrs.get("name"))
                .build();

        IdentityEvidenceMetadata metadata = new IdentityEvidenceMetadata(
            samlAttrs.get("issuer"),
            Instant.now(),
            null, // expiresAt not computed in legacy path
            null, // nonce not available
            null, // audience not available
            true, // verified by SAML validation
            "saml"
        );

        return new ValidatedIdentity("saml", "saml2-base64", claims, metadata, evidenceHash);
    }

    // XXX: LEGACY - This method computes hash directly from raw SAML assertion.
    // TODO: Remove this method once the new identityEvidence flow is validated.
    // The new flow uses evidenceHash from ValidatedIdentity instead.
    private String computeLegacyAssertionHash(String samlAssertion) {
        byte[] digest = Hash.sha3(samlAssertion.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(digest));
    }

    // =========================================================================
    // End of XXX: LEGACY - Unified Identity Validation
    // =========================================================================

    /**
     * Resolves PUC from validated identity or falls back to payload values.
     */
    private String resolvePucFromIdentity(ValidatedIdentity identity, ActionIntentPayload actionPayload, ReservationIntentPayload reservationPayload) {
        // First try to get PUC from validated identity claims
        if (identity != null && identity.claims() != null && identity.claims().puc() != null && !isBlank(identity.claims().puc())) {
            return identity.claims().puc();
        }
        // Fallback to payload-based PUC
        return resolvePuc(actionPayload, reservationPayload);
    }

    private void ensurePayloadEvidenceHash(
        ActionIntentPayload actionPayload,
        ReservationIntentPayload reservationPayload,
        String expectedHash
    ) {
        if (actionPayload != null) {
            String payloadHash = normalizeBytes32(actionPayload.getAssertionHash());
            if (payloadHash == null || !expectedHash.equalsIgnoreCase(payloadHash)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "evidence_hash_mismatch");
            }
        }
        if (reservationPayload != null) {
            String payloadHash = normalizeBytes32(reservationPayload.getAssertionHash());
            if (payloadHash == null || !expectedHash.equalsIgnoreCase(payloadHash)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "evidence_hash_mismatch");
            }
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

    // XXX: LEGACY - These methods use "assertion" naming but now work with evidence hash.
    // TODO: Rename to evidence-related terms once legacy SAML is removed.
    private void checkEvidenceReplay(String evidenceHash) {
        if (evidenceHash == null || evidenceHash.isBlank()) {
            return;
        }
        long nowMs = Instant.now().toEpochMilli();
        purgeExpiredEvidence(nowMs);
        Long expiresAt = evidenceReplayCache.get(evidenceHash);
        if (expiresAt != null && expiresAt > nowMs) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "evidence_replay");
        }
    }

    private void markEvidenceUsed(String evidenceHash) {
        if (evidenceHash == null || evidenceHash.isBlank()) {
            return;
        }
        long nowMs = Instant.now().toEpochMilli();
        long ttl = evidenceReplayTtlMs <= 0 ? 0 : evidenceReplayTtlMs;
        evidenceReplayCache.put(evidenceHash, nowMs + ttl);
    }

    private void purgeExpiredEvidence(long nowMs) {
        evidenceReplayCache.entrySet().removeIf(entry -> entry.getValue() <= nowMs);
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

        String expectedChallenge = buildWebauthnChallenge(puc, meta);
        String legacyExpectedChallenge = buildLegacyWebauthnChallenge(puc, credentialId, meta);
        
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
            expectedChallenge,
            legacyExpectedChallenge
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

    private String buildWebauthnChallenge(String puc, IntentMeta meta) {
        return String.join("|",
            puc.toLowerCase(Locale.ROOT),
            meta.getRequestId(),
            meta.getPayloadHash(),
            String.valueOf(meta.getNonce()),
            String.valueOf(meta.getRequestedAt()),
            String.valueOf(meta.getExpiresAt()),
            String.valueOf(meta.getAction())
        );
    }

    private String buildLegacyWebauthnChallenge(String puc, String credentialId, IntentMeta meta) {
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
        String expectedChallenge,
        String legacyExpectedChallenge
    ) {
        try {
            byte[] clientData = Base64.getUrlDecoder().decode(clientDataJSONb64);
            byte[] authenticatorData = Base64.getUrlDecoder().decode(authenticatorDatab64);
            byte[] signature = Base64.getUrlDecoder().decode(signatureB64);

            String challengeFromClient = extractChallengeFromClientData(clientData);
            String expectedChallengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedChallenge.getBytes(StandardCharsets.UTF_8));
            String legacyExpectedChallengeB64 = legacyExpectedChallenge == null ? null
                : Base64.getUrlEncoder().withoutPadding().encodeToString(legacyExpectedChallenge.getBytes(StandardCharsets.UTF_8));
            boolean matchesCurrent = expectedChallengeB64.equals(challengeFromClient);
            boolean matchesLegacy = legacyExpectedChallengeB64 != null && legacyExpectedChallengeB64.equals(challengeFromClient);
            if (!matchesCurrent && !matchesLegacy) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_challenge_mismatch");
            }

            byte[] clientHash = sha256(clientData);
            byte[] signed = concat(authenticatorData, clientHash);

            PublicKey publicKey = decodePublicKey(cred.getPublicKey());
            String signatureAlgorithm = resolveSignatureAlgorithm(publicKey);
            Signature sig = Signature.getInstance(signatureAlgorithm);
            sig.initVerify(publicKey);
            sig.update(signed);
            if (!sig.verify(signature)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_signature_invalid");
            }
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("WebAuthn assertion validation failed: {}", ex.getMessage());
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
        byte[] keyBytes = decodeBase64Flexible(publicKeyBase64);
        PublicKey coseKey = decodeCosePublicKey(keyBytes);
        if (coseKey != null) {
            return coseKey;
        }
        return decodeX509PublicKey(keyBytes);
    }

    private byte[] decodeBase64Flexible(String value) {
        String normalized = value == null ? "" : value.trim();
        String padded = padBase64(normalized);
        try {
            return Base64.getUrlDecoder().decode(padded);
        } catch (IllegalArgumentException ex) {
            return Base64.getDecoder().decode(padded);
        }
    }

    private String padBase64(String value) {
        int mod = value.length() % 4;
        if (mod == 2) {
            return value + "==";
        }
        if (mod == 3) {
            return value + "=";
        }
        return value;
    }

    private PublicKey decodeCosePublicKey(byte[] keyBytes) throws Exception {
        try {
            List<DataItem> items = new CborDecoder(new ByteArrayInputStream(keyBytes)).decode();
            if (items.isEmpty() || !(items.get(0) instanceof co.nstant.in.cbor.model.Map)) {
                return null;
            }
            co.nstant.in.cbor.model.Map coseKey = (co.nstant.in.cbor.model.Map) items.get(0);
            Long keyType = getCoseLong(coseKey, 1);
            if (keyType == null) {
                return null;
            }
            if (keyType == 2L) { // EC2
                return decodeCoseEcKey(coseKey);
            }
            if (keyType == 3L) { // RSA
                return decodeCoseRsaKey(coseKey);
            }
            return null;
        } catch (CborException ex) {
            return null;
        }
    }

    private PublicKey decodeCoseEcKey(co.nstant.in.cbor.model.Map coseKey) throws Exception {
        byte[] x = getCoseBytes(coseKey, -2);
        byte[] y = getCoseBytes(coseKey, -3);
        if (x == null || y == null) {
            throw new IllegalArgumentException("Missing COSE EC coordinates");
        }
        ECParameterSpec params = resolveEcParameters(getCoseLong(coseKey, -1));
        ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        ECPublicKeySpec spec = new ECPublicKeySpec(w, params);
        return KeyFactory.getInstance("EC").generatePublic(spec);
    }

    private PublicKey decodeCoseRsaKey(co.nstant.in.cbor.model.Map coseKey) throws Exception {
        byte[] n = getCoseBytes(coseKey, -1);
        byte[] e = getCoseBytes(coseKey, -2);
        if (n == null || e == null) {
            throw new IllegalArgumentException("Missing COSE RSA parameters");
        }
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e));
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private ECParameterSpec resolveEcParameters(Long curve) throws Exception {
        String curveName;
        if (curve == null || curve == 1L) {
            curveName = "secp256r1";
        } else if (curve == 2L) {
            curveName = "secp384r1";
        } else if (curve == 3L) {
            curveName = "secp521r1";
        } else {
            throw new IllegalArgumentException("Unsupported COSE curve: " + curve);
        }
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private Long getCoseLong(co.nstant.in.cbor.model.Map coseKey, long key) {
        DataItem item = getCoseItem(coseKey, key);
        if (item instanceof UnsignedInteger unsignedInt) {
            return unsignedInt.getValue().longValue();
        }
        if (item instanceof NegativeInteger negativeInt) {
            return negativeInt.getValue().longValue();
        }
        return null;
    }

    private byte[] getCoseBytes(co.nstant.in.cbor.model.Map coseKey, long key) {
        DataItem item = getCoseItem(coseKey, key);
        if (item instanceof ByteString byteString) {
            return byteString.getBytes();
        }
        return null;
    }

    private DataItem getCoseItem(co.nstant.in.cbor.model.Map coseKey, long key) {
        DataItem keyItem = key >= 0 ? new UnsignedInteger(key) : new NegativeInteger(key);
        return coseKey.get(keyItem);
    }

    private PublicKey decodeX509PublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        try {
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (Exception ex) {
            // Fall through and try other key types.
        }
        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception ex) {
            // Fall through to last attempt.
        }
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }

    private String resolveSignatureAlgorithm(PublicKey publicKey) {
        if (publicKey instanceof ECPublicKey) {
            return "SHA256withECDSA";
        }
        if (publicKey instanceof RSAPublicKey) {
            return "SHA256withRSA";
        }
        String algorithm = publicKey.getAlgorithm();
        if ("Ed25519".equalsIgnoreCase(algorithm) || "EdDSA".equalsIgnoreCase(algorithm)) {
            return "Ed25519";
        }
        throw new IllegalArgumentException("Unsupported WebAuthn public key algorithm: " + algorithm);
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

    public Optional<String> findPucByReservationKey(String reservationKey) {
        String normalized = normalizeBytes32(reservationKey);
        if (normalized == null) {
            return Optional.empty();
        }

        IntentRecord record = intents.values().stream()
            .filter(intent -> normalized.equalsIgnoreCase(intent.getReservationKey()))
            .findFirst()
            .orElse(null);

        if (record == null) {
            record = persistenceService.findByReservationKey(normalized).orElse(null);
            if (record != null && record.getRequestId() != null) {
                intents.put(record.getRequestId(), record);
                if (record.getSigner() != null && record.getNonce() != null) {
                    nonceIndex.put(buildNonceKey(record.getSigner(), record.getNonce()), record.getRequestId());
                }
            }
        }

        if (record == null || isBlank(record.getPuc())) {
            return Optional.empty();
        }
        return Optional.of(record.getPuc());
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
        markFailed(record, reason, null, null);
    }

    public void markFailed(IntentRecord record, String reason, String txHash, Long blockNumber) {
        record.setStatus(IntentStatus.FAILED);
        record.setReason(reason);
        record.setError(reason);
        if (txHash != null && !txHash.isBlank()) {
            record.setTxHash(txHash);
        }
        if (blockNumber != null) {
            record.setBlockNumber(blockNumber);
        }
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
