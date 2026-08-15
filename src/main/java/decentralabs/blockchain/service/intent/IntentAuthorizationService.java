package decentralabs.blockchain.service.intent;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAckResponse;
import decentralabs.blockchain.dto.intent.IntentAuthorizationCompleteRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationRequest;
import decentralabs.blockchain.dto.intent.IntentAuthorizationStatusResponse;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.LogSanitizer;
import decentralabs.blockchain.util.PucNormalizer;

@Service
@Slf4j
public class IntentAuthorizationService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_SAML_DIAGNOSTIC_LENGTH = 512;
    private static final Set<String> WEBAUTHN_TRANSPORTS = Set.of(
        "usb", "nfc", "ble", "smart-card", "hybrid", "internal"
    );

    private final IntentService intentService;
    private final IntentExecutionService intentExecutionService;
    private final WebauthnCredentialService webauthnCredentialService;
    private final SamlValidationService samlValidationService;
    private final BackendUrlResolver backendUrlResolver;

    @Value("${webauthn.rp.id:${base.domain:localhost}}")
    private String rpId;

    @Value("${webauthn.base-url:}")
    private String baseUrl;

    @Value("${intent.authorization.session.ttl.seconds:300}")
    private long sessionTtlSeconds;

    @Value("${intent.authorization.session.cleanup.interval.seconds:60}")
    private long cleanupIntervalSeconds;

    @Value("${intent.authorization.session.processing-lease.seconds:60}")
    private long processingLeaseSeconds;

    private final IntentAuthorizationSessionPersistenceService sessionPersistence;
    private ScheduledExecutorService cleanupScheduler;

    public IntentAuthorizationService(
        IntentService intentService,
        IntentExecutionService intentExecutionService,
        WebauthnCredentialService webauthnCredentialService,
        SamlValidationService samlValidationService,
        BackendUrlResolver backendUrlResolver,
        IntentAuthorizationSessionPersistenceService sessionPersistence
    ) {
        this.intentService = intentService;
        this.intentExecutionService = intentExecutionService;
        this.webauthnCredentialService = webauthnCredentialService;
        this.samlValidationService = samlValidationService;
        this.backendUrlResolver = backendUrlResolver;
        this.sessionPersistence = sessionPersistence;
    }

    @PostConstruct
    public void init() {
        cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "intent-auth-session-cleanup");
            t.setDaemon(true);
            return t;
        });
        cleanupScheduler.scheduleAtFixedRate(
            this::cleanupExpiredSessions,
            cleanupIntervalSeconds,
            cleanupIntervalSeconds,
            TimeUnit.SECONDS
        );
    }

    @PreDestroy
    public void shutdown() {
        if (cleanupScheduler != null) {
            cleanupScheduler.shutdown();
        }
    }

    public AuthorizationSession createSession(IntentAuthorizationRequest request) {
        IntentSubmission submission = buildSubmission(request);
        IntentMeta meta = submission.getMeta();
        intentService.enforceActionAllowedById(meta.getAction());
        String puc = resolvePuc(submission);
        if (puc == null || puc.isBlank()) {
            // codeql[java/log-injection]
            log.warn("Intent authorization PUC resolution failed. requestId={} stableUserIdMode={} payloadPucHash={}",
                LogSanitizer.sanitize(meta.getRequestId()),
                LogSanitizer.sanitize(request.getStableUserIdMode()),
                LogSanitizer.sanitize(expectedPucHash(submission.getActionPayload(), submission.getReservationPayload()))
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_puc_for_webauthn");
        }

        Set<String> seenCredentialIds = new HashSet<>();
        List<AllowedCredential> allowedCredentials = selectCredentials(puc).stream()
            .map(credential -> new AllowedCredential(
                credential.getCredentialId(),
                normalizeTransports(credential.getTransports())
            ))
            .filter(credential -> credential.getId() != null
                && !credential.getId().isBlank()
                && seenCredentialIds.add(credential.getId()))
            .toList();
        if (allowedCredentials.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered");
        }

        String challengeString = buildWebauthnChallenge(puc, meta);
        String challengeB64 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(challengeString.getBytes(StandardCharsets.UTF_8));

        String sessionId = randomSessionId();
        Instant expiresAt = Instant.now().plusSeconds(sessionTtlSeconds);

        AuthorizationSession session = new AuthorizationSession(
            sessionId,
            submission,
            allowedCredentials,
            challengeB64,
            request.getReturnUrl(),
            expiresAt
        );
        try {
            sessionPersistence.create(session);
        } catch (IntentAuthorizationSessionPersistenceException ex) {
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "intent_authorization_persistence_unavailable",
                ex
            );
        }

        // Session metadata is control-character sanitized or hashed before logging.
        // codeql[java/log-injection]
        log.info(
            "Intent authorization session created. sessionId={} requestId={} stableUserIdMode={} resolvedPucHash={} payloadPucHash={} activeCredentials={} rpId={}",
            LogSanitizer.sanitize(sessionId),
            LogSanitizer.sanitize(meta.getRequestId()),
            LogSanitizer.sanitize(request.getStableUserIdMode()),
            PucHashUtil.hashPuc(puc),
            LogSanitizer.sanitize(expectedPucHash(submission.getActionPayload(), submission.getReservationPayload())),
            allowedCredentials.size(),
            LogSanitizer.sanitize(getRelyingPartyId())
        );
        return session;
    }

    public AuthorizationSession getSession(String sessionId) {
        IntentAuthorizationSessionPersistenceService.StoredSession stored = loadSessionReadOnly(sessionId);
        if (!stored.isTerminal() && stored.session().isExpired()) {
            throw new ResponseStatusException(HttpStatus.GONE, "Session expired");
        }
        if (stored.isTerminal()) {
            if ("Session expired".equals(stored.resultError())) {
                throw new ResponseStatusException(HttpStatus.GONE, "Session expired");
            }
            throw new ResponseStatusException(HttpStatus.GONE, "Session is no longer available");
        }
        if ("PROCESSING".equals(stored.status())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Authorization is already processing");
        }
        return stored.session();
    }

    public IntentAuthorizationStatusResponse getStatus(String sessionId) {
        IntentAuthorizationSessionPersistenceService.StoredSession stored = loadSessionReadOnly(sessionId);
        boolean expired = !stored.isTerminal() && stored.session().isExpired();
        return IntentAuthorizationStatusResponse.builder()
            .sessionId(sessionId)
            .requestId(stored.session().getSubmission().getMeta().getRequestId())
            .status(expired ? "FAILED_TERMINAL" : stored.status())
            .error(expired ? "Session expired" : stored.resultError())
            .completedAt(expired ? null : stored.completedAt())
            .build();
    }

    public IntentAckResponse completeAuthorization(IntentAuthorizationCompleteRequest request) {
        if (request == null || request.getSessionId() == null || request.getSessionId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired session");
        }
        IntentAuthorizationSessionPersistenceService.StoredSession current = loadSession(request.getSessionId());
        if (current.isTerminal()) {
            return replayTerminalResult(current);
        }

        IntentAuthorizationSessionPersistenceService.ClaimedSession claim;
        try {
            claim = sessionPersistence.claim(request.getSessionId(), processingLeaseSeconds).orElse(null);
        } catch (IntentAuthorizationSessionPersistenceException ex) {
            throw persistenceUnavailable(ex);
        }
        if (claim == null) {
            current = loadSession(request.getSessionId());
            if (current.isTerminal()) {
                return replayTerminalResult(current);
            }
            log.warn("Intent authorization completion rejected: session is already processing");
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Authorization is already processing");
        }

        AuthorizationSession session = claim.stored().session();
        log.info(
            "Intent authorization completion received. credentialAllowed={} credentialIdPresent={}",
            session.getAllowedCredentials() != null && session.getAllowedCredentials().stream()
                .anyMatch(credential -> credential.getId().equals(request.getCredentialId())),
            request.getCredentialId() != null && !request.getCredentialId().isBlank()
        );
        if (session.isExpired()) {
            log.warn("Intent authorization completion rejected: session expired");
            completeClaimOrThrow(claim, "FAILED_TERMINAL", null, "Session expired", HttpStatus.GONE.value());
            throw new ResponseStatusException(HttpStatus.GONE, "Session expired");
        }
        try {
            validateCompletionRequest(session, request);

            IntentSubmission submission = session.getSubmission();
            submission.setWebauthnCredentialId(request.getCredentialId());
            submission.setWebauthnClientDataJSON(request.getClientDataJSON());
            submission.setWebauthnAuthenticatorData(request.getAuthenticatorData());
            submission.setWebauthnSignature(request.getSignature());

            IntentAckResponse ack = intentService.processIntent(submission);
            if ("accepted".equalsIgnoreCase(ack.getStatus())) {
                completeClaimOrThrow(claim, "SUCCESS", ack, null, HttpStatus.OK.value());
                log.info("Intent authorization completion accepted");
                try {
                    intentExecutionService.processQueuedIntent(ack.getRequestId());
                } catch (Exception ex) {
                    log.warn("Immediate intent execution failed");
                }
            } else {
                completeClaimOrThrow(claim, "FAILED_TERMINAL", ack, ack.getReason(), HttpStatus.BAD_REQUEST.value());
                log.warn("Intent authorization completion rejected by intent service");
            }
            return ack;
        } catch (ResponseStatusException ex) {
            boolean retryable = isRetryable(ex);
            completeClaimOrThrow(
                claim,
                retryable ? "FAILED_RETRYABLE" : "FAILED_TERMINAL",
                null,
                resultReason(ex),
                ex.getStatusCode().value()
            );
            log.warn("Intent authorization completion failed. retryable={}", retryable);
            throw ex;
        } catch (Exception ex) {
            completeClaimOrThrow(
                claim,
                "FAILED_RETRYABLE",
                null,
                "intent_authorization_processing_unavailable",
                HttpStatus.SERVICE_UNAVAILABLE.value()
            );
            log.warn("Intent authorization completion failed with a retryable processing error", ex);
            throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "intent_authorization_processing_unavailable",
                ex
            );
        }
    }

    public String getRelyingPartyId() {
        return getEffectiveRpId();
    }

    public String buildCeremonyUrl(String sessionId) {
        String effectiveBaseUrl = baseUrl;
        if (effectiveBaseUrl == null || effectiveBaseUrl.isBlank()) {
            effectiveBaseUrl = backendUrlResolver.resolveBaseDomain();
        }
        if (effectiveBaseUrl.endsWith("/")) {
            effectiveBaseUrl = effectiveBaseUrl.substring(0, effectiveBaseUrl.length() - 1);
        }
        return effectiveBaseUrl + "/intents/authorize/ceremony/" + sessionId;
    }

    private IntentSubmission buildSubmission(IntentAuthorizationRequest request) {
        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(request.getMeta());
        submission.setActionPayload(request.getActionPayload());
        submission.setReservationPayload(request.getReservationPayload());
        submission.setSignature(request.getSignature());
        submission.setSamlAssertion(request.getSamlAssertion());
        submission.setStableUserIdMode(request.getStableUserIdMode());
        return submission;
    }

    private List<WebauthnCredential> selectCredentials(String puc) {
        List<WebauthnCredential> credentials = webauthnCredentialService.getCredentials(puc);
        List<WebauthnCredential> activeCredentials = credentials.stream()
            .filter(credential -> credential.isActive())
            .sorted(Comparator.comparing(
                (WebauthnCredential credential) -> credential.getCreatedAt(),
                Comparator.nullsLast((left, right) -> left.compareTo(right))
            ).reversed())
            .toList();
        if (activeCredentials.isEmpty()) {
            log.warn("No active WebAuthn credentials for intent authorization. totalCredentials={}",
                credentials.size());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered");
        }
        log.info(
            "WebAuthn credentials selected for intent authorization. activeCredentials={} totalCredentials={}",
            activeCredentials.size(),
            credentials.size()
        );
        return activeCredentials;
    }

    private List<String> normalizeTransports(String transports) {
        if (transports == null || transports.isBlank()) {
            return List.of();
        }
        return Arrays.stream(transports.split(","))
            .map(value -> value.trim())
            .map(value -> value.toLowerCase(Locale.ROOT))
            .filter(WEBAUTHN_TRANSPORTS::contains)
            .distinct()
            .toList();
    }

    private String resolvePuc(IntentSubmission submission) {
        // Intent payloads do not carry raw PUC; derive it from the SAML assertion.
        try {
            String expectedPucHash = expectedPucHash(submission.getActionPayload(), submission.getReservationPayload());
            var samlAttributes = samlValidationService.validateSamlAssertionWithSignature(submission.getSamlAssertion());
            String samlUser = samlValidationService.resolveStableUserId(
                samlAttributes,
                submission.getStableUserIdMode(),
                expectedPucHash
            );
            String normalized = PucNormalizer.normalize(samlUser);
            if (normalized != null && !normalized.isBlank()) {
                log.info("Resolved intent authorization PUC");
                return normalized;
            }
        } catch (Exception ex) {
            Throwable rootCause = rootCause(ex);
            log.warn(
                "Invalid SAML while resolving intent authorization PUC. requestId={} exceptionType={} reason={} rootCauseType={} rootCause={}",
                LogSanitizer.sanitize(submission.getMeta().getRequestId()),
                LogSanitizer.sanitize(ex.getClass().getSimpleName()),
                sanitizeSamlDiagnostic(ex),
                LogSanitizer.sanitize(rootCause.getClass().getSimpleName()),
                sanitizeSamlDiagnostic(rootCause)
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml", ex);
        }
        return null;
    }

    private Throwable rootCause(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    private String sanitizeSamlDiagnostic(Throwable throwable) {
        String message = LogSanitizer.sanitize(throwable == null ? null : throwable.getMessage());
        if (message.length() <= MAX_SAML_DIAGNOSTIC_LENGTH) {
            return message;
        }
        return message.substring(0, MAX_SAML_DIAGNOSTIC_LENGTH) + "...";
    }

    private String expectedPucHash(ActionIntentPayload actionPayload, ReservationIntentPayload reservationPayload) {
        if (reservationPayload != null && reservationPayload.getPucHash() != null && !reservationPayload.getPucHash().isBlank()) {
            return reservationPayload.getPucHash();
        }
        if (actionPayload != null && actionPayload.getPucHash() != null && !actionPayload.getPucHash().isBlank()) {
            return actionPayload.getPucHash();
        }
        return null;
    }

    private String getEffectiveRpId() {
        if (rpId != null && !rpId.isBlank()) {
            return rpId.trim();
        }

        String candidate = baseUrl;
        if (candidate == null || candidate.isBlank()) {
            candidate = backendUrlResolver.resolveBaseDomain();
        }

        String host = extractHost(candidate);
        if (host != null && !host.isBlank()) {
            return host;
        }

        return "localhost";
    }

    private String extractHost(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }

        String host = parseHost(trimmed);
        if (host != null && !host.isBlank()) {
            return host;
        }

        String noScheme = trimmed;
        int schemeIndex = trimmed.indexOf("://");
        if (schemeIndex >= 0) {
            noScheme = trimmed.substring(schemeIndex + 3);
        }

        int slashIndex = noScheme.indexOf('/');
        if (slashIndex >= 0) {
            noScheme = noScheme.substring(0, slashIndex);
        }

        if (noScheme.startsWith("[")) {
            int end = noScheme.indexOf(']');
            if (end > 1) {
                return noScheme.substring(1, end);
            }
        }

        int colonIndex = noScheme.lastIndexOf(':');
        if (colonIndex > 0) {
            return noScheme.substring(0, colonIndex);
        }
        return noScheme;
    }

    private String parseHost(String value) {
        try {
            java.net.URI uri = new java.net.URI(value);
            if (uri.getHost() != null && !uri.getHost().isBlank()) {
                return uri.getHost();
            }
        } catch (Exception e) {
            // codeql[java/log-injection]
            log.debug("Unable to parse RP ID host '{}'", LogSanitizer.sanitize(value), e);
        }

        if (!value.contains("://")) {
            try {
                java.net.URI uri = new java.net.URI("https://" + value);
                if (uri.getHost() != null && !uri.getHost().isBlank()) {
                    return uri.getHost();
                }
            } catch (Exception e) {
                // codeql[java/log-injection]
                log.debug("Unable to parse RP ID host with https fallback '{}'", LogSanitizer.sanitize(value), e);
            }
        }

        return null;
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

    private String randomSessionId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private IntentAuthorizationSessionPersistenceService.StoredSession loadSession(String sessionId) {
        IntentAuthorizationSessionPersistenceService.StoredSession stored = loadSessionReadOnly(sessionId);
        if (!stored.isTerminal() && stored.session().isExpired()) {
            try {
                sessionPersistence.expireIfNeeded(sessionId, sessionTtlSeconds);
                stored = sessionPersistence.find(sessionId).orElse(stored);
            } catch (IntentAuthorizationSessionPersistenceException ex) {
                throw persistenceUnavailable(ex);
            }
        }
        return stored;
    }

    private IntentAuthorizationSessionPersistenceService.StoredSession loadSessionReadOnly(String sessionId) {
        IntentAuthorizationSessionPersistenceService.StoredSession stored;
        try {
            stored = sessionPersistence.find(sessionId).orElse(null);
        } catch (IntentAuthorizationSessionPersistenceException ex) {
            throw persistenceUnavailable(ex);
        }
        if (stored == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found");
        }
        return stored;
    }

    private void cleanupExpiredSessions() {
        try {
            sessionPersistence.cleanupExpiredSessions(sessionTtlSeconds);
        } catch (IntentAuthorizationSessionPersistenceException ex) {
            log.warn("Intent authorization session cleanup failed", ex);
        }
    }

    private void validateCompletionRequest(AuthorizationSession session, IntentAuthorizationCompleteRequest request) {
        if (request.getCredentialId() == null || request.getCredentialId().isBlank()) {
            log.warn("Intent authorization completion rejected: missing WebAuthn credential");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_webauthn_credential");
        }
        if (session.getAllowedCredentials() == null || session.getAllowedCredentials().isEmpty()) {
            log.warn("Intent authorization completion rejected: WebAuthn credential not registered");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered");
        }
        if (session.getAllowedCredentials().stream()
            .noneMatch(credential -> credential.getId().equals(request.getCredentialId()))) {
            log.warn("Intent authorization completion rejected: WebAuthn credential not allowed (allowedCredentials={})",
                session.getAllowedCredentials().size());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_allowed");
        }
    }

    private void completeClaimOrThrow(
        IntentAuthorizationSessionPersistenceService.ClaimedSession claim,
        String status,
        IntentAckResponse ack,
        String error,
        int httpStatus
    ) {
        try {
            boolean completed = sessionPersistence.complete(
                claim,
                status,
                ack,
                error,
                httpStatus,
                Instant.now(),
                sessionTtlSeconds
            );
            if (!completed) {
                throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "intent_authorization_lease_lost"
                );
            }
        } catch (IntentAuthorizationSessionPersistenceException ex) {
            throw persistenceUnavailable(ex);
        }
    }

    private IntentAckResponse replayTerminalResult(
        IntentAuthorizationSessionPersistenceService.StoredSession stored
    ) {
        if (stored.resultAck() != null) {
            return stored.resultAck();
        }
        int status = stored.resultHttpStatus() == null ? HttpStatus.BAD_REQUEST.value() : stored.resultHttpStatus();
        HttpStatus responseStatus = HttpStatus.resolve(status);
        throw new ResponseStatusException(
            responseStatus == null ? HttpStatus.BAD_REQUEST : responseStatus,
            stored.resultError() == null ? "Authorization already completed" : stored.resultError()
        );
    }

    private boolean isRetryable(ResponseStatusException ex) {
        if (ex.getStatusCode().is5xxServerError()) {
            return true;
        }
        return Set.of(
            "missing_webauthn_credential",
            "webauthn_credential_not_registered",
            "webauthn_credential_not_allowed"
        ).contains(ex.getReason());
    }

    private String resultReason(ResponseStatusException ex) {
        return ex.getReason() == null || ex.getReason().isBlank()
            ? "intent_authorization_failed"
            : ex.getReason();
    }

    private ResponseStatusException persistenceUnavailable(IntentAuthorizationSessionPersistenceException ex) {
        return new ResponseStatusException(
            HttpStatus.SERVICE_UNAVAILABLE,
            "intent_authorization_persistence_unavailable",
            ex
        );
    }

    @Data
    @AllArgsConstructor
    public static class AuthorizationSession {
        private String sessionId;
        @ToString.Exclude
        private IntentSubmission submission;
        private List<AllowedCredential> allowedCredentials;
        private String challenge;
        private String returnUrl;
        private Instant expiresAt;

        public boolean isExpired() {
            return expiresAt == null || !Instant.now().isBefore(expiresAt);
        }
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class AllowedCredential {
        private String id;
        private List<String> transports;
    }

}
