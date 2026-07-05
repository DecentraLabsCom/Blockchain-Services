package decentralabs.blockchain.service.intent;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.AllArgsConstructor;
import lombok.Data;
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
import decentralabs.blockchain.dto.intent.IntentRegistrationSignalRequest;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.PucNormalizer;

@Service
@Slf4j
public class IntentAuthorizationService {

    private static final SecureRandom RANDOM = new SecureRandom();

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

    private final ConcurrentHashMap<String, AuthorizationSession> pendingSessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AuthorizationResult> completedSessions = new ConcurrentHashMap<>();
    private ScheduledExecutorService cleanupScheduler;

    public IntentAuthorizationService(
        IntentService intentService,
        IntentExecutionService intentExecutionService,
        WebauthnCredentialService webauthnCredentialService,
        SamlValidationService samlValidationService,
        BackendUrlResolver backendUrlResolver
    ) {
        this.intentService = intentService;
        this.intentExecutionService = intentExecutionService;
        this.webauthnCredentialService = webauthnCredentialService;
        this.samlValidationService = samlValidationService;
        this.backendUrlResolver = backendUrlResolver;
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
        String puc = resolvePuc(submission);
        if (puc == null || puc.isBlank()) {
            log.warn("Intent authorization PUC resolution failed. requestId={} stableUserIdMode={} payloadPucHash={}",
                meta.getRequestId(),
                request.getStableUserIdMode(),
                expectedPucHash(submission.getActionPayload(), submission.getReservationPayload())
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_puc_for_webauthn");
        }

        List<WebauthnCredential> activeCredentials = selectCredentials(puc, meta);
        List<String> credentialIds = activeCredentials.stream()
            .map(credential -> credential.getCredentialId())
            .filter(id -> id != null && !id.isBlank())
            .distinct()
            .toList();
        if (credentialIds.isEmpty()) {
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
            credentialIds,
            challengeB64,
            request.getReturnUrl(),
            expiresAt
        );
        pendingSessions.put(sessionId, session);

        log.info(
            "Intent authorization session created. sessionId={} requestId={} stableUserIdMode={} resolvedPucHash={} payloadPucHash={} activeCredentials={} rpId={}",
            sessionId,
            meta.getRequestId(),
            request.getStableUserIdMode(),
            PucHashUtil.hashPuc(puc),
            expectedPucHash(submission.getActionPayload(), submission.getReservationPayload()),
            credentialIds.size(),
            getRelyingPartyId()
        );
        return session;
    }

    public AuthorizationSession getSession(String sessionId) {
        AuthorizationSession session = pendingSessions.get(sessionId);
        if (session == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found");
        }
        if (session.isExpired()) {
            pendingSessions.remove(sessionId);
            throw new ResponseStatusException(HttpStatus.GONE, "Session expired");
        }
        return session;
    }

    public IntentAuthorizationStatusResponse getStatus(String sessionId) {
        AuthorizationSession pending = pendingSessions.get(sessionId);
        if (pending != null) {
            return IntentAuthorizationStatusResponse.builder()
                .sessionId(sessionId)
                .requestId(pending.getSubmission().getMeta().getRequestId())
                .status("PENDING")
                .build();
        }

        AuthorizationResult completed = completedSessions.get(sessionId);
        if (completed != null) {
            return IntentAuthorizationStatusResponse.builder()
                .sessionId(sessionId)
                .requestId(completed.requestId())
                .status(completed.status())
                .error(completed.error())
                .completedAt(completed.completedAt())
                .build();
        }

        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found");
    }

    public Map<String, String> handleRegistrationSignal(String requestId, IntentRegistrationSignalRequest request) {
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing registration signal");
        }
        return intentExecutionService.handleRegistrationSignal(
            requestId,
            request.getEvent(),
            request.getTxHash(),
            request.getBlockNumber(),
            request.getReason()
        );
    }

    public IntentAckResponse completeAuthorization(IntentAuthorizationCompleteRequest request) {
        AuthorizationSession session = pendingSessions.remove(request.getSessionId());
        if (session == null) {
            log.warn("Intent authorization completion rejected. sessionId={} reason=invalid_or_expired_session", request.getSessionId());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired session");
        }
        String requestId = session.getSubmission().getMeta().getRequestId();
        log.info(
            "Intent authorization completion received. sessionId={} requestId={} credentialAllowed={} credentialIdPresent={}",
            request.getSessionId(),
            requestId,
            session.getCredentialIds() != null && session.getCredentialIds().contains(request.getCredentialId()),
            request.getCredentialId() != null && !request.getCredentialId().isBlank()
        );
        if (session.isExpired()) {
            log.warn("Intent authorization completion rejected. sessionId={} requestId={} reason=session_expired", request.getSessionId(), requestId);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Session expired");
        }
        if (request.getCredentialId() == null || request.getCredentialId().isBlank()) {
            log.warn("Intent authorization completion rejected. sessionId={} requestId={} reason=missing_webauthn_credential", request.getSessionId(), requestId);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_webauthn_credential");
        }
        if (session.getCredentialIds() == null || session.getCredentialIds().isEmpty()) {
            log.warn("Intent authorization completion rejected. sessionId={} requestId={} reason=webauthn_credential_not_registered", request.getSessionId(), requestId);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered");
        }
        if (!session.getCredentialIds().contains(request.getCredentialId())) {
            log.warn("Intent authorization completion rejected. sessionId={} requestId={} reason=webauthn_credential_not_allowed allowedCredentials={}",
                request.getSessionId(),
                requestId,
                session.getCredentialIds().size()
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_allowed");
        }

        IntentSubmission submission = session.getSubmission();
        submission.setWebauthnCredentialId(request.getCredentialId());
        submission.setWebauthnClientDataJSON(request.getClientDataJSON());
        submission.setWebauthnAuthenticatorData(request.getAuthenticatorData());
        submission.setWebauthnSignature(request.getSignature());

        IntentAckResponse ack;
        try {
            ack = intentService.processIntent(submission);
        } catch (ResponseStatusException ex) {
            storeResult(session, "FAILED", ex.getReason());
            log.warn("Intent authorization completion failed. sessionId={} requestId={} reason={}", request.getSessionId(), requestId, ex.getReason());
            throw ex;
        }

        if ("accepted".equalsIgnoreCase(ack.getStatus())) {
            storeResult(session, "SUCCESS", null);
            log.info("Intent authorization completion accepted. sessionId={} requestId={}", request.getSessionId(), requestId);
            try {
                intentExecutionService.processQueuedIntent(ack.getRequestId());
            } catch (Exception ex) {
                log.warn("Immediate intent execution failed for {}: {}", ack.getRequestId(), ex.getMessage(), ex);
            }
        } else {
            storeResult(session, "FAILED", ack.getReason());
            log.warn("Intent authorization completion rejected by intent service. sessionId={} requestId={} reason={}", request.getSessionId(), requestId, ack.getReason());
        }
        return ack;
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

    private List<WebauthnCredential> selectCredentials(String puc, IntentMeta meta) {
        List<WebauthnCredential> credentials = webauthnCredentialService.getCredentials(puc);
        List<WebauthnCredential> activeCredentials = credentials.stream()
            .filter(credential -> credential.isActive())
            .sorted(Comparator.comparing(
                (WebauthnCredential credential) -> credential.getCreatedAt(),
                Comparator.nullsLast((left, right) -> left.compareTo(right))
            ).reversed())
            .toList();
        if (activeCredentials.isEmpty()) {
            log.warn(
                "No active WebAuthn credentials for intent authorization. requestId={} resolvedPucHash={} totalCredentials={}",
                meta.getRequestId(),
                PucHashUtil.hashPuc(puc),
                credentials.size()
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered");
        }
        log.info(
            "WebAuthn credentials selected for intent authorization. requestId={} resolvedPucHash={} activeCredentials={} totalCredentials={}",
            meta.getRequestId(),
            PucHashUtil.hashPuc(puc),
            activeCredentials.size(),
            credentials.size()
        );
        return activeCredentials;
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
                log.info(
                    "Resolved intent authorization PUC. requestId={} stableUserIdMode={} samlUserHash={} resolvedPucHash={} payloadPucHash={}",
                    submission.getMeta().getRequestId(),
                    submission.getStableUserIdMode(),
                    PucHashUtil.hashPuc(samlAttributes.get("userid")),
                    PucHashUtil.hashPuc(normalized),
                    expectedPucHash
                );
                return normalized;
            }
        } catch (Exception ex) {
            log.warn("Invalid SAML while resolving intent authorization PUC. requestId={} reason={}",
                submission.getMeta() != null ? submission.getMeta().getRequestId() : null,
                ex.getMessage()
            );
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_saml", ex);
        }
        return null;
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
            log.debug("Unable to parse RP ID host '{}'", value, e);
        }

        if (!value.contains("://")) {
            try {
                java.net.URI uri = new java.net.URI("https://" + value);
                if (uri.getHost() != null && !uri.getHost().isBlank()) {
                    return uri.getHost();
                }
            } catch (Exception e) {
                log.debug("Unable to parse RP ID host with https fallback '{}'", value, e);
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

    private void storeResult(AuthorizationSession session, String status, String error) {
        completedSessions.put(session.getSessionId(), new AuthorizationResult(
            status,
            session.getSubmission().getMeta().getRequestId(),
            error,
            Instant.now()
        ));
    }

    private void cleanupExpiredSessions() {
        Instant now = Instant.now();
        pendingSessions.entrySet().removeIf(entry -> entry.getValue().getExpiresAt().isBefore(now));
        completedSessions.entrySet().removeIf(entry -> entry.getValue().completedAt().isBefore(now.minusSeconds(sessionTtlSeconds)));
    }

    @Data
    @AllArgsConstructor
    public static class AuthorizationSession {
        private String sessionId;
        private IntentSubmission submission;
        private List<String> credentialIds;
        private String challenge;
        private String returnUrl;
        private Instant expiresAt;

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    private record AuthorizationResult(
        String status,
        String requestId,
        String error,
        Instant completedAt
    ) {}
}
