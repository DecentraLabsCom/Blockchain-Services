package decentralabs.blockchain.service.intent;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
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
import decentralabs.blockchain.dto.intent.IntentSubmission;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.auth.WebauthnCredentialService;
import decentralabs.blockchain.service.auth.WebauthnCredentialService.WebauthnCredential;

@Service
@Slf4j
public class IntentAuthorizationService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final IntentService intentService;
    private final WebauthnCredentialService webauthnCredentialService;

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
        WebauthnCredentialService webauthnCredentialService
    ) {
        this.intentService = intentService;
        this.webauthnCredentialService = webauthnCredentialService;
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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "missing_puc_for_webauthn");
        }

        WebauthnCredential credential = selectCredential(puc);
        String challengeString = buildWebauthnChallenge(puc, credential.getCredentialId(), meta);
        String challengeB64 = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(challengeString.getBytes(StandardCharsets.UTF_8));

        String sessionId = randomSessionId();
        Instant expiresAt = Instant.now().plusSeconds(sessionTtlSeconds);

        AuthorizationSession session = new AuthorizationSession(
            sessionId,
            submission,
            credential.getCredentialId(),
            challengeB64,
            request.getReturnUrl(),
            expiresAt
        );
        pendingSessions.put(sessionId, session);

        log.info("Intent authorization session created. sessionId={} requestId={}", sessionId, meta.getRequestId());
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

    public IntentAckResponse completeAuthorization(IntentAuthorizationCompleteRequest request) {
        AuthorizationSession session = pendingSessions.remove(request.getSessionId());
        if (session == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired session");
        }
        if (session.isExpired()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Session expired");
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
            throw ex;
        }

        if ("accepted".equalsIgnoreCase(ack.getStatus())) {
            storeResult(session, "SUCCESS", null);
        } else {
            storeResult(session, "FAILED", ack.getReason());
        }
        return ack;
    }

    public String getRelyingPartyId() {
        return rpId;
    }

    public String buildCeremonyUrl(String sessionId) {
        String effectiveBaseUrl = baseUrl;
        if (effectiveBaseUrl == null || effectiveBaseUrl.isBlank()) {
            effectiveBaseUrl = "https://" + rpId;
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
        return submission;
    }

    private WebauthnCredential selectCredential(String puc) {
        List<WebauthnCredential> credentials = webauthnCredentialService.getCredentials(puc);
        return credentials.stream()
            .filter(WebauthnCredential::isActive)
            .max(Comparator.comparing(WebauthnCredential::getCreatedAt, Comparator.nullsLast(Long::compareTo)))
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "webauthn_credential_not_registered"));
    }

    private String resolvePuc(IntentSubmission submission) {
        ReservationIntentPayload reservationPayload = submission.getReservationPayload();
        ActionIntentPayload actionPayload = submission.getActionPayload();
        if (reservationPayload != null && reservationPayload.getPuc() != null) {
            return reservationPayload.getPuc();
        }
        if (actionPayload != null) {
            return actionPayload.getPuc();
        }
        return null;
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
        private String credentialId;
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
