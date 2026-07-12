package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import decentralabs.blockchain.service.auth.AccessCredentialAuditService;
import decentralabs.blockchain.service.auth.SessionStartedAttestationService;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/access-audit/internal")
@RequiredArgsConstructor
public class AccessCredentialAuditController {

    private final AccessCredentialAuditService auditService;
    private final SessionStartedAttestationService sessionStartedAttestationService;

    @PostMapping("/session-observed")
    public ResponseEntity<?> recordSessionObserved(
        @RequestBody(required = false) AccessCredentialSessionObservedRequest request,
        Authentication authentication
    ) {
        String authenticatedGateway = authentication != null ? authentication.getName() : null;
        if (request != null && hasText(authenticatedGateway)) {
            if (hasText(request.getGatewayId()) && !Objects.equals(authenticatedGateway, request.getGatewayId())) {
                return ResponseEntity.status(403).body(Map.of(
                    "code", "GATEWAY_ID_MISMATCH",
                    "error", "gatewayId does not match the authenticated observer"
                ));
            }
            request.setGatewayId(authenticatedGateway);
        }
        String validationError = validateObservation(request);
        if (validationError != null) {
            return ResponseEntity.badRequest().body(Map.of(
                "code", "INVALID_REQUEST",
                "error", validationError
            ));
        }

        AccessCredentialAuditService.SessionObservationResult result = auditService.recordSessionObserved(request);
        return ResponseEntity.ok(Map.of(
            "recorded", result.recorded(),
            "auditRecorded", result.auditRecorded(),
            "attestationRecorded", result.attestationRecorded()
        ));
    }

    @GetMapping("/reservations/{reservationKey}")
    public ResponseEntity<AccessCredentialAuditSummaryResponse> getReservationAudit(
        @PathVariable String reservationKey
    ) {
        List<AccessCredentialAuditService.AuditEntry> entries = auditService.findByReservationKey(reservationKey);
        List<SessionStartedAttestationService.SessionStartedAttestationEntry> attestations =
            sessionStartedAttestationService.findByReservationKey(reservationKey);
        return ResponseEntity.ok(AccessCredentialAuditSummaryResponse.from(reservationKey, entries, attestations));
    }

    private String validateObservation(AccessCredentialSessionObservedRequest request) {
        if (request == null) {
            return "missing request body";
        }
        if (!hasText(request.getReservationKey())) {
            return "reservationKey is required";
        }
        if (!hasText(request.getCredentialHash())
            && !hasText(request.getJwtJti())
            && !hasText(request.getFmuTicketId())) {
            return "credentialHash, jwtJti or fmuTicketId is required";
        }
        return null;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public record AccessCredentialAuditSummaryResponse(
        String reservationKey,
        boolean credentialIssued,
        boolean sessionObserved,
        List<AccessCredentialAuditService.AuditEntry> entries,
        List<SessionStartedAttestationService.SessionStartedAttestationEntry> sessionStartedAttestations
    ) {
        static AccessCredentialAuditSummaryResponse from(
            String reservationKey,
            List<AccessCredentialAuditService.AuditEntry> entries,
            List<SessionStartedAttestationService.SessionStartedAttestationEntry> sessionStartedAttestations
        ) {
            boolean observed = entries.stream().anyMatch(entry -> entry != null && entry.sessionObserved());
            return new AccessCredentialAuditSummaryResponse(
                reservationKey,
                !entries.isEmpty(),
                observed,
                entries,
                sessionStartedAttestations
            );
        }
    }
}
