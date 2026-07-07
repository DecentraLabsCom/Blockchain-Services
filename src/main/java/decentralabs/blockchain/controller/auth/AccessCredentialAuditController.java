package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AccessCredentialSessionObservedRequest;
import decentralabs.blockchain.service.auth.AccessCredentialAuditService;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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

    @PostMapping("/session-observed")
    public ResponseEntity<?> recordSessionObserved(
        @RequestBody(required = false) AccessCredentialSessionObservedRequest request
    ) {
        String validationError = validateObservation(request);
        if (validationError != null) {
            return ResponseEntity.badRequest().body(Map.of(
                "code", "INVALID_REQUEST",
                "error", validationError
            ));
        }

        boolean recorded = auditService.recordSessionObserved(request);
        return ResponseEntity.ok(Map.of("recorded", recorded));
    }

    @GetMapping("/reservations/{reservationKey}")
    public ResponseEntity<AccessCredentialAuditSummaryResponse> getReservationAudit(
        @PathVariable String reservationKey
    ) {
        List<AccessCredentialAuditService.AuditEntry> entries = auditService.findByReservationKey(reservationKey);
        return ResponseEntity.ok(AccessCredentialAuditSummaryResponse.from(reservationKey, entries));
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
        List<AccessCredentialAuditService.AuditEntry> entries
    ) {
        static AccessCredentialAuditSummaryResponse from(
            String reservationKey,
            List<AccessCredentialAuditService.AuditEntry> entries
        ) {
            boolean observed = entries.stream().anyMatch(entry -> entry != null && entry.sessionObserved());
            return new AccessCredentialAuditSummaryResponse(
                reservationKey,
                !entries.isEmpty(),
                observed,
                entries
            );
        }
    }
}
