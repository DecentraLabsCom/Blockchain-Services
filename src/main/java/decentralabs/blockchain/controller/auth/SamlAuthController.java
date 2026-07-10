package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.AccessCodeIssueRequest;
import decentralabs.blockchain.dto.auth.AccessCodeRedeemRequest;
import decentralabs.blockchain.dto.auth.AccessCodeResponse;
import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.AccessAuthorizationPendingException;
import decentralabs.blockchain.exception.AccessAuthorizationRejectedException;
import decentralabs.blockchain.exception.SamlAuthenticationException;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.SamlAuthService;
import decentralabs.blockchain.service.auth.AccessCodeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.LinkedHashMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
public class SamlAuthController {

    private final SamlAuthService samlAuthService;
    private final InstitutionalCheckInService institutionalCheckInService;
    private final AccessCodeService accessCodeService;

    @PostMapping("/access-code/issue")
    public ResponseEntity<AccessCodeResponse> issueAccessCode(@RequestBody AccessCodeIssueRequest request) {
        return ResponseEntity.ok(accessCodeService.issue(request.getToken(), request.getLabURL()));
    }

    @PostMapping("/access-code/redeem")
    public ResponseEntity<AuthResponse> redeemAccessCode(@RequestBody AccessCodeRedeemRequest request) {
        return ResponseEntity.ok(accessCodeService.redeem(request.getAccessCode()));
    }

    @PostMapping("/authorize-and-issue")
    public ResponseEntity<?> authorizeAndIssue(@RequestBody SamlAuthRequest request)
            throws SamlAuthenticationException {
        try {
            return ResponseEntity.ok(samlAuthService.authorizeAndIssue(request));
        } catch (AccessAuthorizationPendingException ex) {
            return pendingResponse(ex);
        } catch (AccessAuthorizationRejectedException ex) {
            return rejectedResponse(ex);
        }
    }

    @PostMapping("/access-credential")
    public ResponseEntity<?> accessCredential(@RequestBody ProviderAccessCredentialRequest request) {
        try {
            return ResponseEntity.ok(samlAuthService.issueAccessCredential(request));
        } catch (AccessAuthorizationPendingException ex) {
            return pendingResponse(ex);
        } catch (AccessAuthorizationRejectedException ex) {
            return rejectedResponse(ex);
        }
    }

    private ResponseEntity<Map<String, Object>> pendingResponse(AccessAuthorizationPendingException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "ACCESS_AUTHORIZATION_PENDING");
        body.put("details", ex.getMessage());
        body.put("retryable", true);
        if (ex.getReservationKey() != null) {
            body.put("reservationKey", ex.getReservationKey());
        }
        if (ex.getTransactionHash() != null) {
            body.put("txHash", ex.getTransactionHash());
        }
        return ResponseEntity.status(503).header("Retry-After", "1").body(body);
    }

    private ResponseEntity<Map<String, Object>> rejectedResponse(AccessAuthorizationRejectedException ex) {
        return ResponseEntity.status(409)
            .body(Map.of("error", "ACCESS_AUTHORIZATION_REJECTED", "details", ex.getMessage(), "retryable", false));
    }

    @PostMapping("/checkin-institutional")
    public ResponseEntity<CheckInResponse> institutionalCheckIn(@RequestBody InstitutionalCheckInRequest request) {
        try {
            CheckInResponse response = institutionalCheckInService.checkIn(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason(e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (SecurityException e) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason(e.getMessage());
            return ResponseEntity.status(401).body(response);
        } catch (Exception e) {
            log.error("Institutional check-in error", e);
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason("Internal server error");
            return ResponseEntity.status(500).body(response);
        }
    }
}
