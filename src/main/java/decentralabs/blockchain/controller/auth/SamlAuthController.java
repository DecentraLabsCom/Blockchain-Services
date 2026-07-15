package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.AccessCodeRedeemRequest;
import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInStatusRequest;
import decentralabs.blockchain.dto.auth.ProviderAccessCredentialRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.AccessAuthorizationPendingException;
import decentralabs.blockchain.exception.AccessAuthorizationRejectedException;
import decentralabs.blockchain.exception.AccessAuthorizationContextMismatchException;
import decentralabs.blockchain.exception.AccessAuthorizationManualInterventionException;
import decentralabs.blockchain.exception.AccessAuthorizationSignerNotAuthorizedException;
import decentralabs.blockchain.exception.AccessAuthorizationDelegationException;
import decentralabs.blockchain.exception.SamlAuthenticationException;
import decentralabs.blockchain.service.auth.RemoteInstitutionalCheckInClient;
import decentralabs.blockchain.service.auth.RemoteInstitutionalCheckInException;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.SamlAuthService;
import decentralabs.blockchain.service.auth.AccessCodeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.LinkedHashMap;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
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
    @Value("${auth.access-code.redeemer-credentials-json:{}}")
    private String accessCodeRedeemerCredentialsJson;

    @PostMapping("/access-code/redeem")
    public ResponseEntity<AuthResponse> redeemAccessCode(
        @RequestHeader(value = "X-Access-Code-Redeemer-Token", required = false) String redeemerToken,
        @RequestHeader(value = "X-Gateway-ID", required = false) String gatewayId,
        @RequestBody AccessCodeRedeemRequest request
    ) {
        String expected = redeemerCredential(gatewayId);
        if (!constantTimeEquals(expected, redeemerToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(accessCodeService.redeem(request.getAccessCode(), gatewayId.trim().toLowerCase()));
    }

    private String redeemerCredential(String gatewayId) {
        if (gatewayId == null || gatewayId.isBlank()) {
            return null;
        }
        try {
            Map<String, String> credentials = new ObjectMapper().readValue(
                accessCodeRedeemerCredentialsJson == null ? "{}" : accessCodeRedeemerCredentialsJson,
                new TypeReference<>() { }
            );
            return credentials.get(gatewayId.trim().toLowerCase());
        } catch (Exception ex) {
            log.error("Invalid access-code redeemer credential configuration", ex);
            return null;
        }
    }

    private boolean constantTimeEquals(String expected, String actual) {
        if (expected == null || expected.isBlank() || "CHANGE_ME".equalsIgnoreCase(expected) || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            actual.getBytes(StandardCharsets.UTF_8)
        );
    }

    @PostMapping("/authorize-and-issue")
    public ResponseEntity<?> authorizeAndIssue(@RequestBody SamlAuthRequest request)
            throws SamlAuthenticationException {
        try {
            return ResponseEntity.ok(samlAuthService.authorizeAndIssue(request));
        } catch (AccessAuthorizationContextMismatchException ex) {
            return contextMismatchResponse(ex);
        } catch (AccessAuthorizationManualInterventionException ex) {
            return manualInterventionResponse(ex);
        } catch (AccessAuthorizationSignerNotAuthorizedException ex) {
            return signerNotAuthorizedResponse(ex);
        } catch (AccessAuthorizationDelegationException ex) {
            return delegationResponse(ex);
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
        } catch (AccessAuthorizationContextMismatchException ex) {
            return contextMismatchResponse(ex);
        } catch (AccessAuthorizationManualInterventionException ex) {
            return manualInterventionResponse(ex);
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

    private ResponseEntity<Map<String, Object>> contextMismatchResponse(
        AccessAuthorizationContextMismatchException ex
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "CHECKIN_CONTEXT_MISMATCH");
        body.put("details", ex.getMessage());
        body.put("retryable", false);
        if (ex.getReservationKey() != null) {
            body.put("reservationKey", ex.getReservationKey());
        }
        if (ex.getTransactionHash() != null) {
            body.put("txHash", ex.getTransactionHash());
        }
        return ResponseEntity.status(409).body(body);
    }

    private ResponseEntity<Map<String, Object>> manualInterventionResponse(
        AccessAuthorizationManualInterventionException ex
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "CHECKIN_MANUAL_INTERVENTION");
        body.put("details", ex.getMessage());
        body.put("retryable", false);
        if (ex.getReservationKey() != null) {
            body.put("reservationKey", ex.getReservationKey());
        }
        if (ex.getTransactionHash() != null) {
            body.put("txHash", ex.getTransactionHash());
        }
        return ResponseEntity.status(409).body(body);
    }

    private ResponseEntity<Map<String, Object>> signerNotAuthorizedResponse(
        AccessAuthorizationSignerNotAuthorizedException ex
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "CHECKIN_SIGNER_NOT_AUTHORIZED");
        body.put("details", ex.getMessage());
        body.put("retryable", false);
        if (ex.getReservationKey() != null) body.put("reservationKey", ex.getReservationKey());
        if (ex.getTransactionHash() != null) body.put("txHash", ex.getTransactionHash());
        return ResponseEntity.status(409).body(body);
    }

    private ResponseEntity<Map<String, Object>> delegationResponse(
        AccessAuthorizationDelegationException ex
    ) {
        RemoteInstitutionalCheckInClient.RemoteCheckInResult result = ex.result();
        CheckInResponse remote = result == null ? null : result.body();
        boolean retryable = result != null && result.isRetryable();
        int status = result == null ? 502 : result.status();
        if (status < 400 || status > 599) status = retryable ? 503 : 409;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", remote != null && remote.getReason() != null
            ? remote.getReason() : "CHECKIN_DELEGATION_FAILED");
        body.put("details", ex.getMessage());
        body.put("retryable", retryable);
        if (remote != null && remote.getQueued() != null) body.put("queued", remote.getQueued());
        if (remote != null && remote.getReservationKey() != null) body.put("reservationKey", remote.getReservationKey());
        if (remote != null && remote.getTxHash() != null) body.put("txHash", remote.getTxHash());
        ResponseEntity.BodyBuilder response = ResponseEntity.status(status);
        if (result != null && result.retryAfter() != null && !result.retryAfter().isBlank()) {
            response.header("Retry-After", result.retryAfter());
        }
        return response.body(body);
    }

    @PostMapping("/checkin-institutional")
    public ResponseEntity<CheckInResponse> institutionalCheckIn(@RequestBody InstitutionalCheckInRequest request) {
        try {
            CheckInResponse response = institutionalCheckInService.checkIn(request);
            if (response != null && (
                "CHECKIN_CONTEXT_MISMATCH".equals(response.getReason())
                    || "CHECKIN_MANUAL_INTERVENTION".equals(response.getReason())
            )) {
                return ResponseEntity.status(409).body(response);
            }
            if (response != null && Boolean.TRUE.equals(response.getQueued())) {
                return ResponseEntity.status(202)
                    .header("Retry-After", "2")
                    .body(response);
            }
            return ResponseEntity.ok(response);
        } catch (RemoteInstitutionalCheckInException e) {
            RemoteInstitutionalCheckInClient.RemoteCheckInResult result = e.result();
            CheckInResponse response = result == null ? new CheckInResponse() : result.body();
            if (response == null) {
                response = new CheckInResponse();
                response.setValid(false);
            }
            int status = result == null ? 502 : result.status();
            ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
            if (result != null && result.retryAfter() != null && !result.retryAfter().isBlank()) {
                builder.header("Retry-After", result.retryAfter());
            }
            return builder.body(response);
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

    @PostMapping("/checkin-institutional/status")
    public ResponseEntity<CheckInResponse> institutionalCheckInStatus(
        @RequestBody InstitutionalCheckInStatusRequest request
    ) {
        try {
            CheckInResponse response = institutionalCheckInService.checkInStatus(request);
            if (response != null && "CHECKIN_NOT_FOUND".equals(response.getReason())) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
            if (response != null && (
                "CHECKIN_CONTEXT_MISMATCH".equals(response.getReason())
                    || "CHECKIN_MANUAL_INTERVENTION".equals(response.getReason())
                    || "CHECKIN_FAILED".equals(response.getReason())
            )) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
            }
            if (response != null && Boolean.TRUE.equals(response.getQueued())) {
                return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .header("Retry-After", "2")
                    .body(response);
            }
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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        } catch (Exception e) {
            log.error("Institutional check-in status error", e);
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason("Internal server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
