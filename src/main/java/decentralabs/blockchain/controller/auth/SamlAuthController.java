package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.SamlAuthenticationException;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import decentralabs.blockchain.service.auth.SamlAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
@RequiredArgsConstructor
public class SamlAuthController {

    private final SamlAuthService samlAuthService;
    private final InstitutionalCheckInService institutionalCheckInService;

    @PostMapping("/saml-auth")
    public ResponseEntity<AuthResponse> samlAuth(@RequestBody SamlAuthRequest request)
            throws SamlAuthenticationException {
        AuthResponse response = samlAuthService.handleAuthentication(request, false);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/saml-auth2")
    public ResponseEntity<AuthResponse> samlAuth2(@RequestBody SamlAuthRequest request)
            throws SamlAuthenticationException {
        AuthResponse response = samlAuthService.handleAuthentication(request, true);
        return ResponseEntity.ok(response);
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
