package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.InstitutionalCheckInRequest;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.exception.*;
import decentralabs.blockchain.service.auth.SamlAuthService;
import decentralabs.blockchain.service.auth.InstitutionalCheckInService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for SAML-based authentication endpoints
 */
@RestController
@RequestMapping("/auth")
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class SamlAuthController {
    
    @Autowired
    private SamlAuthService samlAuthService;

    @Autowired
    private InstitutionalCheckInService institutionalCheckInService;
    
    /**
     * Endpoint for SAML authentication without booking information
     * 
     * @param request SAML authentication request
     * @return JWT token as JSON string
     */
    @PostMapping("/saml-auth")
    public ResponseEntity<String> samlAuth(@RequestBody SamlAuthRequest request) {
        try {
            AuthResponse response = samlAuthService.handleAuthentication(request, false);
            return ResponseEntity.ok(response.toJson());
        } catch (SamlExpiredAssertionException | SamlInvalidIssuerException | SamlReplayAttackException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (SamlMalformedResponseException | SamlMissingAttributesException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SamlServiceUnavailableException e) {
            return ResponseEntity.status(503).body(AuthResponse.errorJson(e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (Exception e) {
            log.error("SAML authentication error", e);
            return ResponseEntity.status(500).body(AuthResponse.errorJson("Internal server error"));
        }
    }
    
    /**
     * Endpoint for SAML authentication with booking information
     * 
     * @param request SAML authentication request (must include labId or reservationKey)
     * @return JWT token with booking claims and lab URL as JSON string
     */
    @PostMapping("/saml-auth2")
    public ResponseEntity<String> samlAuth2(@RequestBody SamlAuthRequest request) {
        try {
            AuthResponse response = samlAuthService.handleAuthentication(request, true);
            return ResponseEntity.ok(response.toJson());
        } catch (SamlExpiredAssertionException | SamlInvalidIssuerException | SamlReplayAttackException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (SamlMalformedResponseException | SamlMissingAttributesException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SamlServiceUnavailableException e) {
            return ResponseEntity.status(503).body(AuthResponse.errorJson(e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (Exception e) {
            log.error("SAML authentication error", e);
            return ResponseEntity.status(500).body(AuthResponse.errorJson("Internal server error"));
        }
    }

    /**
     * Endpoint to submit an institutional check-in using SAML assertion.
     */
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
