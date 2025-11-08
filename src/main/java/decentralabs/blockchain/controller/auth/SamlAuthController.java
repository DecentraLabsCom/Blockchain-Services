package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.service.auth.SamlAuthService;
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
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (Exception e) {
            log.error("SAML authentication error", e);
            return ResponseEntity.status(500).body(AuthResponse.errorJson("Internal server error"));
        }
    }
}
