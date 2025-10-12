package decentralabs.auth.controller;

import decentralabs.auth.dto.AuthResponse;
import decentralabs.auth.dto.SamlAuthRequest;
import decentralabs.auth.service.SamlAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for SAML-based authentication endpoints
 */
@RestController
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
            System.err.println("SAML authentication error: " + e.getMessage());
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
            System.err.println("SAML authentication error: " + e.getMessage());
            return ResponseEntity.status(500).body(AuthResponse.errorJson("Internal server error"));
        }
    }
}
