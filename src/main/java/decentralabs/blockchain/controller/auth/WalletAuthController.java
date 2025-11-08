package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.WalletAuthRequest;
import decentralabs.blockchain.service.auth.WalletAuthService;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for wallet-based authentication endpoints
 */
@RestController
@RequestMapping("/auth")
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class WalletAuthController {
    
    @Autowired
    private WalletAuthService walletAuthService;
    
    /**
     * Endpoint to get a message to sign (timestamp-based)
     * 
     * @return Message containing current timestamp
     */
    @GetMapping("/message")
    public ResponseEntity<Map<String, String>> getMessage() {
        long timestamp = System.currentTimeMillis();
        String message = "Login request: " + timestamp;
        
        Map<String, String> response = new HashMap<>();
        response.put("message", message);
        response.put("timestamp", String.valueOf(timestamp));
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Endpoint for wallet authentication without booking information
     * 
     * @param request Wallet authentication request
     * @return JWT token as JSON string
     */
    @PostMapping("/wallet-auth")
    public ResponseEntity<String> walletAuth(@RequestBody WalletAuthRequest request) {
        try {
            AuthResponse response = walletAuthService.handleAuthentication(request, false);
            return ResponseEntity.ok(response.toJson());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (Exception e) {
            log.error("Wallet authentication error", e);
            return ResponseEntity.status(500).body(AuthResponse.errorJson("Internal server error"));
        }
    }
    
    /**
     * Endpoint for wallet authentication with booking information
     * 
     * @param request Wallet authentication request (must include labId or reservationKey)
     * @return JWT token with booking claims and lab URL as JSON string
     */
    @PostMapping("/wallet-auth2")
    public ResponseEntity<String> walletAuth2(@RequestBody WalletAuthRequest request) {
        try {
            AuthResponse response = walletAuthService.handleAuthentication(request, true);
            return ResponseEntity.ok(response.toJson());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(AuthResponse.errorJson(e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(AuthResponse.errorJson(e.getMessage()));
        } catch (Exception e) {
            log.error("Wallet authentication error", e);
            return ResponseEntity.status(500).body(AuthResponse.errorJson("Internal server error"));
        }
    }
}
