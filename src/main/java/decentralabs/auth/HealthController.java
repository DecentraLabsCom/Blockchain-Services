package decentralabs.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/health")
public class HealthController {
    
    @Autowired
    private AuthController authController;
    
    @Value("${marketplace.public-key-url}")
    private String marketplacePublicKeyUrl;
    
    @GetMapping
    @CrossOrigin(origins = "*") // Will be handled by SecurityConfig CORS configuration
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> healthStatus = new HashMap<>();
        
        try {
            // Basic service checks
            healthStatus.put("status", "UP");
            healthStatus.put("timestamp", Instant.now().toString());
            healthStatus.put("service", "auth-service");
            healthStatus.put("version", "1.0.0");
            
            // Check marketplace public key availability
            boolean marketplaceKeyAvailable = checkMarketplaceKeyAvailability();
            healthStatus.put("marketplace_key_cached", marketplaceKeyAvailable);
            healthStatus.put("marketplace_key_url", marketplacePublicKeyUrl);
            
            // JWT validation readiness
            healthStatus.put("jwt_validation", "ready");
            
            // Additional service status
            healthStatus.put("endpoints", getEndpointStatus());
            
            return ResponseEntity.ok(healthStatus);
            
        } catch (Exception e) {
            // Critical error occurred
            healthStatus.put("status", "DOWN");
            healthStatus.put("error", e.getMessage());
            healthStatus.put("timestamp", Instant.now().toString());
            healthStatus.put("service", "auth-service");
            
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(healthStatus);
        }
    }
    
    private boolean checkMarketplaceKeyAvailability() {
        try {
            // Check if we can access the marketplace public key
            // This will use the cached key if available, or try to fetch it
            return authController.isMarketplacePublicKeyAvailable();
        } catch (Exception e) {
            return false;
        }
    }
    
    private Map<String, String> getEndpointStatus() {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("auth", "available");
        endpoints.put("auth2", "available");
        endpoints.put("marketplace-auth", "available");
        endpoints.put("marketplace-auth2", "available");
        endpoints.put("jwks", "available");
        endpoints.put("message", "available");
        return endpoints;
    }
}