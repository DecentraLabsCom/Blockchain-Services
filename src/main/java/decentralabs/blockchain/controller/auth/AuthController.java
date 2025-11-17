package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.service.GatewayUrlResolver;
import decentralabs.blockchain.service.auth.JwtService;
import decentralabs.blockchain.service.auth.KeyService;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Main controller for OpenID Connect and JWKS endpoints
 * 
 * Authentication endpoints have been moved to:
 * - WalletAuthController (wallet-based authentication)
 * - SamlAuthController (SAML-based authentication)
 */
@RestController
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class AuthController {

    @Value("${auth.base-path:/auth}")
    private String authPath;
    
    @Value("${endpoint.wallet-auth2}")
    private String walletAuth2Endpoint;
    
    @Value("${endpoint.saml-auth2}")
    private String samlAuth2Endpoint;
    
    @Value("${endpoint.jwks}")
    private String jwksEndpoint;

    @Autowired
    private KeyService keyService;
    
    @Autowired
    private GatewayUrlResolver gatewayUrlResolver;

    /**
     * OpenID Connect Discovery endpoint
     * Exposes the authorization and JWKS endpoints for OpenID Connect
     * 
     * @return OpenID Connect configuration
     */
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, Object>> openidConfig() {
        String baseDomain = gatewayUrlResolver.resolveBaseDomain();
        Map<String, Object> config = new HashMap<>();
        config.put("issuer", baseDomain + authPath);
        
        // Primary authorization endpoint (wallet-based by default)
        config.put("authorization_endpoint", baseDomain + walletAuth2Endpoint);

        config.put("jwks_uri", baseDomain + jwksEndpoint);
        return ResponseEntity.ok(config);
    }

    /**
     * JWKS endpoint - Returns the public key in JSON Web Key Set format
     * Used by clients to verify JWT signatures
     * 
     * @return JWKS with RSA public key
     */
    @GetMapping("${endpoint.jwks}")
    public ResponseEntity<Map<String, Object>> getJWKS() {
        try {
            RSAPublicKey publicKey = keyService.getPublicKey();

            // Obtain modulus (n) and exponent (e) in Base64URL format
            BigInteger modulus = publicKey.getModulus();
            String modulusBase64Url = JwtService.base64UrlEncode(modulus);
            String exponentBase64Url = JwtService.base64UrlEncode(publicKey.getPublicExponent());    
            
            String kid = JwtService.generateKid(modulus); 

            // Build JWKS response
            Map<String, Object> key = new HashMap<>();
            key.put("kty", "RSA");
            key.put("alg", "RS256");
            key.put("use", "sig");
            key.put("n", modulusBase64Url);
            key.put("e", exponentBase64Url);
            key.put("kid", kid);

            Map<String, Object> response = new HashMap<>();
            response.put("keys", Collections.singletonList(key));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("JWKS generation error: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                .body(Collections.singletonMap("error", "Failed to process the public key"));
        }
    }
}
