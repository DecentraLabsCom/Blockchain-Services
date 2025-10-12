package decentralabs.auth.controller;

import decentralabs.auth.service.JwtService;
import decentralabs.auth.service.KeyService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Main controller for OpenID Connect and JWKS endpoints
 * 
 * Authentication endpoints have been moved to:
 * - WalletAuthController (wallet-based authentication)
 * - SamlAuthController (SAML-based authentication)
 */
@RestController
@RequestMapping("")
public class AuthController {

    @Value("${base.domain}")
    private String baseDomain;
    
    @Value("${server.servlet.context-path}")
    private String contextPath;
    
    @Value("${endpoint.wallet-auth2}")
    private String walletAuth2Endpoint;
    
    @Value("${endpoint.jwks}")
    private String jwksEndpoint;

    @Autowired
    private KeyService keyService;
    
    @Autowired
    private JwtService jwtService;
    
    /**
     * Helper method to construct the issuer URL from base domain and context path
     */
    private String getIssuerUrl() {
        return baseDomain + contextPath;
    }

    /**
     * OpenID Connect Discovery endpoint
     * Exposes the authorization and JWKS endpoints for OpenID Connect
     * 
     * @return OpenID Connect configuration
     */
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, String>> openidConfig() {
        String issuerUrl = getIssuerUrl();
        Map<String, String> config = new HashMap<>();
        config.put("issuer", issuerUrl);
        config.put("authorization_endpoint", issuerUrl + walletAuth2Endpoint);
        config.put("jwks_uri", issuerUrl + jwksEndpoint);
        return ResponseEntity.ok(config);
    }

    /**
     * JWKS endpoint - Returns the public key in JSON Web Key Set format
     * Used by clients to verify JWT signatures
     * 
     * @return JWKS with RSA public key
     */
    @GetMapping("/jwks")
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
            System.err.println("JWKS generation error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500)
                .body(Collections.singletonMap("error", "Failed to process the public key"));
        }
    }
}
