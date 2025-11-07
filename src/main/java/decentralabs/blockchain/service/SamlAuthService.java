package decentralabs.blockchain.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import decentralabs.blockchain.dto.AuthResponse;
import decentralabs.blockchain.dto.SamlAuthRequest;

import java.security.PublicKey;
import java.util.Map;

/**
 * Service for SAML-based authentication
 */
@Service
public class SamlAuthService {
    
    @Autowired
    private BlockchainBookingService blockchainService;
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private MarketplaceKeyService marketplaceKeyService;
    
    @Autowired
    private SamlValidationService samlValidationService;
    
    /**
     * Handles SAML authentication request with 3-layer validation
     * 
     * @param request SAML authentication request
     * @param includeBookingInfo Whether to include booking information in the token
     * @return Authentication response with JWT token
     * @throws Exception if validation or token generation fails
     */
    public AuthResponse handleAuthentication(SamlAuthRequest request, boolean includeBookingInfo) throws Exception {
        String marketplaceToken = request.getMarketplaceToken();
        String samlAssertion = request.getSamlAssertion();
        String labId = request.getLabId();
        String reservationKey = request.getReservationKey();
        
        // Validate required fields
        if (marketplaceToken == null || marketplaceToken.isEmpty()) {
            throw new IllegalArgumentException("Missing marketplaceToken");
        }
        if (samlAssertion == null || samlAssertion.isEmpty()) {
            throw new IllegalArgumentException("Missing samlAssertion");
        }
        
        // LAYER 1: Basic JWT validation (signature + expiration)
        Map<String, Object> marketplaceJWTClaims = validateMarketplaceJWTBasic(marketplaceToken);
        
        // LAYER 2: SAML assertion validation (XML structure + attributes)
        Map<String, String> samlAttributes = validateSAMLAssertion(samlAssertion);
        
        // LAYER 3: Cross-validation between JWT and SAML
        String jwtUserId = (String) marketplaceJWTClaims.get("userid");
        String jwtAffiliation = (String) marketplaceJWTClaims.get("affiliation");
        String samlUserId = samlAttributes.get("userid");
        String samlAffiliation = samlAttributes.get("affiliation");
        
        if (jwtUserId == null || !jwtUserId.equals(samlUserId)) {
            throw new SecurityException("JWT and SAML userid mismatch");
        }
        if (jwtAffiliation == null || !jwtAffiliation.equals(samlAffiliation)) {
            throw new SecurityException("JWT and SAML affiliation mismatch");
        }
        
        // Audit log
        auditSAMLAuthentication(jwtUserId, jwtAffiliation, labId, reservationKey);
        
        // Generate JWT token
        if (includeBookingInfo) {
            // Get booking information from blockchain (SAML users)
            String institutionalProviderWallet = (String) marketplaceJWTClaims.get("institutionalProviderWallet");
            String puc = (String) marketplaceJWTClaims.get("puc");
            Map<String, Object> bookingInfo = blockchainService.getBookingInfo(
                institutionalProviderWallet,
                reservationKey,
                labId,
                puc
            );
            String token = jwtService.generateToken(null, bookingInfo);
            String labURL = (String) bookingInfo.get("labURL");
            return new AuthResponse(token, labURL);
        } else {
            // Generate simple token with SAML claims
            Map<String, Object> claims = Map.of(
                "userid", jwtUserId,
                "affiliation", jwtAffiliation
            );
            String token = jwtService.generateToken(claims, null);
            return new AuthResponse(token);
        }
    }
    
    /**
     * LAYER 1: Validates the marketplace JWT token (signature + expiration)
     * 
     * @param marketplaceToken JWT token from marketplace
     * @return Parsed JWT claims
     * @throws Exception if validation fails
     */
    private Map<String, Object> validateMarketplaceJWTBasic(String marketplaceToken) throws Exception {
        PublicKey marketplacePublicKey = marketplaceKeyService.getPublicKey(false);
        
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(marketplacePublicKey)
                    .build()
                    .parseSignedClaims(marketplaceToken);
            
            return jws.getPayload();
        } catch (Exception e) {
            System.err.println("Marketplace JWT validation failed: " + e.getMessage());
            throw new SecurityException("Invalid marketplace token: " + e.getMessage(), e);
        }
    }
    
    /**
     * LAYER 2: Validates the SAML assertion XML structure and extracts attributes
     * 
     * @param samlAssertion Base64-encoded SAML assertion XML
     * @return Map of SAML attributes (userid, affiliation, etc.)
     * @throws Exception if validation fails
     */
    private Map<String, String> validateSAMLAssertion(String samlAssertion) throws Exception {
        Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
        System.out.println("✅ SAML assertion validated WITH SIGNATURE for user: " + attributes.get("userid"));
        return attributes;
    }
    
    /**
     * Audit log for SAML authentication attempts
     */
    private void auditSAMLAuthentication(String userid, String affiliation, String labId, String reservationKey) {
        System.out.println("SAML Authentication: userid=" + userid + 
                          ", affiliation=" + affiliation + 
                          ", labId=" + labId + 
                          ", reservationKey=" + reservationKey);
    }
}
