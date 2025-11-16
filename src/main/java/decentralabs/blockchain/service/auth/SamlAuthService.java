package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.SamlAuthRequest;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import decentralabs.blockchain.util.LogSanitizer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service for SAML-based authentication
 */
@Service
@Slf4j
public class SamlAuthService {
    
    @Autowired
    private BlockchainBookingService blockchainService;
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private MarketplaceKeyService marketplaceKeyService;
    
    @Autowired
    private SamlValidationService samlValidationService;

    @Value("${auth.saml.require-booking-scope:true}")
    private boolean requireBookingScope;

    @Value("${auth.saml.required-booking-scope:booking:read}")
    private String requiredBookingScope;
    
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
            enforceBookingInfoEntitlement(marketplaceJWTClaims, jwtUserId);
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
            log.error("Marketplace JWT validation failed: {}", LogSanitizer.sanitize(e.getMessage()), e);
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
        log.info("SAML assertion validated WITH SIGNATURE for user: {}", LogSanitizer.maskIdentifier(attributes.get("userid")));
        return attributes;
    }
    
    /**
     * Audit log for SAML authentication attempts
     */
    private void auditSAMLAuthentication(String userid, String affiliation, String labId, String reservationKey) {
        log.info("SAML Authentication attempt recorded");
    }

    private void enforceBookingInfoEntitlement(Map<String, Object> marketplaceClaims, String userId) {
        if (!requireBookingScope) {
            return;
        }
        if (Boolean.TRUE.equals(marketplaceClaims.get("bookingInfoAllowed"))) {
            return;
        }
        Object scopeClaim = marketplaceClaims.getOrDefault("scope", marketplaceClaims.get("scopes"));
        if (scopeClaim != null && scopeContainsRequiredScope(scopeClaim)) {
            return;
        }
        log.warn("Booking info request denied - missing required scope");
        throw new SecurityException("Marketplace token missing required scope '" + requiredBookingScope + "' for booking info");
    }

    private boolean scopeContainsRequiredScope(Object scopeClaim) {
        if (scopeClaim instanceof String scopeText) {
            return Stream.of(scopeText.split("[\\s,]+"))
                .anyMatch(token -> token.equals(requiredBookingScope));
        }
        if (scopeClaim instanceof Collection<?> collection) {
            return collection.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .anyMatch(token -> token.equals(requiredBookingScope));
        }
        return false;
    }
}
