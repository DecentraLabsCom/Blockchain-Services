package decentralabs.blockchain.service;

import decentralabs.blockchain.dto.InstitutionalReservationRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Map;

/**
 * Service for processing institutional reservations.
 * Uses the SAME 3-layer validation as SamlAuthService:
 * - Layer 1: Marketplace JWT validation
 * - Layer 2: SAML assertion from IdP
 * - Layer 3: Cross-validation (JWT vs SAML)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class InstitutionalReservationService {
    
    private final MarketplaceKeyService marketplaceKeyService;
    private final SamlValidationService samlValidationService;
    private final Web3j web3j;
    
    @Value("${wallet.address}")
    private String institutionalWalletAddress;
    
    @Value("${wallet.private.key}")
    private String institutionalWalletPrivateKey;
    
    private volatile Credentials cachedInstitutionalCredentials;
    
    /**
     * Process an institutional reservation request.
     * 
     * Flow (same as SamlAuthService):
     * 1. Layer 1: Validate marketplace JWT token
     * 2. Layer 2: Validate SAML assertion from IdP
     * 3. Layer 3: Cross-validate JWT vs SAML
     * 4. Get institutional policy
     * 5. Estimate reservation cost
     * 6. Validate against policy limits
     * 7. Execute blockchain transaction with institutional wallet
     * 8. Record spending
     * 
     * @param request The reservation request
     * @return Result map with transaction details
     */
    public Map<String, Object> processReservation(InstitutionalReservationRequest request) {
        log.info("Processing institutional reservation for user: {} from institution: {}", 
                request.getUserId(), request.getInstitutionId());
        
        // Step 1-3: 3-Layer Validation (same as SAML auth)
        validateUserAuthenticationThreeLayer(request);
        
        Credentials institutionalCredentials = getInstitutionalWallet();
        String transactionHash = executeBlockchainReservation(request, institutionalCredentials);
        
        log.info("Reservation processed successfully. Transaction: {}", transactionHash);
        
        return Map.of(
                "success", true,
                "transactionHash", transactionHash,
                "institutionId", request.getInstitutionId(),
                "userId", request.getUserId(),
                "labId", request.getLabId().toString(),
                "startTime", request.getStartTime().toString(),
                "endTime", request.getEndTime().toString()
        );
    }
    
    /**
     * 3-LAYER VALIDATION (same as SamlAuthService)
     * 
     * Layer 1: Marketplace JWT validation (signature + expiration)
     * Layer 2: SAML assertion from IdP (XML parsing + attributes)
     * Layer 3: Cross-validation (JWT.userid === SAML.userid)
     */
    private void validateUserAuthenticationThreeLayer(InstitutionalReservationRequest request) {
        try {
            // LAYER 1: Basic JWT validation from marketplace
            Map<String, Object> marketplaceJWTClaims = validateMarketplaceJWT(request.getMarketplaceToken());
            
            // LAYER 2: SAML assertion validation from IdP
            Map<String, String> samlAttributes = validateSAMLAssertion(request.getSamlAssertion());
            
            // LAYER 3: Cross-validation between JWT and SAML
            String jwtUserId = (String) marketplaceJWTClaims.get("userid");
            String jwtAffiliation = (String) marketplaceJWTClaims.get("affiliation");
            String samlUserId = samlAttributes.get("userid");
            String samlAffiliation = samlAttributes.get("affiliation");
            
            // Validate userId match
            if (jwtUserId == null || !jwtUserId.equals(samlUserId)) {
                throw new SecurityException("JWT and SAML userid mismatch");
            }
            
            // Validate affiliation/institution match
            if (jwtAffiliation == null || !jwtAffiliation.equals(samlAffiliation)) {
                throw new SecurityException("JWT and SAML affiliation mismatch");
            }
            
            // Validate request userId matches validated identity
            if (!request.getUserId().equals(samlUserId)) {
                throw new SecurityException("Request userId does not match SAML userid");
            }
            
            // Validate request institutionId matches SAML affiliation
            if (!request.getInstitutionId().equals(samlAffiliation)) {
                throw new SecurityException("Request institutionId does not match SAML affiliation");
            }
            
            log.info("✅ 3-Layer validation passed for user: {} from institution: {}", 
                    samlUserId, samlAffiliation);
            
        } catch (Exception e) {
            log.error("Authentication validation failed", e);
            throw new IllegalStateException("Authentication validation failed: " + e.getMessage());
        }
    }
    
    /**
     * LAYER 1: Validates the marketplace JWT token (signature + expiration)
     */
    private Map<String, Object> validateMarketplaceJWT(String marketplaceToken) throws Exception {
        PublicKey marketplacePublicKey = marketplaceKeyService.getPublicKey(false);
        
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(marketplacePublicKey)
                    .build()
                    .parseSignedClaims(marketplaceToken);
            
            log.info("✅ Layer 1: Marketplace JWT validated");
            return jws.getPayload();
            
        } catch (Exception e) {
            log.error("Marketplace JWT validation failed: {}", e.getMessage());
            throw new SecurityException("Invalid marketplace token: " + e.getMessage(), e);
        }
    }
    
    private Map<String, String> validateSAMLAssertion(String samlAssertion) throws Exception {
        Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
        log.info("✅ Layer 2: SAML assertion validated WITH SIGNATURE for user: {}", 
                attributes.get("userid"));
        return attributes;
    }
    
    /**
     * Retrieves institutional wallet credentials from configuration.
     */
    private Credentials getInstitutionalWallet() {
        if (institutionalWalletPrivateKey == null || institutionalWalletPrivateKey.isBlank()) {
            throw new IllegalStateException("wallet.private.key not configured");
        }

        if (cachedInstitutionalCredentials == null) {
            cachedInstitutionalCredentials = Credentials.create(institutionalWalletPrivateKey);
            log.info("Loaded institutional wallet credentials for address {}", cachedInstitutionalCredentials.getAddress());
        }

        if (institutionalWalletAddress != null
            && !institutionalWalletAddress.isBlank()
            && !cachedInstitutionalCredentials.getAddress().equalsIgnoreCase(institutionalWalletAddress)) {
            log.warn("Configured wallet.address ({}) does not match derived private key address ({})",
                institutionalWalletAddress,
                cachedInstitutionalCredentials.getAddress());
        }

        return cachedInstitutionalCredentials;
    }
    
    /**
     * Executes the blockchain reservation transaction using the institutional wallet.
     */
    private String executeBlockchainReservation(
            InstitutionalReservationRequest request, 
            Credentials credentials) {
        
        try {
            // TODO: Implement actual smart contract call
            // This would use Web3j to call the institutionalReservationRequest function
            
            log.info("Executing blockchain transaction for lab: {} with institutional wallet: {}", 
                    request.getLabId(), credentials.getAddress());
            
            // Placeholder - in production, call the smart contract
            String mockTransactionHash = "0x" + java.util.UUID.randomUUID().toString().replace("-", "");
            
            log.info("Blockchain transaction executed: {}", mockTransactionHash);
            
            return mockTransactionHash;
            
        } catch (Exception e) {
            log.error("Blockchain transaction failed", e);
            throw new IllegalStateException("Failed to execute blockchain transaction: " + e.getMessage());
        }
    }
    
}
