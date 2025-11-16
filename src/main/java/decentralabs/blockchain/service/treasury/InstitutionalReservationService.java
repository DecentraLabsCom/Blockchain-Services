package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.dto.treasury.InstitutionalReservationRequest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.PublicKey;
import java.time.ZoneOffset;
import java.util.Map;

import decentralabs.blockchain.service.auth.MarketplaceKeyService;
import decentralabs.blockchain.service.auth.SamlValidationService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.util.LogSanitizer;
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
    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalAnalyticsService institutionalAnalyticsService;
    private final Web3j web3j;
    
    @Value("${contract.address}")
    private String contractAddress;
    
    @Value("${ethereum.gas.price.default}")
    private BigDecimal defaultGasPriceGwei;
    
    @Value("${ethereum.gas.limit.contract}")
    private BigInteger contractGasLimit;
    
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
        log.info("Processing institutional reservation request");
        
        // Step 1-3: 3-Layer Validation (same as SAML auth)
        validateUserAuthenticationThreeLayer(request);
        
        Credentials institutionalCredentials = institutionalWalletService.getInstitutionalCredentials();
        String transactionHash = executeBlockchainReservation(request, institutionalCredentials);

        institutionalAnalyticsService.recordUserActivity(institutionalCredentials.getAddress(), request.getUserId());
        institutionalAnalyticsService.recordTransaction(
            institutionalCredentials.getAddress(),
            new InstitutionalAnalyticsService.TransactionRecord(
                transactionHash,
                "RESERVATION",
                "Reservation for lab " + request.getLabId(),
                null,
                System.currentTimeMillis(),
                "submitted"
            )
        );

        log.info("Reservation processed successfully.");
        
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
            
            log.info("✅ 3-Layer validation passed.");
            
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
            log.error("Marketplace JWT validation failed: {}", LogSanitizer.sanitize(e.getMessage()));
            throw new SecurityException("Invalid marketplace token: " + e.getMessage(), e);
        }
    }
    
    private Map<String, String> validateSAMLAssertion(String samlAssertion) throws Exception {
        Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(samlAssertion);
        log.info("✅ Layer 2: SAML assertion validated WITH SIGNATURE.");
        return attributes;
    }
    
    /**
     * Executes the blockchain reservation transaction using the institutional wallet.
     */
    private String executeBlockchainReservation(
            InstitutionalReservationRequest request, 
            Credentials credentials) {
        
        try {
            Diamond contract = Diamond.load(
                contractAddress,
                web3j,
                credentials,
                new StaticGasProvider(resolveGasPriceWei(), contractGasLimit)
            );

            BigInteger startEpoch = BigInteger.valueOf(request.getStartTime().toEpochSecond(ZoneOffset.UTC));
            BigInteger endEpoch = BigInteger.valueOf(request.getEndTime().toEpochSecond(ZoneOffset.UTC));
            String puc = request.getUserId(); // Using SAML user identifier as PUC

            log.info("Executing blockchain transaction for reservation.");

            TransactionReceipt receipt = contract.institutionalReservationRequest(
                credentials.getAddress(),  // Use actual wallet address from credentials
                puc,
                request.getLabId(),
                startEpoch,
                endEpoch
            ).send();

            log.info("Blockchain transaction executed.");
            return receipt.getTransactionHash();
            
        } catch (Exception e) {
            log.error("Blockchain transaction failed", e);
            throw new IllegalStateException("Failed to execute blockchain transaction: " + e.getMessage(), e);
        }
    }
    
    private BigInteger resolveGasPriceWei() {
        BigDecimal gwei = (defaultGasPriceGwei == null || defaultGasPriceGwei.signum() <= 0)
            ? BigDecimal.ONE
            : defaultGasPriceGwei;
        return Convert.toWei(gwei, Convert.Unit.GWEI).toBigInteger();
    }
    
}
