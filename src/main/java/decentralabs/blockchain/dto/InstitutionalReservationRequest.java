package decentralabs.blockchain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.time.LocalDateTime;

/**
 * Request DTO for institutional laboratory reservations.
 * Uses the same 3-layer validation as SamlAuthService:
 * - Layer 1: Marketplace JWT validation
 * - Layer 2: SAML assertion from IdP
 * - Layer 3: Cross-validation (JWT vs SAML)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InstitutionalReservationRequest {
    
    /**
     * JWT token from marketplace (for Layer 1 validation)
     */
    private String marketplaceToken;
    
    /**
     * SAML assertion from IdP (Base64-encoded XML) (for Layer 2 validation)
     */
    private String samlAssertion;
    
    /**
     * SAML user identifier from institutional authentication
     * This is validated against SAML assertion in Layer 3
     */
    private String userId;
    
    /**
     * Institution identifier (from SAML attributes or institutional registry)
     * This is validated against SAML assertion in Layer 3
     */
    private String institutionId;
    
    /**
     * Laboratory token ID to reserve
     */
    private BigInteger labId;
    
    /**
     * Reservation start time
     */
    private LocalDateTime startTime;
    
    /**
     * Reservation end time
     */
    private LocalDateTime endTime;
    
    /**
     * Number of concurrent users for this reservation
     */
    private int userCount;
    
    /**
     * Optional: Budget code or project identifier for institutional accounting
     */
    private String budgetCode;
    
    /**
     * Optional: Additional metadata for the reservation
     */
    private String metadata;
    
    /**
     * Timestamp to prevent replay attacks
     */
    private long timestamp;
}
