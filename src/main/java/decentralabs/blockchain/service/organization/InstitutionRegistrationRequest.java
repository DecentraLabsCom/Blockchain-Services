package decentralabs.blockchain.service.organization;

import lombok.Builder;
import lombok.Value;

/**
 * Unified request for institution registration (provider or consumer)
 * Includes all possible fields - specific roles will only use relevant ones
 */
@Value
@Builder
public class InstitutionRegistrationRequest {
    
    /**
     * Role of the institution (PROVIDER or CONSUMER)
     */
    InstitutionRole role;
    
    /**
     * Marketplace base URL (required for both roles)
     */
    String marketplaceUrl;
    
    /**
     * Provisioning token for authentication (required for both roles)
     */
    String provisioningToken;
    
    /**
     * schacHomeOrganization identifier (required for both roles)
     */
    String organization;
    
    // Provider-specific fields (nullable for CONSUMER)
    
    /**
     * Institution name (PROVIDER only)
     */
    String name;
    
    /**
     * Contact email (PROVIDER only)
     */
    String email;
    
    /**
     * Country code (PROVIDER only)
     */
    String country;
    
    /**
     * Public base URL / auth URI (PROVIDER only, optional for CONSUMER)
     */
    String publicBaseUrl;
}
