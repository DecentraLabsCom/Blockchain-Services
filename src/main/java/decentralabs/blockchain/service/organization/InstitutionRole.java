package decentralabs.blockchain.service.organization;

/**
 * Defines the role of an institution in the DecentraLabs ecosystem
 */
public enum InstitutionRole {
    /**
     * Provider institutions can publish labs and provide authentication services
     * Registered via /api/institutions/registerProvider endpoint
     */
    PROVIDER("/api/institutions/registerProvider", "provider.registered"),
    
    /**
     * Consumer institutions can only reserve labs, not publish them
     * Registered via /api/institutions/registerConsumer endpoint
     */
    CONSUMER("/api/institutions/registerConsumer", "consumer.registered");
    
    private final String registrationEndpoint;
    private final String registeredFlag;
    
    InstitutionRole(String registrationEndpoint, String registeredFlag) {
        this.registrationEndpoint = registrationEndpoint;
        this.registeredFlag = registeredFlag;
    }
    
    /**
     * Get the marketplace endpoint for this role's registration
     */
    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }
    
    /**
     * Get the configuration property name that tracks registration status
     */
    public String getRegisteredFlag() {
        return registeredFlag;
    }
}
