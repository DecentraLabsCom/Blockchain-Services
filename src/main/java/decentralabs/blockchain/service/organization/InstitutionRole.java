package decentralabs.blockchain.service.organization;

/**
 * Defines the role of an institution in the DecentraLabs ecosystem
 */
public enum InstitutionRole {
    /**
     * Provider institutions can publish labs and provide authentication services
     * Registered via /api/institutions/registerProvider endpoint
     */
    PROVIDER("provider.registered"),
    
    /**
     * Consumer institutions can only reserve labs, not publish them
     * Registered via /api/institutions/registerConsumer endpoint
     */
    CONSUMER("consumer.registered");
    
    private final String registeredFlag;
    
    InstitutionRole(String registeredFlag) {
        this.registeredFlag = registeredFlag;
    }

    /**
     * Get the configuration property name that tracks registration status
     */
    public String getRegisteredFlag() {
        return registeredFlag;
    }
}
