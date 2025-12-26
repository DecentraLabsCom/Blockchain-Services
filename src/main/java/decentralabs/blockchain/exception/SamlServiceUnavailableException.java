package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to service unavailability
 */
public class SamlServiceUnavailableException extends SamlAuthenticationException {
    public SamlServiceUnavailableException(String message) {
        super(message);
    }

    public SamlServiceUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}