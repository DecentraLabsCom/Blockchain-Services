package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to service unavailability
 */
public class SamlServiceUnavailableException extends SamlAuthenticationException {

    private static final long serialVersionUID = 1L;

    public SamlServiceUnavailableException(String message) {
        super(message);
    }

    public SamlServiceUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
