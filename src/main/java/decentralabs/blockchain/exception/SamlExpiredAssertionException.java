package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to expired assertion
 */
public class SamlExpiredAssertionException extends SamlAuthenticationException {
    public SamlExpiredAssertionException(String message) {
        super(message);
    }

    public SamlExpiredAssertionException(String message, Throwable cause) {
        super(message, cause);
    }
}