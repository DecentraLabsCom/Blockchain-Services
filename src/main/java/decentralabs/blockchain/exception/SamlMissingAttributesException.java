package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to missing required attributes
 */
public class SamlMissingAttributesException extends SamlAuthenticationException {
    public SamlMissingAttributesException(String message) {
        super(message);
    }

    public SamlMissingAttributesException(String message, Throwable cause) {
        super(message, cause);
    }
}