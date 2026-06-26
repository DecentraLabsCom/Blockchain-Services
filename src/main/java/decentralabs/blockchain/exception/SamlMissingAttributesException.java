package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to missing required attributes
 */
public class SamlMissingAttributesException extends SamlAuthenticationException {

    private static final long serialVersionUID = 1L;

    public SamlMissingAttributesException(String message) {
        super(message);
    }

    public SamlMissingAttributesException(String message, Throwable cause) {
        super(message, cause);
    }
}
