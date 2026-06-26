package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to malformed response
 */
public class SamlMalformedResponseException extends SamlAuthenticationException {

    private static final long serialVersionUID = 1L;

    public SamlMalformedResponseException(String message) {
        super(message);
    }

    public SamlMalformedResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
