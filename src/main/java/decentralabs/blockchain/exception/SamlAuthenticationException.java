package decentralabs.blockchain.exception;

/**
 * Base exception for SAML authentication errors
 */
public abstract class SamlAuthenticationException extends Exception {

    private static final long serialVersionUID = 1L;

    public SamlAuthenticationException(String message) {
        super(message);
    }

    public SamlAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
