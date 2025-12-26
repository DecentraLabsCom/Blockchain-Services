package decentralabs.blockchain.exception;

/**
 * Base exception for SAML authentication errors
 */
public abstract class SamlAuthenticationException extends Exception {
    public SamlAuthenticationException(String message) {
        super(message);
    }

    public SamlAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}