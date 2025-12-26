package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to invalid issuer
 */
public class SamlInvalidIssuerException extends SamlAuthenticationException {
    public SamlInvalidIssuerException(String message) {
        super(message);
    }

    public SamlInvalidIssuerException(String message, Throwable cause) {
        super(message, cause);
    }
}