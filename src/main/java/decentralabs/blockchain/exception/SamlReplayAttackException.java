package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to replay attack detection
 */
public class SamlReplayAttackException extends SamlAuthenticationException {

    private static final long serialVersionUID = 1L;

    public SamlReplayAttackException(String message) {
        super(message);
    }

    public SamlReplayAttackException(String message, Throwable cause) {
        super(message, cause);
    }
}
