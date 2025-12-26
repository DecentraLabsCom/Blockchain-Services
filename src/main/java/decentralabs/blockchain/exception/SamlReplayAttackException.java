package decentralabs.blockchain.exception;

/**
 * Exception thrown when SAML authentication fails due to replay attack detection
 */
public class SamlReplayAttackException extends SamlAuthenticationException {
    public SamlReplayAttackException(String message) {
        super(message);
    }

    public SamlReplayAttackException(String message, Throwable cause) {
        super(message, cause);
    }
}