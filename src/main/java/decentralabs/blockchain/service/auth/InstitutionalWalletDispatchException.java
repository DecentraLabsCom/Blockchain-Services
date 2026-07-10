package decentralabs.blockchain.service.auth;

/**
 * Checked so Spring commits a reserved nonce when broadcast outcome is
 * uncertain; retry/reconciliation must then keep using that nonce.
 */
public class InstitutionalWalletDispatchException extends Exception {
    public InstitutionalWalletDispatchException(String message, Throwable cause) {
        super(message, cause);
    }
}
