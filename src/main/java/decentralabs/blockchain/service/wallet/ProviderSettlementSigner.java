package decentralabs.blockchain.service.wallet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;
import org.web3j.utils.Numeric;

/**
 * Resolves the independent EVM signers used for provider settlement approval
 * and payment. The private keys are supplied by the deployment secret store;
 * they are never accepted from the billing HTTP payload.
 */
@Service
public class ProviderSettlementSigner {

    private final String approverPrivateKey;
    private final String payerPrivateKey;

    private volatile Credentials approverCredentials;
    private volatile Credentials payerCredentials;

    public ProviderSettlementSigner(
        @Value("${provider.settlement.approver.private-key:}") String approverPrivateKey,
        @Value("${provider.settlement.payer.private-key:}") String payerPrivateKey
    ) {
        this.approverPrivateKey = approverPrivateKey;
        this.payerPrivateKey = payerPrivateKey;
    }

    public boolean isConfigured() {
        return approverPrivateKey != null && !approverPrivateKey.isBlank()
            && payerPrivateKey != null && !payerPrivateKey.isBlank();
    }

    public Credentials approverCredentials() {
        Credentials cached = approverCredentials;
        if (cached != null) return cached;
        synchronized (this) {
            if (approverCredentials == null) {
                approverCredentials = loadCredentials(approverPrivateKey, "approver");
            }
            return approverCredentials;
        }
    }

    public Credentials payerCredentials() {
        Credentials cached = payerCredentials;
        if (cached != null) return cached;
        synchronized (this) {
            if (payerCredentials == null) {
                payerCredentials = loadCredentials(payerPrivateKey, "payer");
            }
            return payerCredentials;
        }
    }

    public String approverAddress() {
        return approverCredentials().getAddress();
    }

    public String payerAddress() {
        return payerCredentials().getAddress();
    }

    public void requireDistinctSigners() {
        if (approverAddress().equalsIgnoreCase(payerAddress())) {
            throw new IllegalStateException("Provider settlement approver and payer signers must be distinct");
        }
    }

    private Credentials loadCredentials(String privateKey, String role) {
        if (privateKey == null || privateKey.isBlank()) {
            throw new IllegalStateException("Provider settlement " + role + " signer is not configured");
        }
        try {
            return Credentials.create(Numeric.cleanHexPrefix(privateKey.trim()));
        } catch (RuntimeException ex) {
            throw new IllegalStateException("Provider settlement " + role + " signer is invalid", ex);
        }
    }
}
