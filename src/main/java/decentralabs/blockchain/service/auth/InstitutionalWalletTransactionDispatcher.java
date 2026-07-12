package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.web3j.protocol.core.DefaultBlockParameterName;

/**
 * Durable, cross-replica critical section for institutional-wallet nonce
 * allocation, signing, broadcast and transaction-hash persistence.
 */
@Service
@RequiredArgsConstructor
public class InstitutionalWalletTransactionDispatcher {
    private final InstitutionalCheckInOutboxService nonceStore;
    private final WalletService walletService;

    @Transactional(noRollbackFor = InstitutionalWalletDispatchException.class)
    public String dispatch(
        String walletAddress,
        BigInteger existingNonce,
        Consumer<BigInteger> persistNonce,
        Function<BigInteger, String> broadcast,
        Consumer<String> persistTransactionHash
    ) throws InstitutionalWalletDispatchException {
        if (walletAddress == null || walletAddress.isBlank()) {
            throw new IllegalArgumentException("Institutional wallet address is required");
        }
        BigInteger nonce = existingNonce;
        if (nonce == null) {
            nonce = nonceStore.reserveNextNonce(walletAddress, pendingNonce(walletAddress));
            persistNonce.accept(nonce);
        }

        try {
            String txHash = broadcast.apply(nonce);
            if (txHash == null || txHash.isBlank()) {
                throw new IllegalStateException("Transaction broadcast returned no hash");
            }
            persistTransactionHash.accept(txHash);
            return txHash;
        } catch (RuntimeException ex) {
            throw new InstitutionalWalletDispatchException("Institutional transaction broadcast outcome is uncertain", ex);
        }
    }

    private BigInteger pendingNonce(String walletAddress) {
        try {
            var response = walletService.getWeb3jInstance().ethGetTransactionCount(
                walletAddress,
                DefaultBlockParameterName.PENDING
            ).send();
            if (response == null || response.getTransactionCount() == null) {
                throw new IllegalStateException("Node returned no pending nonce");
            }
            return response.getTransactionCount();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to read institutional wallet pending nonce", ex);
        }
    }
}
