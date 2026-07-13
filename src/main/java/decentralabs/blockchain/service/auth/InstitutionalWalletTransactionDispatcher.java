package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.web3j.protocol.core.DefaultBlockParameterName;

/**
 * Dispatches institutional-wallet transactions after committing their nonce
 * ownership. Broadcast deliberately happens outside the reservation transaction
 * so a process crash cannot roll the nonce association back and permit reuse.
 */
@Service
@RequiredArgsConstructor
public class InstitutionalWalletTransactionDispatcher {
    private final InstitutionalWalletNonceReservationService nonceReservationService;
    private final WalletService walletService;

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
            nonce = nonceReservationService.reserveAndPersist(
                walletAddress, pendingNonce(walletAddress), persistNonce
            );
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
