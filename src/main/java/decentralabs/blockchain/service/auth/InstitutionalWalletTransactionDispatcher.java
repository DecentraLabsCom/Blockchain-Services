package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.util.function.Consumer;
import java.util.function.BiConsumer;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.Web3j;

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
        BigInteger existingChainId,
        BigInteger existingNonce,
        BiConsumer<BigInteger, BigInteger> persistNonce,
        Function<BigInteger, String> broadcast,
        Consumer<String> persistTransactionHash
    ) throws InstitutionalWalletDispatchException {
        if (walletAddress == null || walletAddress.isBlank()) {
            throw new IllegalArgumentException("Institutional wallet address is required");
        }
        Web3j web3j = walletService.getWeb3jInstance();
        BigInteger chainId = chainId(web3j);
        BigInteger nonce = existingNonce != null
            && (existingChainId == null || chainId.equals(existingChainId)) ? existingNonce : null;
        if (nonce == null) {
            nonce = nonceReservationService.reserveAndPersist(
                walletAddress, chainId, pendingNonce(web3j, walletAddress), persistNonce
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

    private BigInteger chainId(Web3j web3j) {
        try {
            var response = web3j.ethChainId().send();
            if (response == null || response.getChainId() == null || response.getChainId().signum() <= 0) {
                throw new IllegalStateException("Node returned no chainId");
            }
            return response.getChainId();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to read institutional wallet chainId", ex);
        }
    }

    private BigInteger pendingNonce(Web3j web3j, String walletAddress) {
        try {
            var response = web3j.ethGetTransactionCount(
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
