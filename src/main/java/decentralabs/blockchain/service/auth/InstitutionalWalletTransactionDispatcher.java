package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.io.IOException;
import java.util.function.Consumer;
import java.util.function.BiConsumer;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.EthSendTransaction;

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

    /** Signed transaction material that is safe to persist before RPC. */
    public record PreparedTransaction(String rawTransaction, String transactionHash) {
        public PreparedTransaction {
            if (rawTransaction == null || rawTransaction.isBlank()) {
                throw new IllegalArgumentException("Signed raw transaction is required");
            }
            if (transactionHash == null || !transactionHash.matches("^0x[0-9a-fA-F]{64}$")) {
                throw new IllegalArgumentException("Signed transaction hash is invalid");
            }
        }
    }

    /**
     * Durable dispatch contract for institutional transactions. The producer
     * signs locally, the caller persists raw+hash, and only then does this
     * method invoke eth_sendRawTransaction. A database failure before the RPC
     * therefore cannot hide a broadcast hash, while a failure after the RPC
     * leaves enough material for reconciliation and rebroadcast.
     */
    public String dispatchPrepared(
        String walletAddress,
        BigInteger existingChainId,
        BigInteger existingNonce,
        BiConsumer<BigInteger, BigInteger> persistNonce,
        Function<BigInteger, PreparedTransaction> prepare,
        Consumer<PreparedTransaction> persistPrepared,
        Consumer<String> persistTransactionHash
    ) throws InstitutionalWalletDispatchException {
        BigInteger[] allocation = resolveNonce(walletAddress, existingChainId, existingNonce, persistNonce);
        BigInteger nonce = allocation[1];

        // Preparation and its durable write happen before any network side
        // effect. Preparation errors are ordinary retryable failures.
        PreparedTransaction prepared = prepare.apply(nonce);
        if (prepared == null) {
            throw new IllegalStateException("Transaction preparation returned no transaction");
        }
        persistPrepared.accept(prepared);

        try {
            EthSendTransaction response = web3j().ethSendRawTransaction(prepared.rawTransaction()).send();
            if (response == null) {
                throw new IOException("RPC returned no transaction response");
            }
            if (response.hasError()) {
                String error = response.getError() != null ? response.getError().getMessage() : "broadcast_failed";
                if (!isAlreadyKnown(error)) {
                    throw new IllegalStateException("Transaction broadcast failed: " + error);
                }
                // The locally computed hash is authoritative even when the
                // node answers `already known` without returning one.
            }
            String returnedHash = response.getTransactionHash();
            if (returnedHash != null && !returnedHash.isBlank()
                && !returnedHash.equalsIgnoreCase(prepared.transactionHash())) {
                throw new IllegalStateException("Node returned a hash different from the signed transaction");
            }
            persistTransactionHash.accept(prepared.transactionHash());
            return prepared.transactionHash();
        } catch (Exception ex) {
            throw new InstitutionalWalletDispatchException(
                "Institutional transaction broadcast outcome is uncertain", ex
            );
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

    private BigInteger[] resolveNonce(
        String walletAddress,
        BigInteger existingChainId,
        BigInteger existingNonce,
        BiConsumer<BigInteger, BigInteger> persistNonce
    ) throws InstitutionalWalletDispatchException {
        if (walletAddress == null || walletAddress.isBlank()) {
            throw new IllegalArgumentException("Institutional wallet address is required");
        }
        Web3j web3j = web3j();
        BigInteger chainId = chainId(web3j);
        BigInteger nonce = existingNonce != null
            && (existingChainId == null || chainId.equals(existingChainId)) ? existingNonce : null;
        if (nonce == null) {
            try {
                nonce = nonceReservationService.reserveAndPersist(
                    walletAddress, chainId, pendingNonce(web3j, walletAddress), persistNonce
                );
            } catch (RuntimeException ex) {
                throw new InstitutionalWalletDispatchException(
                    "Institutional nonce allocation is currently blocked", ex
                );
            }
        }
        return new BigInteger[] {chainId, nonce};
    }

    private Web3j web3j() {
        return walletService.getWeb3jInstance();
    }

    private boolean isAlreadyKnown(String error) {
        String normalized = error == null ? "" : error.toLowerCase();
        return normalized.contains("already known") || normalized.contains("known transaction");
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
