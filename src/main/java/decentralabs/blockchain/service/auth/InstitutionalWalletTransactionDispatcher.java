package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.wallet.InstitutionalTransactionOutboxService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.io.IOException;
import java.util.Locale;
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
    public record PreparedTransaction(String rawTransaction, String transactionHash, BigInteger gasPrice) {
        public PreparedTransaction(String rawTransaction, String transactionHash) {
            this(rawTransaction, transactionHash, null);
        }

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
        BigInteger[] allocation;
        try {
            allocation = resolveNonce(walletAddress, existingChainId, existingNonce, persistNonce);
        } catch (InstitutionalWalletDispatchException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new InstitutionalWalletDispatchException(
                "Institutional transaction could not be prepared before broadcast",
                classifyPreBroadcastFailure(ex),
                ex
            );
        }
        BigInteger nonce = allocation[1];

        // Preparation and its durable write happen before any network side
        // effect. A malformed/invalid transaction is permanent; RPC or
        // persistence failures remain transient.
        PreparedTransaction prepared;
        try {
            prepared = prepare.apply(nonce);
            if (prepared == null) {
                throw new IllegalStateException("Transaction preparation returned no transaction");
            }
        } catch (RuntimeException ex) {
            throw new InstitutionalWalletDispatchException(
                "Institutional transaction could not be prepared before broadcast",
                classifyPreBroadcastFailure(ex),
                ex
            );
        }
        try {
            persistPrepared.accept(prepared);
        } catch (RuntimeException ex) {
            throw new InstitutionalWalletDispatchException(
                "Institutional signed transaction could not be persisted before broadcast",
                InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT,
                ex
            );
        }

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
                "Institutional transaction broadcast outcome is uncertain",
                InstitutionalWalletDispatchException.Outcome.BROADCAST_OUTCOME_UNKNOWN,
                ex
            );
        }
    }

    /**
     * Resumes a transaction whose signed material was already persisted before
     * a process crash. The previous hash is checked first; a new raw
     * transaction must never replace that material before the node has
     * classified the old attempt.
     */
    public String rebroadcastPrepared(PreparedTransaction prepared)
        throws InstitutionalWalletDispatchException {
        if (prepared == null) {
            throw new InstitutionalWalletDispatchException(
                "Persisted institutional transaction is missing",
                InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT,
                new IllegalArgumentException("Prepared transaction is required")
            );
        }

        Web3j node = web3j();
        try {
            var receiptResponse = node.ethGetTransactionReceipt(prepared.transactionHash()).send();
            if (receiptResponse == null) {
                throw new IOException("RPC returned no transaction receipt response");
            }
            if (receiptResponse.getTransactionReceipt().isPresent()) {
                return prepared.transactionHash();
            }

            var transactionResponse = node.ethGetTransactionByHash(prepared.transactionHash()).send();
            if (transactionResponse == null) {
                throw new IOException("RPC returned no transaction lookup response");
            }
            if (transactionResponse.getTransaction().isPresent()) {
                return prepared.transactionHash();
            }
        } catch (Exception ex) {
            throw new InstitutionalWalletDispatchException(
                "Persisted institutional transaction outcome is uncertain",
                InstitutionalWalletDispatchException.Outcome.BROADCAST_OUTCOME_UNKNOWN,
                ex
            );
        }

        try {
            EthSendTransaction response = node.ethSendRawTransaction(prepared.rawTransaction()).send();
            if (response == null) {
                throw new IOException("RPC returned no transaction response");
            }
            if (response.hasError()) {
                String error = response.getError() != null ? response.getError().getMessage() : "broadcast_failed";
                if (!isAlreadyKnown(error)) {
                    throw new IllegalStateException("Transaction rebroadcast failed: " + error);
                }
            }
            String returnedHash = response.getTransactionHash();
            if (returnedHash != null && !returnedHash.isBlank()
                && !returnedHash.equalsIgnoreCase(prepared.transactionHash())) {
                throw new IllegalStateException("Node returned a hash different from the persisted transaction");
            }
            return prepared.transactionHash();
        } catch (Exception ex) {
            throw new InstitutionalWalletDispatchException(
                "Persisted institutional transaction rebroadcast outcome is uncertain",
                InstitutionalWalletDispatchException.Outcome.BROADCAST_OUTCOME_UNKNOWN,
                ex
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
                    "Institutional nonce allocation is currently blocked",
                    classifyNonceFailure(ex),
                    ex
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

    private InstitutionalWalletDispatchException.Outcome classifyNonceFailure(RuntimeException ex) {
        return isNonceContention(ex)
            ? InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED
            : InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT;
    }

    private InstitutionalWalletDispatchException.Outcome classifyPreBroadcastFailure(RuntimeException ex) {
        if (isNonceContention(ex)) {
            return InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_BLOCKED;
        }
        return isTransientFailure(ex)
            ? InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_TRANSIENT
            : InstitutionalWalletDispatchException.Outcome.PRE_BROADCAST_PERMANENT;
    }

    private boolean isNonceContention(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof InstitutionalWalletNonceReservationService.TransactionBlockedException
                || current instanceof InstitutionalTransactionOutboxService.TransactionBlockedException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null) {
                String normalized = message.toLowerCase(Locale.ROOT);
                if (normalized.contains("wallet") && (normalized.contains("blocked")
                    || normalized.contains("unresolved") || normalized.contains("contention"))) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

    private boolean isTransientFailure(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof IOException || current instanceof java.net.ConnectException
                || current instanceof java.net.SocketTimeoutException
                || current instanceof org.springframework.dao.DataAccessException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null) {
                String normalized = message.toLowerCase(Locale.ROOT);
                if (normalized.contains("rpc") || normalized.contains("timeout")
                    || normalized.contains("timed out") || normalized.contains("connection")
                    || normalized.contains("network") || normalized.contains("database")) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
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
