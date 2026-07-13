package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.PendingNonceFastRawTransactionManager;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.PucHashUtil;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
@Slf4j
public class CheckInOnChainService {
    public enum TransactionState { PENDING, SUCCEEDED, FAILED }
    private final CheckInAuthService checkInAuthService;
    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final ConcurrentMap<String, Object> transactionSubmissionLocks = new ConcurrentHashMap<>();

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger gasLimit;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger gasPriceGwei;

    @Value("${checkin.receipt.max-attempts:40}")
    private int receiptMaxAttempts;

    @Value("${checkin.receipt.poll-interval-ms:1500}")
    private long receiptPollIntervalMs;

    @Value("${institutional.checkin.outbox.nonce-replacement-gas-bump-percent:15}")
    private int nonceReplacementGasBumpPercent;

    public CheckInResponse verifyAndSubmit(CheckInRequest request) {
        CheckInResponse response = checkInAuthService.verifyCheckIn(request);
        String pucHash = computePucHash(request.getPuc());
        long timestamp = response.getTimestamp() != null ? response.getTimestamp() : 0L;
        String txHash = submitSignedCheckInAsync(
            response.getSigner(),
            response.getReservationKey(),
            pucHash,
            timestamp,
            request.getSignature()
        );
        response.setTxHash(txHash);
        return response;
    }

    public String submitSignedCheckIn(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature
    ) {
        return submitSignedCheckIn(signer, reservationKey, pucHash, timestamp, signature, true);
    }

    /**
     * Submits a check-in transaction without making the caller wait for a
     * receipt. The provider observes ACCESS_AUTHORIZED before it releases an
     * access credential, so the transaction hash is sufficient here.
     */
    public String submitSignedCheckInAsync(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature
    ) {
        return submitSignedCheckIn(signer, reservationKey, pucHash, timestamp, signature, false);
    }

    /** Uses a nonce allocated by the durable per-wallet dispatcher. */
    public String submitSignedCheckInAsync(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature,
        BigInteger nonce
    ) {
        return submitSignedCheckIn(signer, reservationKey, pucHash, timestamp, signature, false, nonce, 0);
    }

    public String submitSignedCheckInAsync(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature,
        BigInteger nonce,
        int replacementAttempt
    ) {
        return submitSignedCheckIn(
            signer, reservationKey, pucHash, timestamp, signature, false, nonce, replacementAttempt
        );
    }

    public BigInteger pendingNonce(String walletAddress) {
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
            throw new IllegalStateException("Failed to read pending nonce", ex);
        }
    }

    /** Best-effort diagnostic only; access remains authorized solely by contract state. */
    public TransactionState transactionState(String txHash) {
        try {
            return transactionStateStrict(txHash);
        } catch (RuntimeException ex) {
            log.warn("Unable to inspect access authorization transaction {}: {}", txHash, ex.getMessage());
            return TransactionState.PENDING;
        }
    }

    /** Strict receipt lookup for reconciliation; RPC failures must never look like pending work. */
    public TransactionState transactionStateStrict(String txHash) {
        if (txHash == null || !txHash.matches("^0x[0-9a-fA-F]{64}$")) {
            throw new IllegalArgumentException("Invalid access authorization transaction hash");
        }
        try {
            var result = walletService.getWeb3jInstance().ethGetTransactionReceipt(txHash).send();
            if (result == null || result.getTransactionReceipt().isEmpty()) {
                return TransactionState.PENDING;
            }
            return result.getTransactionReceipt().get().isStatusOK()
                ? TransactionState.SUCCEEDED
                : TransactionState.FAILED;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to inspect access authorization transaction", ex);
        }
    }

    /** Strict mempool/chain visibility lookup used only after the receipt is absent. */
    public boolean transactionVisible(String txHash) {
        if (txHash == null || !txHash.matches("^0x[0-9a-fA-F]{64}$")) {
            throw new IllegalArgumentException("Invalid access authorization transaction hash");
        }
        try {
            var result = walletService.getWeb3jInstance().ethGetTransactionByHash(txHash).send();
            if (result == null) {
                throw new IllegalStateException("Node returned no transaction lookup response");
            }
            return result.getTransaction().isPresent();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to inspect access authorization transaction visibility", ex);
        }
    }

    private String submitSignedCheckIn(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature,
        boolean waitForReceipt
    ) {
        return submitSignedCheckIn(signer, reservationKey, pucHash, timestamp, signature, waitForReceipt, null, 0);
    }

    private String submitSignedCheckIn(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature,
        boolean waitForReceipt,
        BigInteger explicitNonce,
        int replacementAttempt
    ) {
        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        Web3j web3j = walletService.getWeb3jInstance();
        
        long chainId = getChainId(web3j);
        TransactionManager txManager = explicitNonce == null
            ? new PendingNonceFastRawTransactionManager(web3j, credentials, chainId)
            : new PendingNonceFastRawTransactionManager(web3j, credentials, chainId, explicitNonce);

        String normalizedReservationKey = normalizeBytes32(reservationKey);
        String normalizedPucHash = normalizeBytes32(pucHash);

        byte[] reservationKeyBytes = Numeric.hexStringToByteArray(normalizedReservationKey);
        byte[] pucHashBytes = Numeric.hexStringToByteArray(normalizedPucHash);
        byte[] signatureBytes = Numeric.hexStringToByteArray(signature);

        Function function = new Function(
            "checkInReservationWithSignature",
            List.of(
                new Bytes32(reservationKeyBytes),
                new Address(signer),
                new Bytes32(pucHashBytes),
                new Uint64(BigInteger.valueOf(timestamp)),
                new DynamicBytes(signatureBytes)
            ),
            List.of()
        );

        String encoded = FunctionEncoder.encode(function);
        EthSendTransaction tx;
        try {
            // The durable dispatcher holds the database row lock for the
            // wallet while it reserves and persists an explicit nonce. Direct
            // callers still need a local critical section, but wallets must
            // not serialize one another in the same JVM.
            Object walletLock = transactionSubmissionLocks.computeIfAbsent(
                credentials.getAddress().toLowerCase(Locale.ROOT), ignored -> new Object()
            );
            synchronized (walletLock) {
                tx = txManager.sendTransaction(
                    toWei(gasPriceForReplacement(replacementAttempt)),
                    gasLimit,
                    contractAddress,
                    encoded,
                    BigInteger.ZERO
                );
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to send check-in transaction: " + e.getMessage(), e);
        }

        String txHash = tx.getTransactionHash();
        if (txHash == null || tx.hasError()) {
            String error = tx.getError() != null ? tx.getError().getMessage() : "tx_hash_missing";
            throw new IllegalStateException("Check-in transaction failed: " + error);
        }

        if (waitForReceipt) {
            TransactionReceipt receipt = waitForReceipt(web3j, txHash);
            if (!receipt.isStatusOK()) {
                String status = receipt.getStatus() != null ? receipt.getStatus() : "unknown";
                throw new IllegalStateException("Check-in transaction was mined but failed. Status: " + status);
            }
        }
        return txHash;
    }

    private TransactionReceipt waitForReceipt(Web3j web3j, String txHash) {
        int attempts = Math.max(1, receiptMaxAttempts);
        long pollInterval = Math.max(0L, receiptPollIntervalMs);

        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                var response = web3j.ethGetTransactionReceipt(txHash).send();
                if (response != null && response.getTransactionReceipt().isPresent()) {
                    return response.getTransactionReceipt().get();
                }
            } catch (Exception e) {
                throw new IllegalStateException("Failed to confirm check-in transaction: " + e.getMessage(), e);
            }

            if (attempt < attempts && pollInterval > 0L) {
                try {
                    Thread.sleep(pollInterval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while waiting for check-in transaction confirmation", e);
                }
            }
        }

        throw new IllegalStateException(
            "Check-in transaction was not confirmed after " + attempts + " receipt poll attempts: " + txHash
        );
    }

    private long getChainId(Web3j web3j) {
        try {
            EthChainId id = web3j.ethChainId().send();
            if (id == null || id.getChainId() == null) {
                return 0L;
            }
            return id.getChainId().longValue();
        } catch (Exception e) {
            log.warn("Unable to resolve chainId: {}", e.getMessage());
            return 0L;
        }
    }

    private BigInteger toWei(BigInteger gwei) {
        if (gwei == null) {
            return BigInteger.ZERO;
        }
        return org.web3j.utils.Convert.toWei(gwei.toString(), org.web3j.utils.Convert.Unit.GWEI).toBigInteger();
    }

    private String computePucHash(String puc) {
        return PucHashUtil.hashPuc(puc);
    }

    private BigInteger gasPriceForReplacement(int replacementAttempt) {
        if (gasPriceGwei == null || replacementAttempt <= 0) {
            return gasPriceGwei;
        }
        BigInteger bumpPercent = BigInteger.valueOf(Math.max(1, nonceReplacementGasBumpPercent));
        BigInteger multiplier = BigInteger.valueOf(100L + bumpPercent.longValue() * replacementAttempt);
        return gasPriceGwei.multiply(multiplier).add(BigInteger.valueOf(99)).divide(BigInteger.valueOf(100));
    }

    private String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }
}
