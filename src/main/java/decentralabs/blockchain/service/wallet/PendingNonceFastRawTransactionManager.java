package decentralabs.blockchain.service.wallet;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Numeric;
import decentralabs.blockchain.service.auth.InstitutionalWalletNonceReservationService;

/**
 * FastRawTransactionManager that initializes nonce from the PENDING pool to avoid
 * accidental nonce reuse when there are already pending transactions.
 */
public class PendingNonceFastRawTransactionManager extends FastRawTransactionManager {

    private final Web3j web3j;
    private final Credentials credentials;
    private final BigInteger explicitNonce;
    private final BigInteger chainId;
    private final InstitutionalWalletNonceReservationService nonceReservationService;
    private final InstitutionalTransactionOutboxService transactionOutboxService;
    private final String configuredOperationKey;

    public PendingNonceFastRawTransactionManager(Web3j web3j, Credentials credentials, long chainId) {
        super(web3j, credentials, chainId);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = null;
        this.configuredOperationKey = null;
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        BigInteger explicitNonce
    ) {
        super(web3j, credentials, chainId);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = explicitNonce;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = null;
        this.configuredOperationKey = null;
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        TransactionReceiptProcessor receiptProcessor
    ) {
        super(web3j, credentials, chainId, receiptProcessor);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = null;
        this.configuredOperationKey = null;
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        TransactionReceiptProcessor receiptProcessor,
        InstitutionalWalletNonceReservationService nonceReservationService
    ) {
        super(web3j, credentials, chainId, receiptProcessor);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = nonceReservationService;
        this.transactionOutboxService = null;
        this.configuredOperationKey = null;
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        InstitutionalTransactionOutboxService transactionOutboxService
    ) {
        super(web3j, credentials, chainId);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = transactionOutboxService;
        this.configuredOperationKey = null;
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        TransactionReceiptProcessor receiptProcessor,
        InstitutionalTransactionOutboxService transactionOutboxService
    ) {
        this(web3j, credentials, chainId, receiptProcessor, transactionOutboxService, null);
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        TransactionReceiptProcessor receiptProcessor,
        InstitutionalTransactionOutboxService transactionOutboxService,
        String operationKey
    ) {
        super(web3j, credentials, chainId, receiptProcessor);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = transactionOutboxService;
        this.configuredOperationKey = normalizeOperationKey(operationKey);
    }

    @Override
    public synchronized EthSendTransaction sendTransaction(
        BigInteger gasPrice,
        BigInteger gasLimit,
        String to,
        String data,
        BigInteger value,
        boolean constructor
    ) throws IOException {
        if (transactionOutboxService == null) {
            return super.sendTransaction(gasPrice, gasLimit, to, data, value, constructor);
        }

        BigInteger pendingNonce = readPendingNonce();
        String operationKey = configuredOperationKey != null
            ? configuredOperationKey
            : operationFingerprint(to, data, value);
        reconcileBlockingAttempt();
        InstitutionalTransactionOutboxService.Attempt attempt;
        try {
            attempt = transactionOutboxService.reserveOrLoad(
                credentials.getAddress(), chainId, pendingNonce, operationKey,
                gasPrice, gasLimit, to, value, data
            );
        } catch (InstitutionalTransactionOutboxService.TransactionBlockedException ex) {
            throw new IOException(ex.getMessage(), ex);
        }

        if (attempt == null) {
            throw new IOException("Outbox returned no durable transaction attempt");
        }

        if (attempt.txHash() != null && !attempt.txHash().isBlank()
            && ("SUBMITTED".equals(attempt.status()) || "MINED_SUCCESS".equals(attempt.status()))) {
            EthSendTransaction existing = new EthSendTransaction();
            existing.setResult(attempt.txHash());
            return existing;
        }

        BigInteger effectiveGasPrice = attempt.gasPrice() != null ? attempt.gasPrice() : gasPrice;
        BigInteger effectiveGasLimit = attempt.gasLimit() != null ? attempt.gasLimit() : gasLimit;
        String effectiveTo = attempt.toAddress() != null ? attempt.toAddress() : to;
        BigInteger effectiveValue = attempt.value() != null ? attempt.value() : value;
        String effectiveData = attempt.data() != null ? attempt.data() : data;
        RawTransaction rawTransaction = RawTransaction.createTransaction(
            attempt.nonce(), effectiveGasPrice, effectiveGasLimit, effectiveTo, effectiveValue, effectiveData
        );
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, chainId.longValueExact(), credentials);
        String signedHex = Numeric.toHexString(signedMessage);
        String expectedHash = Hash.sha3(signedHex);
        transactionOutboxService.markSigned(attempt, signedHex, expectedHash);
        InstitutionalTransactionOutboxService.Attempt preparedAttempt = new InstitutionalTransactionOutboxService.Attempt(
            attempt.id(), attempt.chainId(), attempt.walletAddress(), attempt.operationKey(), attempt.nonce(),
            attempt.originalGasPrice(), attempt.currentGasPrice(), attempt.gasLimit(), attempt.toAddress(),
            attempt.value(), attempt.data(), "RETRYABLE", null, null, attempt.updatedAt(),
            attempt.attempts(), attempt.createdAt(), attempt.version()
        );

        EthSendTransaction response;
        try {
            response = web3j.ethSendRawTransaction(signedHex).send();
        } catch (IOException ex) {
            transactionOutboxService.markRetryable(preparedAttempt, ex.getMessage());
            throw ex;
        } catch (RuntimeException ex) {
            transactionOutboxService.markRetryable(preparedAttempt, ex.getMessage());
            throw ex;
        }

        if (response == null) {
            transactionOutboxService.markRetryable(preparedAttempt, "RPC returned no response");
            throw new IOException("RPC returned no transaction response");
        }
        if (response.hasError()) {
            transactionOutboxService.markRetryable(
                preparedAttempt,
                response.getError() != null ? response.getError().getMessage() : "Transaction broadcast failed"
            );
            return response;
        }
        String txHash = response.getTransactionHash();
        if (txHash == null || txHash.isBlank()) {
            transactionOutboxService.markRetryable(preparedAttempt, "Transaction broadcast returned no hash");
            return response;
        }
        transactionOutboxService.markSubmitted(preparedAttempt, txHash);
        return response;
    }

    @Override
    protected BigInteger getNonce() throws IOException {
        if (explicitNonce != null) {
            return explicitNonce;
        }
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
            credentials.getAddress(),
            DefaultBlockParameterName.PENDING
        ).send();
        BigInteger pendingNonce = ethGetTransactionCount.getTransactionCount();
        if (pendingNonce == null) {
            throw new IOException("Node returned no pending nonce");
        }
        if (nonceReservationService != null) {
            return nonceReservationService.reserve(credentials.getAddress(), chainId, pendingNonce);
        }
        return pendingNonce;
    }

    private BigInteger readPendingNonce() throws IOException {
        EthGetTransactionCount response = web3j.ethGetTransactionCount(
            credentials.getAddress(), DefaultBlockParameterName.PENDING
        ).send();
        BigInteger pendingNonce = response != null ? response.getTransactionCount() : null;
        if (pendingNonce == null) {
            throw new IOException("Node returned no pending nonce");
        }
        return pendingNonce;
    }

    private void reconcileBlockingAttempt() {
        InstitutionalTransactionOutboxService.Attempt blocker = transactionOutboxService.findBlocking(
            credentials.getAddress(), chainId
        );
        if (blocker == null) {
            return;
        }
        if ((blocker.txHash() == null || blocker.txHash().isBlank())
            && (blocker.signedRawTransaction() == null || blocker.signedRawTransaction().isBlank())) {
            if (blocker.gasPrice() == null || blocker.gasLimit() == null || blocker.toAddress() == null
                || blocker.value() == null || blocker.data() == null) {
                return;
            }
            RawTransaction rawTransaction = RawTransaction.createTransaction(
                blocker.nonce(), blocker.gasPrice(), blocker.gasLimit(), blocker.toAddress(),
                blocker.value(), blocker.data()
            );
            String signedHex = Numeric.toHexString(
                TransactionEncoder.signMessage(rawTransaction, chainId.longValueExact(), credentials)
            );
            String expectedHash = Hash.sha3(signedHex);
            transactionOutboxService.markSigned(blocker, signedHex, expectedHash);
            blocker = new InstitutionalTransactionOutboxService.Attempt(
                blocker.id(), blocker.chainId(), blocker.walletAddress(), blocker.operationKey(), blocker.nonce(),
                blocker.originalGasPrice(), blocker.currentGasPrice(), blocker.gasLimit(), blocker.toAddress(),
                blocker.value(), blocker.data(), "PREPARED", signedHex, expectedHash, blocker.updatedAt(),
                blocker.attempts(), blocker.createdAt(), blocker.version() + 1
            );
        }
        if (blocker.txHash() == null || blocker.txHash().isBlank()) {
            try {
                EthSendTransaction response = web3j.ethSendRawTransaction(blocker.signedRawTransaction()).send();
                if (response != null && !response.hasError()
                    && response.getTransactionHash() != null && !response.getTransactionHash().isBlank()) {
                    markVisibleSubmitted(blocker, response.getTransactionHash());
                } else if (response != null && response.hasError()
                    && response.getError() != null
                    && response.getError().getMessage() != null
                    && response.getError().getMessage().toLowerCase().contains("already known")) {
                    markVisibleSubmitted(blocker, blocker.txHash());
                }
            } catch (Exception ignored) {
                // Keep the wallet barrier in place when RPC reconciliation is unavailable.
            }
            return;
        }
        try {
            var receiptResponse = web3j.ethGetTransactionReceipt(blocker.txHash()).send();
            if (receiptResponse != null && receiptResponse.getTransactionReceipt().isPresent()) {
                markVisibleSubmitted(blocker, blocker.txHash());
                return;
            }
            var transactionResponse = web3j.ethGetTransactionByHash(blocker.txHash()).send();
            if (transactionResponse != null && transactionResponse.getTransaction().isPresent()) {
                markVisibleSubmitted(blocker, blocker.txHash());
                return;
            }
        } catch (Exception ignored) {
            // Keep the wallet barrier in place when RPC reconciliation is unavailable.
        }

        if (blocker.signedRawTransaction() == null || blocker.signedRawTransaction().isBlank()) {
            return;
        }
        try {
            EthSendTransaction response = web3j.ethSendRawTransaction(blocker.signedRawTransaction()).send();
                if (response != null && !response.hasError()
                    && response.getTransactionHash() != null && !response.getTransactionHash().isBlank()) {
                markVisibleSubmitted(blocker, response.getTransactionHash());
            } else if (response != null && response.hasError()
                && response.getError() != null
                && response.getError().getMessage() != null
                && response.getError().getMessage().toLowerCase().contains("already known")) {
                markVisibleSubmitted(blocker, blocker.txHash());
            }
        } catch (Exception ignored) {
            // The unresolved row remains a deliberate barrier for the next attempt.
        }
    }

    private void markVisibleSubmitted(
        InstitutionalTransactionOutboxService.Attempt attempt,
        String txHash
    ) {
        if (attempt == null || txHash == null || txHash.isBlank()
            || "SUBMITTED".equals(attempt.status())) {
            return;
        }
        transactionOutboxService.markVisibleSubmitted(attempt, txHash);
    }

    private String operationFingerprint(String to, String data, BigInteger value) {
        String canonical = String.join(
            "|",
            credentials.getAddress().toLowerCase(),
            chainId.toString(),
            to == null ? "" : to.toLowerCase(),
            value == null ? "0" : value.toString(),
            data == null ? "" : data.toLowerCase()
        );
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(canonical.getBytes(StandardCharsets.UTF_8));
            return Numeric.toHexStringNoPrefix(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private String normalizeOperationKey(String operationKey) {
        if (operationKey == null || operationKey.isBlank()) {
            return null;
        }
        String normalized = operationKey.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{64}")) {
            try {
                return Numeric.toHexStringNoPrefix(MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8)));
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException("SHA-256 is not available", ex);
            }
        }
        return normalized;
    }
}
