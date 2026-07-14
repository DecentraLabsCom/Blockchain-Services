package decentralabs.blockchain.service.wallet;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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
    private final Map<String, String> replacementOperationKeys = new HashMap<>();

    public PendingNonceFastRawTransactionManager(Web3j web3j, Credentials credentials, long chainId) {
        super(web3j, credentials, chainId);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = null;
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
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        TransactionReceiptProcessor receiptProcessor,
        InstitutionalTransactionOutboxService transactionOutboxService
    ) {
        super(web3j, credentials, chainId, receiptProcessor);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.chainId = BigInteger.valueOf(chainId);
        this.nonceReservationService = null;
        this.transactionOutboxService = transactionOutboxService;
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
        String operationFingerprint = operationFingerprint(gasLimit, to, data, value);
        String operationKey = replacementOperationKeys.computeIfAbsent(
            operationFingerprint,
            ignored -> newOperationKey(operationFingerprint)
        );
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

        RawTransaction rawTransaction = RawTransaction.createTransaction(
            attempt.nonce(), gasPrice, gasLimit, to, value, data
        );
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, chainId.longValueExact(), credentials);
        String signedHex = Numeric.toHexString(signedMessage);
        String expectedHash = Hash.sha3(signedHex);
        transactionOutboxService.markSigned(attempt, signedHex, expectedHash);

        EthSendTransaction response;
        try {
            response = web3j.ethSendRawTransaction(signedHex).send();
        } catch (IOException ex) {
            transactionOutboxService.markRetryable(attempt, ex.getMessage());
            throw ex;
        } catch (RuntimeException ex) {
            transactionOutboxService.markRetryable(attempt, ex.getMessage());
            throw ex;
        }

        if (response == null) {
            transactionOutboxService.markRetryable(attempt, "RPC returned no response");
            throw new IOException("RPC returned no transaction response");
        }
        if (response.hasError()) {
            transactionOutboxService.markRetryable(
                attempt,
                response.getError() != null ? response.getError().getMessage() : "Transaction broadcast failed"
            );
            return response;
        }
        String txHash = response.getTransactionHash();
        if (txHash == null || txHash.isBlank()) {
            transactionOutboxService.markRetryable(attempt, "Transaction broadcast returned no hash");
            return response;
        }
        transactionOutboxService.markSubmitted(attempt, txHash);
        replacementOperationKeys.remove(operationFingerprint, operationKey);
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
        if (blocker == null || blocker.txHash() == null || blocker.txHash().isBlank()) {
            return;
        }
        try {
            var receiptResponse = web3j.ethGetTransactionReceipt(blocker.txHash()).send();
            if (receiptResponse != null && receiptResponse.getTransactionReceipt().isPresent()) {
                transactionOutboxService.markSubmitted(blocker, blocker.txHash());
                return;
            }
            var transactionResponse = web3j.ethGetTransactionByHash(blocker.txHash()).send();
            if (transactionResponse != null && transactionResponse.getTransaction().isPresent()) {
                transactionOutboxService.markSubmitted(blocker, blocker.txHash());
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
                transactionOutboxService.markSubmitted(blocker, response.getTransactionHash());
            } else if (response != null && response.hasError()
                && response.getError() != null
                && response.getError().getMessage() != null
                && response.getError().getMessage().toLowerCase().contains("already known")) {
                transactionOutboxService.markSubmitted(blocker, blocker.txHash());
            }
        } catch (Exception ignored) {
            // The unresolved row remains a deliberate barrier for the next attempt.
        }
    }

    private String operationFingerprint(BigInteger gasLimit, String to, String data, BigInteger value) {
        String canonical = String.join(
            "|",
            credentials.getAddress().toLowerCase(),
            chainId.toString(),
            to == null ? "" : to.toLowerCase(),
            value == null ? "0" : value.toString(),
            gasLimit == null ? "0" : gasLimit.toString(),
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

    private String newOperationKey(String operationFingerprint) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest((operationFingerprint + "|" + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
            return Numeric.toHexStringNoPrefix(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}
