package decentralabs.blockchain.service.wallet;

import java.io.IOException;
import java.math.BigInteger;
import java.util.function.BiFunction;

import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.response.TransactionReceiptProcessor;

/**
 * FastRawTransactionManager that initializes nonce from the PENDING pool to avoid
 * accidental nonce reuse when there are already pending transactions.
 */
public class PendingNonceFastRawTransactionManager extends FastRawTransactionManager {

    private final Web3j web3j;
    private final Credentials credentials;
    private final BigInteger explicitNonce;
    private final BiFunction<String, BigInteger, BigInteger> nonceAllocator;

    public PendingNonceFastRawTransactionManager(Web3j web3j, Credentials credentials, long chainId) {
        super(web3j, credentials, chainId);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.nonceAllocator = null;
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
        this.nonceAllocator = null;
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
        this.nonceAllocator = null;
    }

    public PendingNonceFastRawTransactionManager(
        Web3j web3j,
        Credentials credentials,
        long chainId,
        TransactionReceiptProcessor receiptProcessor,
        BiFunction<String, BigInteger, BigInteger> nonceAllocator
    ) {
        super(web3j, credentials, chainId, receiptProcessor);
        this.web3j = web3j;
        this.credentials = credentials;
        this.explicitNonce = null;
        this.nonceAllocator = nonceAllocator;
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
        return nonceAllocator != null
            ? nonceAllocator.apply(credentials.getAddress(), pendingNonce)
            : pendingNonce;
    }
}
