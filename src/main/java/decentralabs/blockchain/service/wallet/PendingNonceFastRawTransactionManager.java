package decentralabs.blockchain.service.wallet;

import java.io.IOException;
import java.math.BigInteger;

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

    public PendingNonceFastRawTransactionManager(Web3j web3j, Credentials credentials, long chainId) {
        super(web3j, credentials, chainId);
        this.web3j = web3j;
        this.credentials = credentials;
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
    }

    @Override
    protected BigInteger getNonce() throws IOException {
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
            credentials.getAddress(),
            DefaultBlockParameterName.PENDING
        ).send();
        return ethGetTransactionCount.getTransactionCount();
    }
}
