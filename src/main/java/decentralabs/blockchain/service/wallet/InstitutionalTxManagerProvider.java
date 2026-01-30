package decentralabs.blockchain.service.wallet;

import java.util.Objects;

import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.response.PollingTransactionReceiptProcessor;
import org.web3j.tx.response.TransactionReceiptProcessor;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalTxManagerProvider {

    private final InstitutionalWalletService institutionalWalletService;

    private final Object lock = new Object();
    private TransactionManager txManager;
    private Web3j currentWeb3j;
    private Long currentChainId;

    public TransactionManager get(Web3j web3j) {
        if (web3j == null) {
            throw new IllegalArgumentException("web3j is required");
        }
        long chainId = resolveChainId(web3j);
        synchronized (lock) {
            if (txManager == null
                || currentWeb3j != web3j
                || currentChainId == null
                || !Objects.equals(currentChainId, chainId)) {
                Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
                TransactionReceiptProcessor receiptProcessor = new PollingTransactionReceiptProcessor(web3j, 1500, 40);
                txManager = new PendingNonceFastRawTransactionManager(web3j, credentials, chainId, receiptProcessor);
                currentWeb3j = web3j;
                currentChainId = chainId;
                log.info("Institutional tx manager initialized (chainId={})", chainId);
            }
        }
        return txManager;
    }

    private long resolveChainId(Web3j web3j) {
        try {
            EthChainId id = web3j.ethChainId().send();
            if (id != null && id.getChainId() != null) {
                return id.getChainId().longValue();
            }
        } catch (Exception ex) {
            log.warn("Unable to fetch chainId for tx manager: {}", ex.getMessage());
        }
        return 0L;
    }
}
