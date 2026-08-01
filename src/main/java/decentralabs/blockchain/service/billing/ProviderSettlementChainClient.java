package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.LogSanitizer;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Locale;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;

/**
 * The only write boundary for provider settlement claims. Every operation is
 * sent through the institutional transaction manager, which provides durable
 * nonce/payload idempotency and receipt recovery.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ProviderSettlementChainClient {

    public record ChainReceipt(
        String transactionHash,
        BigInteger blockNumber,
        String blockHash,
        String actor
    ) { }

    private final InstitutionalTxManagerProvider txManagerProvider;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${ethereum.gas.price.default:1}")
    private BigDecimal defaultGasPriceGwei;

    @Value("${ethereum.gas.price.strategy:network}")
    private String gasPriceStrategy;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger contractGasLimit;

    public String actorAddress() {
        return institutionalWalletService.getInstitutionalWalletAddress().toLowerCase(Locale.ROOT);
    }

    public ChainReceipt submit(
        byte[] claimId,
        BigInteger labId,
        BigInteger amount,
        byte[] batchId,
        byte[] invoiceReferenceHash,
        String operationKey
    ) throws Exception {
        Diamond diamond = loadWritableDiamond(operationKey);
        return toReceipt(diamond.submitProviderSettlementClaim(
            claimId, labId, amount, batchId, invoiceReferenceHash
        ).send());
    }

    public ChainReceipt approve(byte[] claimId, byte[] approvalReferenceHash, String operationKey) throws Exception {
        Diamond diamond = loadWritableDiamond(operationKey);
        return toReceipt(diamond.approveProviderSettlementClaim(claimId, approvalReferenceHash).send());
    }

    public ChainReceipt pay(
        byte[] claimId,
        byte[] paymentReferenceHash,
        byte[] paymentAttestationHash,
        String operationKey
    ) throws Exception {
        Diamond diamond = loadWritableDiamond(operationKey);
        return toReceipt(diamond.recordProviderSettlementClaimPayment(
            claimId, paymentReferenceHash, paymentAttestationHash
        ).send());
    }

    public Diamond.ProviderSettlementClaim readClaim(byte[] claimId) throws Exception {
        return loadReadonlyDiamond().getProviderSettlementClaim(claimId).send();
    }

    public byte[] readApprovalReferenceHash(byte[] claimId) throws Exception {
        return loadReadonlyDiamond().getProviderSettlementClaimApprovalReferenceHash(claimId).send();
    }

    private ChainReceipt toReceipt(TransactionReceipt receipt) {
        if (receipt == null || !"0x1".equalsIgnoreCase(receipt.getStatus())) {
            String status = receipt == null ? "missing" : receipt.getStatus();
            throw new IllegalStateException("Settlement transaction was not mined successfully (status=" + status + ")");
        }
        return new ChainReceipt(
            receipt.getTransactionHash(),
            receipt.getBlockNumber(),
            receipt.getBlockHash(),
            actorAddress()
        );
    }

    private Diamond loadReadonlyDiamond() {
        Web3j web3j = walletService.getWeb3jInstance();
        return Diamond.load(
            contractAddress,
            web3j,
            new org.web3j.tx.ReadonlyTransactionManager(web3j, contractAddress),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );
    }

    private Diamond loadWritableDiamond(String operationKey) {
        Web3j web3j = walletService.getWeb3jInstance();
        TransactionManager txManager = txManagerProvider.get(web3j, operationKey);
        return Diamond.load(
            contractAddress,
            web3j,
            txManager,
            new StaticGasProvider(resolveGasPriceWei(web3j), contractGasLimit)
        );
    }

    private BigInteger resolveGasPriceWei(Web3j web3j) {
        BigInteger fallback = Convert.toWei(
            Optional.ofNullable(defaultGasPriceGwei).orElse(BigDecimal.ONE).toString(),
            Convert.Unit.GWEI
        ).toBigInteger();
        if ("fixed".equalsIgnoreCase(Optional.ofNullable(gasPriceStrategy).orElse("network"))) {
            return fallback;
        }
        try {
            var response = web3j.ethGasPrice().send();
            return response != null && response.getGasPrice() != null ? response.getGasPrice() : fallback;
        } catch (Exception ex) {
            log.warn("Unable to resolve settlement gas price, using fallback: {}", LogSanitizer.sanitize(ex.getMessage()));
            return fallback;
        }
    }
}
