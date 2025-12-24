package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
@Slf4j
public class CheckInOnChainService {
    private final CheckInAuthService checkInAuthService;
    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger gasLimit;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger gasPriceGwei;

    public CheckInResponse verifyAndSubmit(CheckInRequest request) {
        CheckInResponse response = checkInAuthService.verifyCheckIn(request);
        String txHash = submitOnChain(request, response);
        response.setTxHash(txHash);
        return response;
    }

    private String submitOnChain(CheckInRequest request, CheckInResponse response) {
        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        Web3j web3j = walletService.getWeb3jInstance();
        long chainId = getChainId(web3j);
        TransactionManager txManager = new FastRawTransactionManager(web3j, credentials, chainId);

        String signer = response.getSigner();
        String reservationKey = normalizeBytes32(response.getReservationKey());
        String pucHash = computePucHash(request.getPuc());
        long timestamp = response.getTimestamp() != null ? response.getTimestamp() : 0L;

        byte[] reservationKeyBytes = Numeric.hexStringToByteArray(reservationKey);
        byte[] pucHashBytes = Numeric.hexStringToByteArray(pucHash);
        byte[] signatureBytes = Numeric.hexStringToByteArray(request.getSignature());

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
            tx = txManager.sendTransaction(
                toWei(gasPriceGwei),
                gasLimit,
                contractAddress,
                encoded,
                BigInteger.ZERO
            );
        } catch (IOException e) {
            throw new IllegalStateException("Failed to send check-in transaction: " + e.getMessage(), e);
        }

        String txHash = tx.getTransactionHash();
        if (txHash == null || tx.hasError()) {
            String error = tx.getError() != null ? tx.getError().getMessage() : "tx_hash_missing";
            throw new IllegalStateException("Check-in transaction failed: " + error);
        }
        return txHash;
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
        if (puc == null || puc.isBlank()) {
            return "0x" + "0".repeat(64);
        }
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(hash));
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
