package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.service.auth.InstitutionalWalletTransactionDispatcher;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

/**
 * Encodes and preflights the permissionless reservation finalizer.
 *
 * <p>The transaction is signed by the configured institutional wallet only as
 * a gas payer. The contract does not use this wallet as an authority.</p>
 */
@Service
@RequiredArgsConstructor
public class ReservationFinalizationOnChainClient {
    public record FinalizationStatus(
        BigInteger activeReservationCount,
        BigInteger payoutHeapLength,
        BigInteger payoutHeapInvalidCount,
        BigInteger oldestPayoutCandidateEnd,
        BigInteger lastFinalizationAt
    ) {
        public boolean hasCandidateWork(long now) {
            return payoutHeapLength != null
                && payoutHeapInvalidCount != null
                && payoutHeapLength.compareTo(payoutHeapInvalidCount) > 0
                && oldestPayoutCandidateEnd != null
                && oldestPayoutCandidateEnd.signum() > 0
                && oldestPayoutCandidateEnd.compareTo(BigInteger.valueOf(now)) <= 0;
        }
    }

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${ethereum.gas.limit.reservation-finalization:5000000}")
    private BigInteger gasLimit;

    @Value("${ethereum.gas.price.default:1}")
    private BigInteger gasPriceGwei;

    @Value("${reservation.finalization.scheduler.nonce-replacement-gas-bump-percent:15}")
    private int nonceReplacementGasBumpPercent;

    public BigInteger connectedChainId() {
        try {
            EthChainId response = walletService.getWeb3jInstance().ethChainId().send();
            if (response == null || response.getChainId() == null || response.getChainId().signum() <= 0) {
                throw new IllegalStateException("RPC returned no valid reservation finalization chainId");
            }
            return response.getChainId();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to resolve reservation finalization chainId", ex);
        }
    }

    public String signerAddress() {
        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        return credentials.getAddress();
    }

    public BigInteger pendingNonce(String walletAddress) {
        try {
            var response = walletService.getWeb3jInstance().ethGetTransactionCount(
                walletAddress, DefaultBlockParameterName.PENDING
            ).send();
            if (response == null || response.getTransactionCount() == null) {
                throw new IllegalStateException("RPC returned no pending nonce");
            }
            return response.getTransactionCount();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to read reservation finalization pending nonce", ex);
        }
    }

    public FinalizationStatus readStatus(BigInteger labId) {
        requireLabId(labId);
        Function function = Diamond.getLabFinalizationStatusFunction(labId);
        List<Type<?>> decoded = call(function, "getLabFinalizationStatus");
        return new FinalizationStatus(
            value(decoded, 0), value(decoded, 1), value(decoded, 2), value(decoded, 3), value(decoded, 4)
        );
    }

    public void validatePreflight(BigInteger labId, BigInteger maxBatch) {
        requireLabId(labId);
        requireBatch(maxBatch);
        Function function = finalizationFunction(labId, maxBatch);
        try {
            Web3j web3j = walletService.getWeb3jInstance();
            EthCall response = web3j.ethCall(
                Transaction.createFunctionCallTransaction(
                    signerAddress(),
                    null,
                    null,
                    gasLimit,
                    contractAddress,
                    FunctionEncoder.encode(function)
                ),
                DefaultBlockParameterName.LATEST
            ).send();
            if (response == null) {
                throw new IllegalStateException("RPC returned no reservation finalization preflight response");
            }
            if (response.hasError()) {
                String message = response.getError() != null && response.getError().getMessage() != null
                    ? response.getError().getMessage() : "contract_reverted";
                throw new IllegalStateException("Reservation finalization preflight reverted: " + message);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to run reservation finalization preflight", ex);
        }
    }

    public String encodedCall(BigInteger labId, BigInteger maxBatch) {
        requireLabId(labId);
        requireBatch(maxBatch);
        return FunctionEncoder.encode(finalizationFunction(labId, maxBatch));
    }

    public InstitutionalWalletTransactionDispatcher.PreparedTransaction prepare(
        BigInteger labId,
        BigInteger maxBatch,
        BigInteger transactionNonce,
        int replacementAttempt,
        BigInteger originalGasPriceWei
    ) {
        requireLabId(labId);
        requireBatch(maxBatch);
        if (transactionNonce == null || transactionNonce.signum() < 0) {
            throw new IllegalArgumentException("Reservation finalization transaction nonce is required");
        }

        BigInteger chainId = connectedChainId();
        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
        BigInteger gasPriceWei = gasPriceWeiForReplacement(replacementAttempt, originalGasPriceWei);
        RawTransaction raw = RawTransaction.createTransaction(
            transactionNonce,
            gasPriceWei,
            gasLimit,
            contractAddress,
            BigInteger.ZERO,
            encodedCall(labId, maxBatch)
        );
        String rawHex = Numeric.toHexString(TransactionEncoder.signMessage(raw, chainId.longValueExact(), credentials));
        return new InstitutionalWalletTransactionDispatcher.PreparedTransaction(
            rawHex, Hash.sha3(rawHex), gasPriceWei
        );
    }

    public BigInteger gasLimit() {
        return gasLimit;
    }

    public BigInteger gasPriceWei() {
        return Convert.toWei(gasPriceGwei.toString(), Convert.Unit.GWEI).toBigInteger();
    }

    private Function finalizationFunction(BigInteger labId, BigInteger maxBatch) {
        return Diamond.finalizeEligibleReservationsFunction(labId, maxBatch);
    }

    private List<Type<?>> call(Function function, String name) {
        try {
            EthCall response = walletService.getWeb3jInstance().ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, FunctionEncoder.encode(function)),
                DefaultBlockParameterName.LATEST
            ).send();
            if (response == null) {
                throw new IllegalStateException("RPC returned no " + name + " response");
            }
            if (response.hasError()) {
                throw new IllegalStateException(response.getError() == null
                    ? "RPC returned an error" : response.getError().getMessage());
            }
            @SuppressWarnings("unchecked")
            List<Type<?>> decoded = (List<Type<?>>) (List<?>) FunctionReturnDecoder.decode(
                response.getValue(), function.getOutputParameters()
            );
            if (decoded.size() != function.getOutputParameters().size()) {
                throw new IllegalStateException("RPC returned an incomplete " + name + " response");
            }
            return decoded;
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read " + name, ex);
        }
    }

    private BigInteger value(List<Type<?>> decoded, int index) {
        return (BigInteger) decoded.get(index).getValue();
    }

    private BigInteger gasPriceWeiForReplacement(int replacementAttempt, BigInteger originalGasPriceWei) {
        BigInteger original = originalGasPriceWei != null && originalGasPriceWei.signum() > 0
            ? originalGasPriceWei : gasPriceWei();
        int attempts = Math.max(0, replacementAttempt);
        int bumpPercent = Math.max(0, nonceReplacementGasBumpPercent);
        BigInteger multiplier = BigInteger.valueOf(100L + (long) attempts * bumpPercent);
        return original.multiply(multiplier).add(BigInteger.valueOf(99)).divide(BigInteger.valueOf(100));
    }

    private void requireLabId(BigInteger labId) {
        if (labId == null || labId.signum() <= 0) {
            throw new IllegalArgumentException("labId is invalid");
        }
    }

    private void requireBatch(BigInteger maxBatch) {
        if (maxBatch == null || maxBatch.signum() <= 0 || maxBatch.compareTo(BigInteger.TEN) > 0) {
            throw new IllegalArgumentException("maxBatch must be between 1 and 10");
        }
    }
}
