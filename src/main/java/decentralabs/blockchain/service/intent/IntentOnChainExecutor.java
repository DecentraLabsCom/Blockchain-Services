package decentralabs.blockchain.service.intent;

import java.math.BigInteger;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint32;
import org.web3j.abi.datatypes.generated.Uint96;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.TypeReference; 
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.FastRawTransactionManager;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class IntentOnChainExecutor {

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final String contractAddress;
    private final BigInteger gasLimit;
    private final BigInteger gasPriceWei;
    @Value("${blockchain.network.active:sepolia}")
    private String executionNetwork;
    public IntentOnChainExecutor(
        WalletService walletService,
        InstitutionalWalletService institutionalWalletService,
        @Value("${contract.address}") String contractAddress,
        @Value("${ethereum.gas.limit.contract:300000}") BigInteger gasLimit,
        @Value("${ethereum.gas.price.default:1}") BigInteger gasPriceGwei
    ) {
        this.walletService = walletService;
        this.institutionalWalletService = institutionalWalletService;
        this.contractAddress = contractAddress;
        this.gasLimit = gasLimit;
        this.gasPriceWei = toWei(gasPriceGwei);
    }

    public record ExecutionResult(boolean success, String txHash, Long blockNumber, String labId, String reservationKey, String reason) { }

    public ExecutionResult execute(IntentRecord record) throws Exception {
        String action = record.getAction() == null ? "" : record.getAction().toUpperCase(Locale.ROOT);

        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();

        return switch (action) {
            case "LAB_ADD" -> send(buildAddLab(record), credentials);
            case "LAB_UPDATE" -> send(buildUpdateLab(record), credentials);
            case "LAB_LIST" -> send(buildSimple(FunctionName.LIST_TOKEN, record), credentials);
            case "LAB_UNLIST" -> send(buildSimple(FunctionName.UNLIST_TOKEN, record), credentials);
            case "LAB_DELETE" -> send(buildSimple(FunctionName.DELETE_LAB, record), credentials);
            case "LAB_SET_URI" -> send(buildSetTokenURI(record), credentials);
            case "CANCEL_RESERVATION_REQUEST" -> send(buildCancelReservation(record), credentials);
            case "RESERVATION_REQUEST" -> send(buildReservationRequest(record), credentials);
            case "CANCEL_BOOKING" -> send(buildCancelBooking(record), credentials);
            case "REQUEST_FUNDS" -> send(buildRequestFunds(record), credentials);
            default -> new ExecutionResult(false, null, null, null, null, "unsupported_action");
        };
    }

    private ExecutionResult send(Optional<Function> functionOpt, Credentials credentials) throws Exception {
        if (functionOpt.isEmpty()) {
            return new ExecutionResult(false, null, null, null, null, "missing_parameters");
        }
        Function function = functionOpt.get();
        Web3j web3j = resolveWeb3j();
        long chainId = getChainId(web3j);
        TransactionManager txManager = new FastRawTransactionManager(web3j, credentials, chainId);
        String encoded = FunctionEncoder.encode(function);

        EthSendTransaction tx = txManager.sendTransaction(gasPriceWei, gasLimit, contractAddress, encoded, BigInteger.ZERO);
        String txHash = tx.getTransactionHash();
        if (txHash == null) {
            return new ExecutionResult(false, null, null, null, null, tx.getError() != null ? tx.getError().getMessage() : "tx_hash_missing");
        }

        try {
            TransactionReceipt receipt = waitForReceipt(web3j, txHash);
            Long blockNumber = receipt.getBlockNumber() != null ? receipt.getBlockNumber().longValue() : null;
            return new ExecutionResult(receipt.isStatusOK(), txHash, blockNumber, null, null,
                receipt.isStatusOK() ? null : receipt.getStatus());
        } catch (Exception ex) {
            log.warn("Failed to get tx receipt for {}: {}", txHash, ex.getMessage());
            return new ExecutionResult(false, txHash, null, null, null, "receipt_error: " + ex.getMessage());
        }
    }

    private TransactionReceipt waitForReceipt(Web3j web3j, String txHash) {
        try {
            int attempts = 0;
            int maxAttempts = 40;
            while (attempts < maxAttempts) {
                var response = web3j.ethGetTransactionReceipt(txHash).send();
                if (response.getTransactionReceipt().isPresent()) {
                    return response.getTransactionReceipt().get();
                }
                Thread.sleep(3000);
                attempts++;
            }
            throw new RuntimeException("Transaction receipt not found after " + maxAttempts + " attempts");
        } catch (Exception e) {
            throw new RuntimeException("Failed to get tx receipt: " + e.getMessage(), e);
        }
    }

    private long getChainId(Web3j web3j) throws Exception {
        EthChainId id = web3j.ethChainId().send();
        if (id == null || id.getChainId() == null) {
            return 0L;
        }
        return id.getChainId().longValue();
    }

    private Optional<Function> buildAddLab(IntentRecord record) {
        ActionIntentPayload payload = record.getActionPayload();
        if (payload == null) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());
        Bytes32 assertion = new Bytes32(toBytes32(payload.getAssertionHash()));
        Bytes32 reservationKey = new Bytes32(toBytes32(payload.getReservationKey()));

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            assertion,
            new Uint256(payload.getLabId()),
            reservationKey,
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : "")
        );

        return Optional.of(new Function(
            "addLabWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildCancelBooking(IntentRecord record) {
        if (record.getReservationKey() == null) {
            return Optional.empty();
        }
        byte[] keyBytes = Numeric.hexStringToByteArray(record.getReservationKey());
        if (keyBytes.length != 32) {
            return Optional.empty();
        }
        ActionIntentPayload payload = record.getActionPayload();
        if (payload == null) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : "")
        );

        return Optional.of(new Function(
            "cancelInstitutionalBookingWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildUpdateLab(IntentRecord record) {
        ActionIntentPayload payload = record.getActionPayload();
        if (payload == null) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        Bytes32 assertion = new Bytes32(toBytes32(payload.getAssertionHash()));
        Bytes32 reservationKey = new Bytes32(toBytes32(payload.getReservationKey()));

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            assertion,
            new Uint256(payload.getLabId()),
            reservationKey,
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : "")
        );

        return Optional.of(new Function(
            "updateLabWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildSimple(FunctionName fn, IntentRecord record) {
        ActionIntentPayload payload = record.getActionPayload();
        if (payload == null || payload.getLabId() == null) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : "")
        );

        return Optional.of(new Function(
            fn.methodWithIntent,
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildCancelReservation(IntentRecord record) {
        if (record.getReservationKey() == null) {
            return Optional.empty();
        }
        byte[] keyBytes = Numeric.hexStringToByteArray(record.getReservationKey());
        if (keyBytes.length != 32) {
            return Optional.empty();
        }
        ReservationIntentPayload payload = record.getReservationPayload();
        if (payload == null) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Uint32(BigInteger.valueOf(payload.getStart())),
            new Uint32(BigInteger.valueOf(payload.getEnd())),
            new Uint96(payload.getPrice()),
            new Bytes32(toBytes32(payload.getReservationKey()))
        );

        return Optional.of(new Function(
            "cancelInstitutionalReservationRequestWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildRequestFunds(IntentRecord record) {
        ActionIntentPayload payload = record.getActionPayload();
        if (payload == null || payload.getLabId() == null) {
            return Optional.empty();
        }
        BigInteger maxBatch = bigIntVal(payload.getMaxBatch());
        if (maxBatch == null || maxBatch.compareTo(BigInteger.ONE) < 0 || maxBatch.compareTo(BigInteger.valueOf(100)) > 0) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : "")
        );

        return Optional.of(new Function(
            "requestFundsWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildReservationRequest(IntentRecord record) {
        ReservationIntentPayload payload = record.getReservationPayload();
        if (payload == null) {
            return Optional.empty();
        }
        BigInteger start = bigIntVal(payload.getStart());
        BigInteger end = bigIntVal(payload.getEnd());
        if (start == null || end == null) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Uint32(BigInteger.valueOf(payload.getStart())),
            new Uint32(BigInteger.valueOf(payload.getEnd())),
            new Uint96(payload.getPrice()),
            new Bytes32(toBytes32(payload.getReservationKey()))
        );

        return Optional.of(new Function(
            "institutionalReservationRequestWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildSetTokenURI(IntentRecord record) {
        ActionIntentPayload payload = record.getActionPayload();
        if (payload == null || payload.getLabId() == null) {
            return Optional.empty();
        }
        String uri = payload.getTokenURI();
        if (uri == null || uri.isBlank()) {
            return Optional.empty();
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return Optional.empty();
        }
        byte[] requestId = toBytes32(record.getRequestId());

        DynamicStruct struct = new DynamicStruct(
            new Address(payload.getExecutor()),
            new Utf8String(payload.getSchacHomeOrganization() != null ? payload.getSchacHomeOrganization() : ""),
            new Utf8String(payload.getPuc() != null ? payload.getPuc() : ""),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : "")
        );

        return Optional.of(new Function(
            "setTokenURIWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    public Optional<BigInteger> fetchNextIntentNonce(String signer) {
        try {
            Web3j web3j = resolveWeb3j();
            Function fn = new Function(
                "nextIntentNonce",
                List.of(new org.web3j.abi.datatypes.Address(signer)),
                List.of(new TypeReference<Uint256>() { })
            );
            String encoded = FunctionEncoder.encode(fn);
            org.web3j.protocol.core.methods.response.EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(signer, contractAddress, encoded),
                DefaultBlockParameterName.LATEST
            ).send();
            if (response == null || response.hasError()) {
                return Optional.empty();
            }
            return FunctionReturnDecoder.decode(response.getValue(), fn.getOutputParameters())
                .stream()
                .findFirst()
                .map(type -> ((Uint256) type).getValue());
        } catch (Exception ex) {
            log.warn("Unable to fetch next intent nonce for {}: {}", signer, ex.getMessage());
            return Optional.empty();
        }
    }

    private BigInteger toWei(BigInteger gwei) {
        if (gwei == null) {
            return BigInteger.ZERO;
        }
        return org.web3j.utils.Convert.toWei(gwei.toString(), org.web3j.utils.Convert.Unit.GWEI).toBigInteger();
    }

    private Web3j resolveWeb3j() {
        return walletService.getWeb3jInstanceForNetwork(executionNetwork);
    }

    private BigInteger bigIntVal(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof BigInteger bi) {
            return bi;
        }
        if (value instanceof Number n) {
            return BigInteger.valueOf(n.longValue());
        }
        try {
            return new BigInteger(value.toString());
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private byte[] toBytes32(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[32];
        }
        byte[] raw = Numeric.hexStringToByteArray(hex);
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        int start = 32 - raw.length;
        if (start < 0) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, start, raw.length);
        }
        return out;
    }

    private enum FunctionName {
        LIST_TOKEN("listLabWithIntent"),
        UNLIST_TOKEN("unlistLabWithIntent"),
        DELETE_LAB("deleteLabWithIntent");

        final String methodWithIntent;

        FunctionName(String methodWithIntent) {
            this.methodWithIntent = methodWithIntent;
        }
    }
}
