package decentralabs.blockchain.service.intent;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.abi.datatypes.generated.Uint32;
import org.web3j.abi.datatypes.generated.Uint96;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.TypeReference; 
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.TransactionManager;
import org.web3j.utils.Numeric;

import jakarta.annotation.PreDestroy;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.InstitutionalTxManagerProvider;
import decentralabs.blockchain.service.wallet.WalletService;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class IntentOnChainExecutor {

    private static final BigInteger MAX_RESERVATIONS_PER_LAB_USER = BigInteger.TEN;
    private static final BigInteger PRE_RELEASE_THRESHOLD = BigInteger.valueOf(2);
    private static final BigInteger PRE_RELEASE_BATCH = BigInteger.TEN;

    private final WalletService walletService;
    private final InstitutionalWalletService institutionalWalletService;
    private final String contractAddress;
    private final BigInteger gasLimit;
    private final BigInteger defaultGasPriceGwei;
    private final BigDecimal gasPriceMultiplier;
    private final BigDecimal gasPriceMinGwei;
    private final ExecutorService cleanupExecutor;
    private final InstitutionalTxManagerProvider txManagerProvider;
    private final Eip712IntentVerifier intentVerifier;
    @Value("${blockchain.network.active:sepolia}")
    private String executionNetwork;
    public IntentOnChainExecutor(
        WalletService walletService,
        InstitutionalWalletService institutionalWalletService,
        @Value("${contract.address}") String contractAddress,
        @Value("${ethereum.gas.limit.contract:300000}") BigInteger gasLimit,
        @Value("${ethereum.gas.price.default:1}") BigInteger gasPriceGwei,
        @Value("${ethereum.gas.price.multiplier:1.2}") BigDecimal gasPriceMultiplier,
        @Value("${ethereum.gas.price.min-gwei:1}") BigDecimal gasPriceMinGwei,
        InstitutionalTxManagerProvider txManagerProvider,
        Eip712IntentVerifier intentVerifier
    ) {
        this.walletService = walletService;
        this.institutionalWalletService = institutionalWalletService;
        this.contractAddress = contractAddress;
        this.gasLimit = gasLimit;
        this.defaultGasPriceGwei = gasPriceGwei;
        this.gasPriceMultiplier = gasPriceMultiplier;
        this.gasPriceMinGwei = gasPriceMinGwei;
        this.txManagerProvider = txManagerProvider;
        this.intentVerifier = intentVerifier;
        this.cleanupExecutor = Executors.newSingleThreadExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "inst-expired-release");
                t.setDaemon(true);
                return t;
            }
        });
    }

    public record ExecutionResult(boolean success, String txHash, Long blockNumber, String labId, String reservationKey, String reason) { }

    public ExecutionResult execute(IntentRecord record) throws Exception {
        String action = record.getAction() == null ? "" : record.getAction().toUpperCase(Locale.ROOT);

        // Validate action first before checking payload
        if (!isValidAction(action)) {
            return new ExecutionResult(false, null, null, null, null, "unsupported_action");
        }

        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();

        return switch (action) {
            case "LAB_ADD" -> send(buildAddLab(record), credentials, record, action);
            case "LAB_ADD_AND_LIST" -> send(buildAddAndList(record), credentials, record, action);
            case "LAB_UPDATE" -> send(buildUpdateLab(record), credentials, record, action);
            case "LAB_LIST" -> send(buildSimple(FunctionName.LIST_TOKEN, record), credentials, record, action);
            case "LAB_UNLIST" -> send(buildSimple(FunctionName.UNLIST_TOKEN, record), credentials, record, action);
            case "LAB_DELETE" -> send(buildSimple(FunctionName.DELETE_LAB, record), credentials, record, action);
            case "LAB_SET_URI" -> send(buildSetTokenURI(record), credentials, record, action);
            case "CANCEL_RESERVATION_REQUEST" -> send(buildCancelReservation(record), credentials, record, action);
            case "RESERVATION_REQUEST" -> {
                ExecutionResult result = send(buildReservationRequest(record), credentials, record, action);
                if (result.success()) {
                    postflightReleaseExpiredInstitutionalReservations(record, credentials);
                }
                yield result;
            }
            case "CANCEL_BOOKING" -> send(buildCancelBooking(record), credentials, record, action);
            default -> new ExecutionResult(false, null, null, null, null, "unsupported_action");
        };
    }

    private boolean isValidAction(String action) {
        return switch (action) {
            case "LAB_ADD", "LAB_ADD_AND_LIST", "LAB_UPDATE", "LAB_LIST", "LAB_UNLIST", 
                 "LAB_DELETE", "LAB_SET_URI", "CANCEL_RESERVATION_REQUEST", 
                 "RESERVATION_REQUEST", "CANCEL_BOOKING" -> true;
            default -> false;
        };
    }

    private ExecutionResult send(Optional<Function> functionOpt, Credentials credentials, IntentRecord record, String action) throws Exception {
        if (functionOpt.isEmpty()) {
            return new ExecutionResult(false, null, null, null, null, "missing_parameters");
        }
        
        // Validate payload hash after function construction but before execution
        Optional<String> payloadValidationError = validatePayloadHash(record, action);
        if (payloadValidationError.isPresent()) {
            return new ExecutionResult(false, null, null, null, null, payloadValidationError.get());
        }
        
        Function function = functionOpt.get();
        Web3j web3j = resolveWeb3j();
        TransactionManager txManager = txManagerProvider.get(web3j);
        String encoded = FunctionEncoder.encode(function);

        Optional<String> preflightFailure = simulateAndDecodeFailure(web3j, credentials.getAddress(), encoded);
        if (preflightFailure.isPresent()) {
            return new ExecutionResult(false, null, null, null, null, preflightFailure.get());
        }

        BigInteger gasPriceWei = resolveGasPriceWei(web3j);

        EthSendTransaction tx = txManager.sendTransaction(gasPriceWei, gasLimit, contractAddress, encoded, BigInteger.ZERO);
        String txHash = tx.getTransactionHash();
        if (txHash == null) {
            String error = tx.getError() != null ? tx.getError().getMessage() : "tx_hash_missing";
            if (shouldRetryWithHigherGas(error)) {
                BigInteger bumpedGasPrice = bumpGasPrice(gasPriceWei);
                EthSendTransaction retry = txManager.sendTransaction(
                    bumpedGasPrice, gasLimit, contractAddress, encoded, BigInteger.ZERO
                );
                String retryHash = retry.getTransactionHash();
                if (retryHash != null) {
                    TransactionReceipt receipt = waitForReceipt(web3j, retryHash);
                    Long blockNumber = receipt.getBlockNumber() != null ? receipt.getBlockNumber().longValue() : null;
                    return new ExecutionResult(receipt.isStatusOK(), retryHash, blockNumber, null, null,
                        receipt.isStatusOK() ? null : inferRevertReason(receipt));
                }
            }
            return new ExecutionResult(false, null, null, null, null, error);
        }

        try {
            TransactionReceipt receipt = waitForReceipt(web3j, txHash);
            Long blockNumber = receipt.getBlockNumber() != null ? receipt.getBlockNumber().longValue() : null;
            return new ExecutionResult(receipt.isStatusOK(), txHash, blockNumber, null, null,
                receipt.isStatusOK() ? null : inferRevertReason(receipt));
        } catch (Exception ex) {
            log.warn("Failed to get tx receipt for {}: {}", txHash, ex.getMessage());
            return new ExecutionResult(false, txHash, null, null, null, "receipt_error: " + ex.getMessage());
        }
    }

    private String inferRevertReason(TransactionReceipt receipt) {
        if (receipt == null) {
            return "tx_reverted_status_unknown";
        }

        String status = receipt.getStatus() != null ? receipt.getStatus() : "unknown";
        if (receipt.getGasUsed() != null && gasLimit != null && receipt.getGasUsed().compareTo(gasLimit) >= 0) {
            return "tx_out_of_gas: gasUsed=" + receipt.getGasUsed() + " gasLimit=" + gasLimit + " status=" + status;
        }

        return "tx_reverted_status_" + status;
    }

    private Optional<String> validatePayloadHash(IntentRecord record, String action) {
        if (record == null || action == null || action.isBlank()) {
            return Optional.of("intent_record_incomplete");
        }

        boolean usesReservationPayload = "RESERVATION_REQUEST".equals(action)
            || "CANCEL_RESERVATION_REQUEST".equals(action);

        String declared = normalizeBytes32(record.getPayloadHash());
        if (declared == null) {
            return Optional.of("missing_payload_hash");
        }

        String computed = usesReservationPayload
            ? intentVerifier.computeReservationPayloadHash(record.getReservationPayload())
            : intentVerifier.computeActionPayloadHash(record.getActionPayload());
        String normalizedComputed = normalizeBytes32(computed);

        if (normalizedComputed == null) {
            return Optional.of("missing_payload_for_hash_validation");
        }
        if (!declared.equalsIgnoreCase(normalizedComputed)) {
            return Optional.of("payload_hash_mismatch: expected=" + normalizedComputed + " provided=" + declared);
        }
        return Optional.empty();
    }

    private Optional<String> simulateAndDecodeFailure(Web3j web3j, String from, String encodedData) {
        try {
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(from, contractAddress, encodedData),
                DefaultBlockParameterName.LATEST
            ).send();
            if (response == null) {
                return Optional.empty();
            }
            if (response.hasError()) {
                String msg = response.getError() != null ? response.getError().getMessage() : "unknown_eth_call_error";
                return Optional.of("preflight_revert: " + msg);
            }

            String value = response.getValue();
            if (value == null || value.isBlank() || "0x".equalsIgnoreCase(value)) {
                return Optional.empty();
            }

            String cleaned = Numeric.cleanHexPrefix(value);
            if (cleaned.length() < 8) {
                return Optional.of("preflight_revert_raw: " + value);
            }

            String selector = "0x" + cleaned.substring(0, 8).toLowerCase(Locale.ROOT);
            if ("0x08c379a0".equals(selector)) {
                String reason = decodeRevertString(value);
                return Optional.of(reason != null ? "preflight_revert: " + reason : "preflight_revert_error_string_decode_failed");
            }
            if ("0x4e487b71".equals(selector)) {
                String panicCode = decodePanicCode(cleaned);
                return Optional.of("preflight_panic: " + panicCode);
            }
            return Optional.of("preflight_custom_error_selector=" + selector);
        } catch (Exception ex) {
            return Optional.of("preflight_error: " + ex.getMessage());
        }
    }

    private String decodeRevertString(String revertData) {
        try {
            String cleaned = Numeric.cleanHexPrefix(revertData);
            // Error(string): selector(4) + offset(32) + strlen(32) + data(N)
            if (cleaned.length() < 8 + 64 + 64) {
                return null;
            }
            int lengthStart = 8 + 64;
            int lengthEnd = lengthStart + 64;
            BigInteger strLen = Numeric.toBigInt("0x" + cleaned.substring(lengthStart, lengthEnd));
            if (strLen.signum() < 0 || strLen.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0) {
                return null;
            }
            int charLen = strLen.intValue() * 2;
            int dataStart = lengthEnd;
            int dataEnd = dataStart + charLen;
            if (dataEnd > cleaned.length()) {
                return null;
            }
            byte[] bytes = Numeric.hexStringToByteArray("0x" + cleaned.substring(dataStart, dataEnd));
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String decodePanicCode(String cleanedHex) {
        try {
            if (cleanedHex.length() < 8 + 64) {
                return "unknown";
            }
            String codeHex = cleanedHex.substring(cleanedHex.length() - 64);
            BigInteger code = Numeric.toBigInt("0x" + codeHex);
            return "0x" + code.toString(16);
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    private TransactionReceipt waitForReceipt(Web3j web3j, String txHash) {
        return waitForReceipt(web3j, txHash, 40, 3000);
    }

    private TransactionReceipt waitForReceipt(Web3j web3j, String txHash, int maxAttempts, long sleepMs) {
        try {
            int attempts = 0;
            while (attempts < maxAttempts) {
                var response = web3j.ethGetTransactionReceipt(txHash).send();
                if (response.getTransactionReceipt().isPresent()) {
                    return response.getTransactionReceipt().get();
                }
                Thread.sleep(sleepMs);
                attempts++;
            }
            throw new RuntimeException("Transaction receipt not found after " + maxAttempts + " attempts");
        } catch (Exception e) {
            throw new RuntimeException("Failed to get tx receipt: " + e.getMessage(), e);
        }
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
            new Bytes32(toBytes32(payload.getPucHash())),
            assertion,
            new Uint256(payload.getLabId()),
            reservationKey,
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : ""),
            new Uint8(toUint8Value(payload.getResourceType()))
        );

        return Optional.of(new Function(
            "addLabWithIntent",
            List.of(new Bytes32(requestId), struct),
            List.of()
        ));
    }

    private Optional<Function> buildAddAndList(IntentRecord record) {
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
            new Bytes32(toBytes32(payload.getPucHash())),
            assertion,
            new Uint256(payload.getLabId()),
            reservationKey,
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : ""),
            new Uint8(toUint8Value(payload.getResourceType()))
        );

        return Optional.of(new Function(
            "addAndListLabWithIntent",
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
            new Bytes32(toBytes32(payload.getPucHash())),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : ""),
            new Uint8(toUint8Value(payload.getResourceType()))
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
            new Bytes32(toBytes32(payload.getPucHash())),
            assertion,
            new Uint256(payload.getLabId()),
            reservationKey,
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : ""),
            new Uint8(toUint8Value(payload.getResourceType()))
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
            new Bytes32(toBytes32(payload.getPucHash())),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : ""),
            new Uint8(toUint8Value(payload.getResourceType()))
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
            new Bytes32(toBytes32(payload.getPucHash())),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(payload.getLabId()),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Utf8String(payload.getUri() != null ? payload.getUri() : ""),
            new Uint96(payload.getPrice() != null ? payload.getPrice() : BigInteger.ZERO),
            new Uint96(payload.getMaxBatch() != null ? payload.getMaxBatch() : BigInteger.ZERO),
            new Utf8String(payload.getAccessURI() != null ? payload.getAccessURI() : ""),
            new Utf8String(payload.getAccessKey() != null ? payload.getAccessKey() : ""),
            new Utf8String(payload.getTokenURI() != null ? payload.getTokenURI() : ""),
            new Uint8(toUint8Value(payload.getResourceType()))
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

    private void postflightReleaseExpiredInstitutionalReservations(IntentRecord record, Credentials credentials) {
        ReservationIntentPayload payload = record.getReservationPayload();
        if (payload == null) {
            return;
        }
        if (payload.getExecutor() == null || payload.getExecutor().isBlank()) {
            return;
        }
        if (payload.getPuc() == null || payload.getPuc().isBlank()) {
            return;
        }
        if (payload.getLabId() == null) {
            return;
        }

        cleanupExecutor.submit(() -> {
            try {
                String pucHash = computePucHash(payload.getPuc());
                Optional<BigInteger> activeCountOpt = fetchInstitutionalUserActiveCount(
                    credentials.getAddress(),
                    payload.getExecutor(),
                    pucHash,
                    payload.getLabId()
                );
                if (activeCountOpt.isEmpty()) {
                    return;
                }
                BigInteger activeCount = activeCountOpt.get();
                BigInteger threshold = MAX_RESERVATIONS_PER_LAB_USER.subtract(PRE_RELEASE_THRESHOLD);
                if (activeCount.compareTo(threshold) < 0) {
                    return;
                }

                Function function = new Function(
                    "releaseInstitutionalExpiredReservations",
                    List.of(
                        new Address(payload.getExecutor()),
                        new Bytes32(toBytes32(pucHash)),
                        new Uint256(payload.getLabId()),
                        new Uint256(PRE_RELEASE_BATCH)
                    ),
                    List.of()
                );

                sendPreflight(function, credentials, "releaseInstitutionalExpiredReservations");
            } catch (Exception ex) {
                log.warn("Postflight release failed for provider {} labId {}: {}", payload.getExecutor(), payload.getLabId(), ex.getMessage());
            }
        });
    }

    @PreDestroy
    private void shutdownCleanupExecutor() {
        cleanupExecutor.shutdown();
    }

    private Optional<BigInteger> fetchInstitutionalUserActiveCount(
        String fromAddress,
        String provider,
        String pucHash,
        BigInteger labId
    ) {
        try {
            Web3j web3j = resolveWeb3j();
            Function fn = new Function(
                "getInstitutionalUserActiveCountByHash",
                List.of(new Address(provider), new Bytes32(toBytes32(pucHash)), new Uint256(labId)),
                List.of(new TypeReference<Uint256>() {})
            );
            String encoded = FunctionEncoder.encode(fn);
            var response = web3j.ethCall(
                Transaction.createEthCallTransaction(fromAddress, contractAddress, encoded),
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
            log.warn("Unable to fetch institutional active count for provider {}: {}", provider, ex.getMessage());
            return Optional.empty();
        }
    }

    private String computePucHash(String puc) {
        if (puc == null || puc.isBlank()) {
            return "0x" + "0".repeat(64);
        }
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return Numeric.toHexString(hash);
    }

    private void sendPreflight(Function function, Credentials credentials, String label) throws Exception {
        Web3j web3j = resolveWeb3j();
        TransactionManager txManager = txManagerProvider.get(web3j);
        String encoded = FunctionEncoder.encode(function);
        BigInteger gasPriceWei = resolveGasPriceWei(web3j);

        EthSendTransaction tx = txManager.sendTransaction(gasPriceWei, gasLimit, contractAddress, encoded, BigInteger.ZERO);
        String txHash = tx.getTransactionHash();
        if (txHash == null) {
            log.warn("Preflight {} tx hash missing: {}", label, tx.getError() != null ? tx.getError().getMessage() : "unknown");
            return;
        }

        TransactionReceipt receipt = waitForReceipt(web3j, txHash, 10, 2000);
        if (!receipt.isStatusOK()) {
            log.warn("Preflight {} failed with status {}", label, receipt.getStatus());
        } else {
            log.info("Preflight {} mined: {}", label, txHash);
        }
    }

    private BigInteger toWei(BigInteger gwei) {
        if (gwei == null) {
            return BigInteger.ZERO;
        }
        return org.web3j.utils.Convert.toWei(gwei.toString(), org.web3j.utils.Convert.Unit.GWEI).toBigInteger();
    }

    private BigInteger resolveGasPriceWei(Web3j web3j) {
        BigInteger fallback = toWei(defaultGasPriceGwei);
        BigInteger minWei = org.web3j.utils.Convert.toWei(
            gasPriceMinGwei != null ? gasPriceMinGwei : BigDecimal.ONE,
            org.web3j.utils.Convert.Unit.GWEI
        ).toBigInteger();
        try {
            var response = web3j.ethGasPrice().send();
            if (response != null && response.getGasPrice() != null) {
                BigDecimal baseWei = new BigDecimal(response.getGasPrice());
                BigDecimal multiplier = gasPriceMultiplier != null ? gasPriceMultiplier : BigDecimal.ONE;
                BigInteger dynamicWei = baseWei.multiply(multiplier).toBigInteger();
                BigInteger candidate = dynamicWei.max(fallback).max(minWei);
                return candidate;
            }
        } catch (Exception ex) {
            log.warn("Unable to fetch gas price; using default: {}", ex.getMessage());
        }
        return fallback.max(minWei);
    }

    private boolean shouldRetryWithHigherGas(String error) {
        if (error == null) {
            return false;
        }
        String lowered = error.toLowerCase(Locale.ROOT);
        return lowered.contains("underpriced")
            || lowered.contains("replacement transaction")
            || lowered.contains("nonce too low");
    }

    private BigInteger bumpGasPrice(BigInteger gasPriceWei) {
        if (gasPriceWei == null) {
            return BigInteger.ZERO;
        }
        return gasPriceWei.multiply(BigInteger.valueOf(12)).divide(BigInteger.TEN);
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

    private long toUint8Value(BigInteger value) {
        if (value == null) {
            return 0L;
        }
        if (value.signum() < 0 || value.compareTo(BigInteger.valueOf(255)) > 0) {
            throw new IllegalArgumentException("resourceType out of uint8 range: " + value);
        }
        return value.longValue();
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

    private String normalizeBytes32(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String clean = Numeric.cleanHexPrefix(value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
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
