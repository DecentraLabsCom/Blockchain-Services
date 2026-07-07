package decentralabs.blockchain.service.intent;

import decentralabs.blockchain.service.wallet.WalletService;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicStruct;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.utils.Numeric;

@Service
@Slf4j
public class IntentRegistrationVerifier {

    private static final int STATE_NONE = 0;
    private static final int STATE_PENDING = 1;
    private static final int STATE_EXECUTED = 2;
    private static final int STATE_CANCELLED = 3;
    private static final int STATE_EXPIRED = 4;

    private final WalletService walletService;
    private final String contractAddress;

    @Value("${blockchain.network.active:sepolia}")
    private String activeNetwork;

    public IntentRegistrationVerifier(
        WalletService walletService,
        @Value("${contract.address}") String contractAddress
    ) {
        this.walletService = walletService;
        this.contractAddress = contractAddress;
    }

    public RegistrationVerificationResult verifyRegistration(IntentRecord record) {
        if (record == null || isBlank(record.getRequestId())) {
            return RegistrationVerificationResult.terminalFailure("intent_record_incomplete");
        }

        try {
            OnChainIntent onChain = fetchIntent(record.getRequestId());
            if (onChain.state() == STATE_NONE) {
                return RegistrationVerificationResult.retryable("intent_not_registered");
            }
            if (onChain.state() == STATE_EXECUTED) {
                return RegistrationVerificationResult.terminalFailure("intent_already_executed");
            }
            if (onChain.state() == STATE_CANCELLED) {
                return RegistrationVerificationResult.terminalFailure("intent_cancelled");
            }
            if (onChain.state() == STATE_EXPIRED) {
                return RegistrationVerificationResult.terminalFailure("intent_expired");
            }
            if (onChain.state() != STATE_PENDING) {
                return RegistrationVerificationResult.retryable("intent_state_unknown_" + onChain.state());
            }
            if (record.getExpiresAt() != null && record.getExpiresAt() <= Instant.now().getEpochSecond()) {
                return RegistrationVerificationResult.terminalFailure("expired");
            }

            String mismatch = firstMismatch(record, onChain);
            if (mismatch != null) {
                return RegistrationVerificationResult.terminalFailure(mismatch);
            }
            return RegistrationVerificationResult.success();
        } catch (Exception ex) {
            log.warn("Registration verification failed for {}: {}", record.getRequestId(), ex.getMessage());
            return RegistrationVerificationResult.retryable("registration_verification_error: " + ex.getMessage());
        }
    }

    private String firstMismatch(IntentRecord record, OnChainIntent onChain) {
        if (!equalsBytes32(record.getRequestId(), onChain.requestId())) {
            return "request_id_mismatch";
        }
        if (!equalsAddress(record.getSigner(), onChain.signer())) {
            return "signer_mismatch";
        }
        if (!equalsAddress(record.getExecutor(), onChain.executor())) {
            return "executor_mismatch";
        }
        if (!equalsInteger(record.getActionId(), onChain.action())) {
            return "action_mismatch";
        }
        if (!equalsBytes32(record.getPayloadHash(), onChain.payloadHash())) {
            return "payload_hash_mismatch";
        }
        if (!equalsNumber(record.getNonce(), onChain.nonce())) {
            return "nonce_mismatch";
        }
        if (!equalsNumber(record.getRequestedAt(), onChain.requestedAt())) {
            return "requested_at_mismatch";
        }
        if (!equalsNumber(record.getExpiresAt(), onChain.expiresAt())) {
            return "expires_at_mismatch";
        }
        return null;
    }

    protected OnChainIntent fetchIntent(String requestId) throws Exception {
        Web3j web3j = walletService.getWeb3jInstanceForNetwork(activeNetwork);
        Function function = new Function(
            "getIntent",
            List.of(new Bytes32(toBytes32(requestId))),
            List.of(new TypeReference<DynamicStruct>() { })
        );
        String encoded = FunctionEncoder.encode(function);
        EthCall response = web3j.ethCall(
            Transaction.createEthCallTransaction(null, contractAddress, encoded),
            DefaultBlockParameterName.LATEST
        ).send();
        if (response == null) {
            throw new IllegalStateException("empty_eth_call_response");
        }
        if (response.hasError()) {
            String message = response.getError() != null ? response.getError().getMessage() : "unknown_eth_call_error";
            throw new IllegalStateException(message);
        }

        var decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
        if (decoded.isEmpty() || !(decoded.get(0) instanceof DynamicStruct struct)) {
            throw new IllegalStateException("getIntent_decode_failed");
        }
        var values = struct.getValue();
        if (values.size() < 9) {
            throw new IllegalStateException("getIntent_tuple_incomplete");
        }

        return new OnChainIntent(
            toHex32((Bytes32) values.get(0)),
            ((Address) values.get(1)).getValue(),
            ((Address) values.get(2)).getValue(),
            ((Uint8) values.get(3)).getValue().intValue(),
            toHex32((Bytes32) values.get(4)),
            ((Uint256) values.get(5)).getValue(),
            ((Uint64) values.get(6)).getValue(),
            ((Uint64) values.get(7)).getValue(),
            ((Uint8) values.get(8)).getValue().intValue()
        );
    }

    private String toHex32(Bytes32 value) {
        return Numeric.toHexString(value.getValue());
    }

    private boolean equalsAddress(String left, String right) {
        return normalizeAddress(left).equals(normalizeAddress(right));
    }

    private String normalizeAddress(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private boolean equalsBytes32(String left, String right) {
        String normalizedLeft = normalizeBytes32(left);
        String normalizedRight = normalizeBytes32(right);
        return normalizedLeft != null && normalizedLeft.equalsIgnoreCase(normalizedRight);
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
        return "0x" + clean.toLowerCase(Locale.ROOT);
    }

    private byte[] toBytes32(String hex) {
        byte[] raw = Numeric.hexStringToByteArray(normalizeBytes32(hex));
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

    private boolean equalsNumber(Number left, BigInteger right) {
        if (left == null || right == null) {
            return false;
        }
        return BigInteger.valueOf(left.longValue()).equals(right);
    }

    private boolean equalsInteger(Number left, Number right) {
        if (left == null || right == null) {
            return false;
        }
        return left.longValue() == right.longValue();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record OnChainIntent(
        String requestId,
        String signer,
        String executor,
        Integer action,
        String payloadHash,
        BigInteger nonce,
        BigInteger requestedAt,
        BigInteger expiresAt,
        Integer state
    ) {}

    public record RegistrationVerificationResult(boolean verified, boolean retryable, String reason) {
        public static RegistrationVerificationResult success() {
            return new RegistrationVerificationResult(true, false, null);
        }

        public static RegistrationVerificationResult retryable(String reason) {
            return new RegistrationVerificationResult(false, true, reason);
        }

        public static RegistrationVerificationResult terminalFailure(String reason) {
            return new RegistrationVerificationResult(false, false, reason);
        }
    }
}
