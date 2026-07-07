package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;

import decentralabs.blockchain.contract.Diamond.IntentMetaStruct;
import decentralabs.blockchain.service.intent.IntentRegistrationVerifier.OnChainIntent;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.utils.Numeric;
import org.junit.jupiter.api.Test;

class IntentRegistrationVerifierTest {

    @Test
    void verifiesPendingIntentWhenMetadataMatches() {
        IntentRecord record = validRecord();
        IntentRegistrationVerifier verifier = verifier(onChain(record, 1));

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isTrue();
    }

    @Test
    void returnsRetryableWhenIntentIsNotRegistered() {
        IntentRecord record = validRecord();
        IntentRegistrationVerifier verifier = verifier(onChain(record, 0));

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isTrue();
        assertThat(result.reason()).isEqualTo("intent_not_registered");
    }

    @Test
    void rejectsPayloadHashMismatch() {
        IntentRecord record = validRecord();
        OnChainIntent onChain = new OnChainIntent(
            record.getRequestId(),
            record.getSigner(),
            record.getExecutor(),
            record.getActionId(),
            "0x" + "9".repeat(64),
            BigInteger.valueOf(record.getNonce()),
            BigInteger.valueOf(record.getRequestedAt()),
            BigInteger.valueOf(record.getExpiresAt()),
            1
        );
        IntentRegistrationVerifier verifier = verifier(onChain);

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("payload_hash_mismatch");
    }

    @Test
    void rejectsExecutorMismatch() {
        IntentRecord record = validRecord();
        OnChainIntent onChain = new OnChainIntent(
            record.getRequestId(),
            record.getSigner(),
            "0x00000000000000000000000000000000000000ff",
            record.getActionId(),
            record.getPayloadHash(),
            BigInteger.valueOf(record.getNonce()),
            BigInteger.valueOf(record.getRequestedAt()),
            BigInteger.valueOf(record.getExpiresAt()),
            1
        );
        IntentRegistrationVerifier verifier = verifier(onChain);

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("executor_mismatch");
    }

    @Test
    void rejectsExpiredAuthorizedIntent() {
        IntentRecord record = validRecord();
        record.setExpiresAt(Instant.now().minusSeconds(1).getEpochSecond());
        IntentRegistrationVerifier verifier = verifier(onChain(record, 1));

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("expired");
    }

    @Test
    void rejectsAlreadyExecutedOnChainIntent() {
        IntentRecord record = validRecord();
        IntentRegistrationVerifier verifier = verifier(onChain(record, 2));

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("intent_already_executed");
    }

    @Test
    void rejectsCancelledOnChainIntent() {
        IntentRecord record = validRecord();
        IntentRegistrationVerifier verifier = verifier(onChain(record, 3));

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("intent_cancelled");
    }

    @Test
    void decodesGetIntentTupleWithTypedStruct() {
        IntentRecord record = validRecord();
        IntentMetaStruct encodedStruct = new IntentMetaStruct(
            new Bytes32(Numeric.hexStringToByteArray(record.getRequestId())),
            new Address(record.getSigner()),
            new Address(record.getExecutor()),
            new Uint8(record.getActionId()),
            new Bytes32(Numeric.hexStringToByteArray(record.getPayloadHash())),
            new Uint256(BigInteger.valueOf(record.getNonce())),
            new Uint64(BigInteger.valueOf(record.getRequestedAt())),
            new Uint64(BigInteger.valueOf(record.getExpiresAt())),
            new Uint8(1)
        );

        var outputParameters = intentMetaOutputParameters();

        var decoded = FunctionReturnDecoder.decode(
            "0x" + TypeEncoder.encode(encodedStruct),
            outputParameters
        );

        assertThat(decoded).hasSize(1);
        assertThat(decoded.get(0)).isInstanceOf(IntentMetaStruct.class);
        IntentMetaStruct struct = (IntentMetaStruct) decoded.get(0);
        assertThat(Numeric.toHexString(struct.requestId.getValue())).isEqualToIgnoringCase(record.getRequestId());
        assertThat(struct.executor.getValue()).isEqualToIgnoringCase(record.getExecutor());
        assertThat(Numeric.toHexString(struct.payloadHash.getValue())).isEqualToIgnoringCase(record.getPayloadHash());
        assertThat(struct.state.getValue()).isEqualTo(BigInteger.ONE);
    }

    private IntentRegistrationVerifier verifier(OnChainIntent onChain) {
        return new IntentRegistrationVerifier(null, "0x0000000000000000000000000000000000000001") {
            @Override
            protected OnChainIntent fetchIntent(String requestId) {
                return onChain;
            }
        };
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private List<TypeReference<Type>> intentMetaOutputParameters() {
        return (List<TypeReference<Type>>) (List<?>) List.of(new TypeReference<IntentMetaStruct>() { });
    }

    private IntentRecord validRecord() {
        IntentRecord record = new IntentRecord(
            "0x" + "1".repeat(64),
            "RESERVATION_REQUEST",
            "0x00000000000000000000000000000000000000aa"
        );
        record.setSigner("0x00000000000000000000000000000000000000aa");
        record.setExecutor("0x00000000000000000000000000000000000000bb");
        record.setActionId(8);
        record.setPayloadHash("0x" + "2".repeat(64));
        record.setNonce(7L);
        record.setRequestedAt(Instant.now().minusSeconds(5).getEpochSecond());
        record.setExpiresAt(Instant.now().plusSeconds(300).getEpochSecond());
        return record;
    }

    private OnChainIntent onChain(IntentRecord record, int state) {
        return new OnChainIntent(
            record.getRequestId(),
            record.getSigner(),
            record.getExecutor(),
            record.getActionId(),
            record.getPayloadHash(),
            BigInteger.valueOf(record.getNonce()),
            BigInteger.valueOf(record.getRequestedAt()),
            BigInteger.valueOf(record.getExpiresAt()),
            state
        );
    }
}
