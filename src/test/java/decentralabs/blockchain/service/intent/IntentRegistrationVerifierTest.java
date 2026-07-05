package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;

import decentralabs.blockchain.service.intent.IntentRegistrationVerifier.OnChainIntent;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

class IntentRegistrationVerifierTest {
    private static final String CONTRACT = "0x0000000000000000000000000000000000000001";
    private static final String INTENT_REGISTERED_TOPIC = EventEncoder.encode(new Event(
        "IntentRegistered",
        List.of(
            new TypeReference<Bytes32>(true) { },
            new TypeReference<Address>(true) { },
            new TypeReference<Uint8>() { },
            new TypeReference<Bytes32>() { }
        )
    ));

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
    void verifiesRegistrationReceiptEventBeforeOnChainState() {
        IntentRecord record = validRecord();
        record.setRegistrationTxHash("0xabc");
        TransactionReceipt receipt = receipt(record, true, true);
        IntentRegistrationVerifier verifier = verifier(onChain(record, 1), receipt);

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isTrue();
        assertThat(record.getRegistrationBlockNumber()).isEqualTo(123L);
    }

    @Test
    void rejectsFailedRegistrationReceipt() {
        IntentRecord record = validRecord();
        record.setRegistrationTxHash("0xabc");
        TransactionReceipt receipt = receipt(record, false, true);
        IntentRegistrationVerifier verifier = verifier(onChain(record, 1), receipt);

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("registration_tx_failed:0x0");
    }

    @Test
    void rejectsRegistrationReceiptWithoutMatchingEvent() {
        IntentRecord record = validRecord();
        record.setRegistrationTxHash("0xabc");
        TransactionReceipt receipt = receipt(record, true, false);
        IntentRegistrationVerifier verifier = verifier(onChain(record, 1), receipt);

        var result = verifier.verifyRegistration(record);

        assertThat(result.verified()).isFalse();
        assertThat(result.retryable()).isFalse();
        assertThat(result.reason()).isEqualTo("registration_event_mismatch");
    }

    private IntentRegistrationVerifier verifier(OnChainIntent onChain) {
        return verifier(onChain, null);
    }

    private IntentRegistrationVerifier verifier(OnChainIntent onChain, TransactionReceipt receipt) {
        return new IntentRegistrationVerifier(null, CONTRACT) {
            @Override
            protected OnChainIntent fetchIntent(String requestId) {
                return onChain;
            }

            @Override
            protected TransactionReceipt fetchReceipt(String txHash) {
                return receipt;
            }
        };
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

    private TransactionReceipt receipt(IntentRecord record, boolean statusOk, boolean matchingEvent) {
        TransactionReceipt receipt = new TransactionReceipt();
        receipt.setStatus(statusOk ? "0x1" : "0x0");
        receipt.setTo(CONTRACT);
        receipt.setBlockNumber("0x7b");
        Log event = new Log();
        event.setTopics(List.of(
            INTENT_REGISTERED_TOPIC,
            record.getRequestId(),
            addressTopic(record.getSigner())
        ));
        String action = leftPadHex(Integer.toHexString(record.getActionId()), 64);
        String payloadHash = matchingEvent
            ? record.getPayloadHash().substring(2)
            : "9".repeat(64);
        event.setData("0x" + action + payloadHash);
        receipt.setLogs(List.of(event));
        return receipt;
    }

    private String addressTopic(String address) {
        return "0x" + "0".repeat(24) + address.substring(2).toLowerCase();
    }

    private String leftPadHex(String value, int length) {
        return "0".repeat(Math.max(0, length - value.length())) + value;
    }
}
