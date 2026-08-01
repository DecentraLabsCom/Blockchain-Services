package decentralabs.blockchain.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.datatypes.Event;
import org.web3j.crypto.Hash;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class ContractEventAbiTest {

    @Test
    void reservationIntentProcessedTopicMatchesGeneratedContractAbi() throws Exception {
        JsonNode eventFromAbi = findReservationIntentProcessedEvent();
        String abiSignature = eventFromAbi.get("name").asText()
            + "("
            + StreamSupport.stream(eventFromAbi.get("inputs").spliterator(), false)
                .map(input -> input.get("type").asText())
                .reduce((left, right) -> left + "," + right)
                .orElse("")
            + ")";

        @SuppressWarnings("unchecked")
        Map<String, Event> definitions = (Map<String, Event>) ReflectionTestUtils.getField(
            ContractEventListenerConfig.class,
            "SUPPORTED_EVENTS"
        );

        assertThat(definitions).isNotNull();
        assertThat(EventEncoder.encode(definitions.get("ReservationIntentProcessed")))
            .isEqualTo(Hash.sha3String(abiSignature));
    }

    @Test
    void everySupportedListenerEventTopicMatchesSolidityAbiAndJavaDefinition() throws Exception {
        JsonNode abi = readDiamondAbi();
        Map<String, String> expectedSignatures = new LinkedHashMap<>();
        expectedSignatures.put("ReservationRequested", "ReservationRequested(address,uint256,uint256,uint256,bytes32)");
        expectedSignatures.put("ReservationConfirmed", "ReservationConfirmed(bytes32,uint256)");
        expectedSignatures.put("ReservationRequestDenied", "ReservationRequestDenied(bytes32,uint256,uint8)");
        expectedSignatures.put("ReservationRequestCanceled", "ReservationRequestCanceled(bytes32,uint256)");
        expectedSignatures.put("BookingCanceled", "BookingCanceled(bytes32,uint256)");
        expectedSignatures.put(
            "BookingCanceledByProvider",
            "BookingCanceledByProvider(bytes32,uint256,address,address,bytes32,uint96,uint8)"
        );
        expectedSignatures.put("ProviderAdded", "ProviderAdded(address,string,string,string)");
        expectedSignatures.put("LabIntentProcessed", "LabIntentProcessed(bytes32,uint256,string,address,bool,string)");
        expectedSignatures.put(
            "ReservationIntentProcessed",
            "ReservationIntentProcessed(bytes32,bytes32,string,bytes32,address,bool,string)"
        );
        expectedSignatures.put(
            "ProviderSettlementBatchInvalidated",
            "ProviderSettlementBatchInvalidated(bytes32,uint256,uint256,uint8,uint8,bytes32,address,uint64)"
        );
        expectedSignatures.put(
            "ProviderSettlementClaimInvalidated",
            "ProviderSettlementClaimInvalidated(bytes32,bytes32,uint256,uint256,uint8,uint8,bytes32,address,uint64)"
        );

        @SuppressWarnings("unchecked")
        Map<String, Event> definitions = (Map<String, Event>) ReflectionTestUtils.getField(
            ContractEventListenerConfig.class,
            "SUPPORTED_EVENTS"
        );
        assertThat(definitions).isNotNull();

        expectedSignatures.forEach((eventName, signature) -> {
            JsonNode eventFromAbi = StreamSupport.stream(abi.spliterator(), false)
                .filter(node -> "event".equals(node.path("type").asText()))
                .filter(node -> eventName.equals(node.path("name").asText()))
                .findFirst()
                .orElse(null);
            assertThat(eventFromAbi).as(eventName + " must be present in Diamond ABI").isNotNull();

            String abiSignature = eventFromAbi.get("name").asText()
                + "("
                + StreamSupport.stream(eventFromAbi.get("inputs").spliterator(), false)
                    .map(input -> input.get("type").asText())
                    .reduce((left, right) -> left + "," + right)
                    .orElse("")
                + ")";

            assertThat(Hash.sha3String(abiSignature)).as(eventName + " ABI topic")
                .isEqualTo(Hash.sha3String(signature));
            assertThat(EventEncoder.encode(definitions.get(eventName))).as(eventName + " Java topic")
                .isEqualTo(Hash.sha3String(signature));
        });
    }

    private JsonNode findReservationIntentProcessedEvent() throws Exception {
        JsonNode abi = readDiamondAbi();
        return StreamSupport.stream(abi.spliterator(), false)
            .filter(node -> "event".equals(node.path("type").asText()))
            .filter(node -> "ReservationIntentProcessed".equals(node.path("name").asText()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("ReservationIntentProcessed missing from ABI"));
    }

    private JsonNode readDiamondAbi() throws Exception {
        Path abiPath = Stream.of(
            Path.of("abi", "Diamond.json"),
            Path.of("Smart-Contracts", "abi", "Diamond.json"),
            Path.of("..", "..", "Smart-Contracts", "abi", "Diamond.json")
        )
            .filter(Files::isRegularFile)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Diamond ABI not found"));

        return new ObjectMapper().readTree(Files.readString(abiPath, StandardCharsets.UTF_8));
    }
}
