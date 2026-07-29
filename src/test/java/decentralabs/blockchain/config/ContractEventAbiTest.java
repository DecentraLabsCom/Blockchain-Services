package decentralabs.blockchain.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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

    private JsonNode findReservationIntentProcessedEvent() throws Exception {
        Path abiPath = Stream.of(
            Path.of("abi", "Diamond.json"),
            Path.of("Smart-Contracts", "abi", "Diamond.json"),
            Path.of("..", "..", "Smart-Contracts", "abi", "Diamond.json")
        )
            .filter(Files::isRegularFile)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Diamond ABI not found"));

        JsonNode abi = new ObjectMapper().readTree(Files.readString(abiPath, StandardCharsets.UTF_8));
        return StreamSupport.stream(abi.spliterator(), false)
            .filter(node -> "event".equals(node.path("type").asText()))
            .filter(node -> "ReservationIntentProcessed".equals(node.path("name").asText()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("ReservationIntentProcessed missing from ABI"));
    }
}
