package decentralabs.blockchain.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** Trusted, provider-configured limits copied into FMU session-ticket claims. */
@Component
@ConfigurationProperties(prefix = "auth.fmu.session-ticket")
public class FmuSessionTicketProperties {

    private static final int PLATFORM_MAX_INPUT_UPDATES_PER_WINDOW = 10_000;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private String maxInputUpdatesPerWindowByLabJson = "{}";
    private Map<String, Integer> maxInputUpdatesPerWindowByLab = Map.of();

    public String getMaxInputUpdatesPerWindowByLabJson() {
        return maxInputUpdatesPerWindowByLabJson;
    }

    public void setMaxInputUpdatesPerWindowByLabJson(String value) {
        this.maxInputUpdatesPerWindowByLabJson = value;
    }

    public Integer maxInputUpdatesPerWindowForLab(String labId) {
        return maxInputUpdatesPerWindowByLab.get(labId);
    }

    @PostConstruct
    public void validate() {
        final JsonNode configured;
        try {
            configured = objectMapper.readTree(maxInputUpdatesPerWindowByLabJson);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException(
                "auth.fmu.session-ticket.max-input-updates-per-window-by-lab-json must be a JSON object",
                exception
            );
        }
        if (configured == null || !configured.isObject()) {
            throw new IllegalStateException(
                "auth.fmu.session-ticket.max-input-updates-per-window-by-lab-json must be a JSON object"
            );
        }

        Map<String, Integer> validated = new TreeMap<>();
        for (Map.Entry<String, JsonNode> entry : configured.properties()) {
            String labId = entry.getKey();
            JsonNode maximumNode = entry.getValue();
            if (labId == null || !labId.matches("(?:0|[1-9][0-9]*)")) {
                throw new IllegalStateException("FMU input-update policy keys must be canonical numeric lab IDs");
            }
            if (!maximumNode.isIntegralNumber() || !maximumNode.canConvertToInt()) {
                throw new IllegalStateException("FMU maxInputUpdatesPerWindow values must be integers");
            }
            int maximum = maximumNode.intValue();
            if (maximum < 1 || maximum > PLATFORM_MAX_INPUT_UPDATES_PER_WINDOW) {
                throw new IllegalStateException(
                    "FMU maxInputUpdatesPerWindow must be between 1 and "
                        + PLATFORM_MAX_INPUT_UPDATES_PER_WINDOW
                );
            }
            validated.put(labId, maximum);
        }
        maxInputUpdatesPerWindowByLab = Map.copyOf(validated);
    }
}
