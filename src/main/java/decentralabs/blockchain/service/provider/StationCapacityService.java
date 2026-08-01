package decentralabs.blockchain.service.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Reads the execution capacity from the Lab Station that owns FMU execution.
 * The Station is the operational authority; the backend never maintains a
 * second configurable capacity value for provider decisions.
 */
@Service
@Slf4j
public class StationCapacityService {

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final URI capacityUri;
    private final String internalToken;
    private final boolean required;
    private final Duration requestTimeout;

    public StationCapacityService(
        ObjectMapper objectMapper,
        @Value("${fmu.station.base-url:}") String baseUrl,
        @Value("${fmu.station.internal-token:}") String internalToken,
        @Value("${fmu.station.request-timeout-ms:5000}") long requestTimeoutMs,
        @Value("${fmu.capacity.required:false}") boolean required
    ) {
        this.objectMapper = objectMapper;
        this.internalToken = internalToken == null ? "" : internalToken.trim();
        this.required = required;
        this.requestTimeout = Duration.ofMillis(Math.max(100, requestTimeoutMs));
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(this.requestTimeout)
            .build();
        this.capacityUri = resolveCapacityUri(baseUrl);
    }

    /**
     * Returns the Station's configured execution capacity.
     *
     * <p>When this integration is optional (consumer-only or local test
     * deployments), no configured Station means no additional restriction.
     * Provider deployments set {@code fmu.capacity.required=true}.</p>
     */
    public int requireCapacity() {
        if (capacityUri == null) {
            if (required) {
                throw new StationCapacityUnavailableException("Station capacity authority is not configured");
            }
            return Integer.MAX_VALUE;
        }

        HttpRequest.Builder request = HttpRequest.newBuilder(capacityUri)
            .timeout(requestTimeout)
            .header("Accept", "application/json")
            .GET();
        if (!internalToken.isBlank()) {
            request.header("X-Internal-Session-Token", internalToken);
        }

        try {
            HttpResponse<String> response = httpClient.send(
                request.build(),
                HttpResponse.BodyHandlers.ofString()
            );
            if (response.statusCode() != 200) {
                throw new StationCapacityUnavailableException(
                    "Station capacity authority returned HTTP " + response.statusCode()
                );
            }
            JsonNode body = objectMapper.readTree(response.body());
            int capacity = body == null ? 0 : body.path("capacity").asInt(0);
            if (capacity <= 0) {
                throw new StationCapacityUnavailableException("Station returned an invalid execution capacity");
            }
            return capacity;
        } catch (StationCapacityUnavailableException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Unable to read FMU capacity from Station: {}", ex.getMessage());
            throw new StationCapacityUnavailableException("Unable to read FMU capacity from Station", ex);
        }
    }

    public void validateDeclaredCapacity(Integer declaredCapacity) {
        if (declaredCapacity == null) {
            throw new IllegalArgumentException("maxConcurrentUsers is required for FMU resources");
        }
        if (declaredCapacity <= 0) {
            throw new IllegalArgumentException("maxConcurrentUsers must be a positive integer");
        }
        int stationCapacity = requireCapacity();
        if (declaredCapacity > stationCapacity) {
            throw new IllegalArgumentException(
                "maxConcurrentUsers " + declaredCapacity
                    + " exceeds effective Station capacity " + stationCapacity
            );
        }
    }

    private URI resolveCapacityUri(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            return null;
        }
        try {
            URI base = URI.create(baseUrl.trim());
            if (base.getScheme() == null || base.getHost() == null) {
                throw new IllegalArgumentException("Station URL must include a scheme and host");
            }
            return URI.create(base.toString().replaceAll("/+$", "") + "/internal/fmu/capacity");
        } catch (Exception ex) {
            throw new IllegalStateException("Configured Station URL is invalid", ex);
        }
    }
}
