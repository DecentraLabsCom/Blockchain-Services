package decentralabs.blockchain.service.health;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.health.LabMetadata;
import decentralabs.blockchain.dto.health.MaintenanceWindow;
import decentralabs.blockchain.dto.health.TimeRange;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Service for fetching and parsing lab metadata including availability configuration
 */
@Service
@Slf4j
public class LabMetadataService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${lab.metadata.cache.enabled:true}")
    private boolean cacheEnabled;

    public LabMetadataService() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Fetches lab metadata from URL or local file path
     */
    @Cacheable(value = "labMetadata", key = "#metadataUri", condition = "#root.target.cacheEnabled")
    public LabMetadata getLabMetadata(String metadataUri) {
        try {
            log.debug("Fetching lab metadata from: {}", metadataUri);

            String jsonContent;
            if (metadataUri.startsWith("http")) {
                jsonContent = restTemplate.getForObject(metadataUri, String.class);
            } else {
                // Assume local file path
                java.nio.file.Path path = java.nio.file.Paths.get(metadataUri);
                jsonContent = java.nio.file.Files.readString(path);
            }

            JsonNode rootNode = objectMapper.readTree(jsonContent);
            return parseLabMetadata(rootNode);

        } catch (Exception e) {
            log.error("Failed to fetch/parse lab metadata from {}: {}", metadataUri, e.getMessage());
            throw new RuntimeException("Unable to load lab metadata", e);
        }
    }

    private LabMetadata parseLabMetadata(JsonNode rootNode) {
        LabMetadata.LabMetadataBuilder builder = LabMetadata.builder()
            .name(rootNode.get("name").asText())
            .description(rootNode.get("description").asText())
            .image(rootNode.get("image").asText());

        // Parse attributes
        JsonNode attributesNode = rootNode.get("attributes");
        if (attributesNode != null && attributesNode.isArray()) {
            for (JsonNode attr : attributesNode) {
                String traitType = attr.get("trait_type").asText();
                JsonNode valueNode = attr.get("value");

                switch (traitType) {
                    case "Available Days" -> builder.availableDays(parseDaysOfWeek(valueNode));
                    case "Available Hours" -> builder.availableHours(parseTimeRange(valueNode));
                    case "Max Concurrent Users" -> builder.maxConcurrentUsers(valueNode.asInt());
                    case "Unavailable Windows" -> builder.unavailableWindows(parseUnavailableWindows(valueNode));
                    // ... other existing attributes
                }
            }
        }

        return builder.build();
    }

    private List<DayOfWeek> parseDaysOfWeek(JsonNode node) {
        if (node.isArray()) {
            return StreamSupport.stream(node.spliterator(), false)
                .map(JsonNode::asText)
                .map(day -> DayOfWeek.valueOf(day.toUpperCase()))
                .collect(Collectors.toList());
        }
        return List.of();
    }

    private TimeRange parseTimeRange(JsonNode node) {
        if (node.isObject()) {
            LocalTime start = LocalTime.parse(node.get("start").asText());
            LocalTime end = LocalTime.parse(node.get("end").asText());
            return new TimeRange(start, end);
        }
        return null;
    }

    /**
     * Parses the "Unavailable Windows" trait from the JSON metadata.
     * This method converts the JSON array of unavailable windows into a list of MaintenanceWindow objects.
     *
     * @param node The JSON node containing the unavailable windows array
     * @return List of MaintenanceWindow objects representing unavailable periods
     */
    private List<MaintenanceWindow> parseUnavailableWindows(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }

        List<MaintenanceWindow> windows = new ArrayList<>();
        for (JsonNode windowNode : node) {
            LocalDateTime start = parseIsoDateTime(windowNode.get("start"));
            LocalDateTime end = parseIsoDateTime(windowNode.get("end"));

            if (start == null || end == null) {
                log.warn("Skipping malformed unavailable window entry: {}", windowNode);
                continue;
            }

            String reason = windowNode.hasNonNull("reason")
                ? windowNode.get("reason").asText()
                : "maintenance window";

            windows.add(MaintenanceWindow.builder()
                .start(start)
                .end(end)
                .reason(reason)
                .build());
        }
        return windows;
    }

    private LocalDateTime parseIsoDateTime(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        String value = node.asText();
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            Instant instant = Instant.parse(value);
            return LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
        } catch (DateTimeParseException ex) {
            log.warn("Unable to parse datetime value {}: {}", value, ex.getMessage());
            return null;
        }
    }

    /**
     * Validates if a reservation request is within lab availability
     */
    public void validateAvailability(LabMetadata metadata, LocalDateTime startTime, LocalDateTime endTime, int userCount) {
        Objects.requireNonNull(metadata, "Lab metadata is required");
        if (startTime == null || endTime == null) {
            throw new IllegalArgumentException("Reservation start/end time is missing");
        }
        if (!endTime.isAfter(startTime)) {
            throw new IllegalArgumentException("Reservation end time must be after start time");
        }

        DayOfWeek dayOfWeek = startTime.getDayOfWeek();
        LocalTime startTimeOfDay = startTime.toLocalTime();
        LocalTime endTimeOfDay = endTime.toLocalTime();

        // Check available days
        if (metadata.getAvailableDays() != null
            && !metadata.getAvailableDays().isEmpty()
            && !metadata.getAvailableDays().contains(dayOfWeek)) {
            throw new IllegalArgumentException("Lab not available on " + dayOfWeek);
        }

        // Check available hours
        if (metadata.getAvailableHours() != null) {
            TimeRange available = metadata.getAvailableHours();
            if (startTimeOfDay.isBefore(available.getStart()) || endTimeOfDay.isAfter(available.getEnd())) {
                throw new IllegalArgumentException("Reservation time outside available hours");
            }
        }

        // Check concurrent users
        if (metadata.getMaxConcurrentUsers() != null
            && metadata.getMaxConcurrentUsers() > 0
            && userCount > metadata.getMaxConcurrentUsers()) {
            throw new IllegalArgumentException("Too many concurrent users requested");
        }

        List<MaintenanceWindow> windows = metadata.getUnavailableWindows();
        if (windows != null && !windows.isEmpty()) {
            for (MaintenanceWindow window : windows) {
                if (window.getStart() == null || window.getEnd() == null) {
                    continue;
                }
                boolean overlaps =
                    !endTime.isBefore(window.getStart()) && !startTime.isAfter(window.getEnd());
                if (overlaps) {
                    throw new IllegalArgumentException(
                        "Lab unavailable due to maintenance: " + window.getReason()
                    );
                }
            }
        }
    }
}
