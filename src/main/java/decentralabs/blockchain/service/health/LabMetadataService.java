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
import java.time.ZoneId;
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

                switch (traitType.trim().toLowerCase()) {
                    case "category" -> builder.category(parseString(valueNode));
                    case "keywords" -> builder.keywords(parseStringList(valueNode));
                    case "timeslots" -> builder.timeSlots(parseIntegerList(valueNode));
                    case "opens" -> builder.opens(parseEpochSeconds(valueNode));
                    case "closes" -> builder.closes(parseEpochSeconds(valueNode));
                    case "availabledays" -> builder.availableDays(parseDaysOfWeek(valueNode));
                    case "availablehours" -> builder.availableHours(parseTimeRange(valueNode));
                    case "maxconcurrentusers" -> builder.maxConcurrentUsers(valueNode.asInt());
                    case "unavailablewindows" -> builder.unavailableWindows(parseUnavailableWindows(valueNode));
                    case "timezone" -> builder.timezone(parseString(valueNode));
                    case "docs" -> builder.documentation(parseStringList(valueNode));
                    case "additionalimages" -> builder.additionalImages(parseStringList(valueNode));
                    // Backwards compatibility with older casing
                    case "available days" -> builder.availableDays(parseDaysOfWeek(valueNode));
                    case "available hours" -> builder.availableHours(parseTimeRange(valueNode));
                    case "max concurrent users" -> builder.maxConcurrentUsers(valueNode.asInt());
                    case "unavailable windows" -> builder.unavailableWindows(parseUnavailableWindows(valueNode));
                }
            }
        }

        return builder.build();
    }

    private String parseString(JsonNode node) {
        return node != null && !node.isNull() ? node.asText() : null;
    }

    private Long parseEpochSeconds(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isNumber()) {
            return node.asLong();
        }
        try {
            return Long.parseLong(node.asText());
        } catch (NumberFormatException ex) {
            log.warn("Unable to parse epoch seconds from {}", node);
            return null;
        }
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

    private List<Integer> parseIntegerList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        List<Integer> list = new ArrayList<>();
        for (JsonNode item : node) {
            try {
                list.add(item.asInt());
            } catch (Exception ex) {
                log.warn("Skipping non-integer value in list: {}", item);
            }
        }
        return list;
    }

    private List<String> parseStringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        List<String> list = new ArrayList<>();
        for (JsonNode item : node) {
            if (item != null && !item.isNull()) {
                list.add(item.asText());
            }
        }
        return list;
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
            Instant start = parseEpochOrIso(windowNode.get("startUnix"), windowNode.get("start"));
            Instant end = parseEpochOrIso(windowNode.get("endUnix"), windowNode.get("end"));

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

    private Instant parseEpochOrIso(JsonNode epochNode, JsonNode isoNode) {
        if (epochNode != null && !epochNode.isNull()) {
            try {
                return Instant.ofEpochSecond(epochNode.asLong());
            } catch (Exception ex) {
                log.warn("Unable to parse epoch seconds from {}: {}", epochNode, ex.getMessage());
            }
        }
        if (isoNode == null || isoNode.isNull()) {
            return null;
        }
        String value = isoNode.asText();
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ex) {
            log.warn("Unable to parse datetime value {}: {}", value, ex.getMessage());
            return null;
        }
    }

    /**
     * Validates if a reservation request is within lab availability
     */
    public void validateAvailability(
        LabMetadata metadata,
        Instant startInstantUtc,
        Instant endInstantUtc,
        int userCount
    ) {
        Objects.requireNonNull(metadata, "Lab metadata is required");
        if (startInstantUtc == null || endInstantUtc == null) {
            throw new IllegalArgumentException("Reservation start/end time is missing");
        }
        if (!endInstantUtc.isAfter(startInstantUtc)) {
            throw new IllegalArgumentException("Reservation end time must be after start time");
        }

        ZoneId zone = resolveZone(metadata.getTimezone());
        LocalDateTime startTime = LocalDateTime.ofInstant(startInstantUtc, zone);
        LocalDateTime endTime = LocalDateTime.ofInstant(endInstantUtc, zone);
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

        // Check opens/closes (epoch seconds, inclusive)
        if (metadata.getOpens() != null) {
            Instant opens = Instant.ofEpochSecond(metadata.getOpens());
            if (startInstantUtc.isBefore(opens)) {
                throw new IllegalArgumentException("Reservation starts before lab opens");
            }
        }
        if (metadata.getCloses() != null) {
            Instant closes = Instant.ofEpochSecond(metadata.getCloses());
            if (endInstantUtc.isAfter(closes)) {
                throw new IllegalArgumentException("Reservation ends after lab closes");
            }
        }

        // Check time slots (duration minutes must match one allowed)
        if (metadata.getTimeSlots() != null && !metadata.getTimeSlots().isEmpty()) {
            long durationMinutes = java.time.Duration.between(startInstantUtc, endInstantUtc).toMinutes();
            if (durationMinutes <= 0 || metadata.getTimeSlots().stream().noneMatch(slot -> slot == durationMinutes)) {
                throw new IllegalArgumentException("Reservation duration not allowed by timeSlots");
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
                    !endInstantUtc.isBefore(window.getStart()) && !startInstantUtc.isAfter(window.getEnd());
                if (overlaps) {
                    throw new IllegalArgumentException(
                        "Lab unavailable due to maintenance: " + window.getReason()
                    );
                }
            }
        }
    }

    private ZoneId resolveZone(String timezone) {
        if (timezone == null || timezone.isBlank()) {
            return ZoneOffset.UTC;
        }
        try {
            return ZoneId.of(timezone);
        } catch (Exception ex) {
            log.warn("Invalid timezone {}. Falling back to UTC.", timezone);
            return ZoneOffset.UTC;
        }
    }
}
