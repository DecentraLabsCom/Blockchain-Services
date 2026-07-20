package decentralabs.blockchain.service.labadmin;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Keeps lab content recoverable for a bounded period after the chain confirms
 * a deletion, while making the content unavailable immediately through the
 * gateway. The tombstone is the durable hand-off to garbage collection.
 */
@Service
@Slf4j
public class LabContentRetentionService {

    private static final String TOMBSTONE_FILE = ".tombstone.json";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${lab.content.base-path:/app/lab-content}")
    private String contentBasePath;

    @Value("${lab.content.retention:7d}")
    private Duration retention = Duration.ofDays(7);

    public void markDeleted(
        BigInteger labId,
        String metadataUri,
        String transactionHash
    ) throws IOException {
        markDeleted(labId, metadataUri, transactionHash, Instant.now());
    }

    void markDeleted(
        BigInteger labId,
        String metadataUri,
        String transactionHash,
        Instant deletedAt
    ) throws IOException {
        if (labId == null || labId.signum() <= 0) {
            throw new IllegalArgumentException("labId must be greater than zero");
        }
        Instant purgeAfter = deletedAt.plus(retention);
        Map<String, Object> tombstone = new LinkedHashMap<>();
        tombstone.put("labId", labId.toString());
        tombstone.put("metadataUri", metadataUri);
        tombstone.put("transactionHash", transactionHash);
        tombstone.put("deletedAt", deletedAt.toString());
        tombstone.put("purgeAfter", purgeAfter.toString());
        tombstone.put("status", "TOMBSTONED");

        Path root = contentRoot();
        Path tombstoneDir = root.resolve("tombstones").normalize();
        ensureWithinRoot(tombstoneDir);
        Files.createDirectories(tombstoneDir);
        writeJson(tombstoneDir.resolve("lab-" + labId + ".json"), tombstone);

        Optional<String> contentRelativePath = contentRelativePath(metadataUri);
        if (contentRelativePath.isEmpty()) {
            return;
        }

        Path contentDir = root.resolve(contentRelativePath.get()).normalize();
        ensureWithinRoot(contentDir);
        if (Files.isDirectory(contentDir)) {
            writeJson(contentDir.resolve(TOMBSTONE_FILE), tombstone);
        }
    }

    public boolean isTombstoned(String relativePath) throws IOException {
        Path root = contentRoot();
        Path normalized = root.resolve(relativePath == null ? "" : relativePath).normalize();
        ensureWithinRoot(normalized);
        Path relative = root.relativize(normalized);
        if (relative.getNameCount() > 0 && "tombstones".equals(relative.getName(0).toString())) {
            return true;
        }
        Path contentDir = contentDirectoryFor(normalized, root);
        return contentDir != null && Files.isRegularFile(contentDir.resolve(TOMBSTONE_FILE));
    }

    public void assertAvailable(String relativePath) throws IOException {
        if (isTombstoned(relativePath)) {
            throw new FileNotFoundException("Content not found");
        }
    }

    @Scheduled(fixedDelayString = "${lab.content.gc.interval-ms:3600000}")
    public void scheduledGarbageCollect() {
        try {
            garbageCollect(Instant.now());
        } catch (IOException ex) {
            log.warn("Lab content garbage collection failed: {}", ex.getMessage());
        }
    }

    void garbageCollect(Instant now) throws IOException {
        Path root = contentRoot();
        Path tombstoneDir = root.resolve("tombstones").normalize();
        ensureWithinRoot(tombstoneDir);
        if (!Files.isDirectory(tombstoneDir)) {
            return;
        }

        try (var stream = Files.list(tombstoneDir)) {
            for (Path tombstoneFile : stream.filter(Files::isRegularFile).toList()) {
                Map<?, ?> tombstone;
                try {
                    tombstone = objectMapper.readValue(tombstoneFile.toFile(), Map.class);
                } catch (Exception ex) {
                    log.warn("Skipping unreadable lab tombstone {}", tombstoneFile.getFileName());
                    continue;
                }
                try {
                    String purgeAfter = String.valueOf(tombstone.get("purgeAfter"));
                    if (now.isBefore(Instant.parse(purgeAfter))) {
                        continue;
                    }

                    String contentRelativePath = contentRelativePath(String.valueOf(tombstone.get("metadataUri")))
                        .orElse(null);
                    if (contentRelativePath != null) {
                        Path contentDir = root.resolve(contentRelativePath).normalize();
                        ensureWithinRoot(contentDir);
                        deleteTree(contentDir);
                    }
                    Files.deleteIfExists(tombstoneFile);
                } catch (RuntimeException ex) {
                    log.warn("Skipping invalid lab tombstone {}", tombstoneFile.getFileName());
                }
            }
        }
    }

    private Optional<String> contentRelativePath(String metadataUri) {
        if (metadataUri == null || metadataUri.isBlank()) {
            return Optional.empty();
        }
        try {
            String path = URI.create(metadataUri).getPath();
            String marker = "/lab-content/";
            int markerIndex = path.indexOf(marker);
            String relative = markerIndex >= 0
                ? path.substring(markerIndex + marker.length())
                : path.startsWith("content/") ? path.substring(1) : "";
            Path normalized = Path.of(relative).normalize();
            if (normalized.isAbsolute() || normalized.getNameCount() < 3
                || !"content".equals(normalized.getName(0).toString())
                || !"metadata.json".equals(normalized.getFileName().toString())) {
                return Optional.empty();
            }
            return Optional.of(normalized.getName(0) + "/" + normalized.getName(1));
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
    }

    private Path contentDirectoryFor(Path path, Path root) {
        Path relative = root.relativize(path);
        if (relative.getNameCount() < 2 || !"content".equals(relative.getName(0).toString())) {
            return null;
        }
        return root.resolve(relative.getName(0).toString()).resolve(relative.getName(1).toString()).normalize();
    }

    private void writeJson(Path target, Map<String, Object> value) throws IOException {
        ensureWithinRoot(target);
        Files.writeString(target, objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(value));
    }

    private Path contentRoot() throws IOException {
        Path root = Path.of(contentBasePath).toAbsolutePath().normalize();
        Files.createDirectories(root);
        return root;
    }

    private void ensureWithinRoot(Path path) throws IOException {
        Path root = Path.of(contentBasePath).toAbsolutePath().normalize();
        if (!path.toAbsolutePath().normalize().startsWith(root)) {
            throw new IllegalArgumentException("Invalid content path");
        }
    }

    private void deleteTree(Path target) throws IOException {
        if (!Files.exists(target)) {
            return;
        }
        try (var stream = Files.walk(target)) {
            for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
