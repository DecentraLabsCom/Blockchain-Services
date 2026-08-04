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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
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
    private static final String PENDING_TOMBSTONE = "PENDING_TOMBSTONE";
    private static final String PROCESSING = "PROCESSING";
    private static final String TOMBSTONED = "TOMBSTONED";
    private static final String PURGED = "PURGED";
    private static final String CANCELLED = "CANCELLED";
    private static final long PROCESSING_LEASE_SECONDS = 15 * 60;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JdbcTemplate jdbcTemplate;
    private final String workerId = UUID.randomUUID().toString();

    /** Kept for focused filesystem tests that do not start a Spring context. */
    public LabContentRetentionService() {
        this.jdbcTemplate = null;
    }

    @Autowired
    public LabContentRetentionService(ObjectProvider<JdbcTemplate> jdbcTemplateProvider) {
        this.jdbcTemplate = jdbcTemplateProvider.getIfAvailable();
    }

    @Value("${lab.content.base-path:/app/lab-content}")
    private String contentBasePath;

    @Value("${lab.content.retention:7d}")
    private Duration retention = Duration.ofDays(7);

    @Value("${lab.content.deletion.outbox.batch-size:25}")
    private int deletionOutboxBatchSize = 25;

    @Value("${lab.content.deletion.outbox.retry-base-delay-ms:30000}")
    private long deletionOutboxRetryBaseDelayMs = 30_000L;

    @Value("${lab.content.deletion.outbox.retry-max-delay-ms:900000}")
    private long deletionOutboxRetryMaxDelayMs = 900_000L;

    /**
     * Reserves the off-chain deletion before the transaction is broadcast.
     * Without this durable reservation a successful receipt could leave the
     * content path unblocked if the process dies before writing its tombstone.
     */
    public void prepareDeletion(BigInteger labId, String metadataUri) {
        validateDeletion(labId);
        if (metadataUri == null || metadataUri.isBlank()) {
            throw new IllegalStateException("Metadata URI is unavailable for durable lab deletion");
        }
        if (jdbcTemplate == null) {
            throw new IllegalStateException("Durable lab deletion outbox is unavailable");
        }
        try {
            upsertOutbox(labId, metadataUri, null, PENDING_TOMBSTONE, null);
        } catch (DataAccessException ex) {
            throw new IllegalStateException("Durable lab deletion outbox is unavailable", ex);
        }
    }

    /**
     * Completes a prepared deletion. Filesystem failures are deliberately
     * propagated to the caller, while the durable row remains pending for the
     * scheduled worker and the LabDeleted event handler.
     */
    public void completeDeletion(
        BigInteger labId,
        String metadataUri,
        String transactionHash
    ) throws IOException {
        markDeleted(labId, metadataUri, transactionHash, Instant.now(), true);
    }

    public void markDeleted(
        BigInteger labId,
        String metadataUri,
        String transactionHash
    ) throws IOException {
        markDeleted(labId, metadataUri, transactionHash, Instant.now(), jdbcTemplate != null);
    }

    void markDeleted(
        BigInteger labId,
        String metadataUri,
        String transactionHash,
        Instant deletedAt
    ) throws IOException {
        markDeleted(labId, metadataUri, transactionHash, deletedAt, jdbcTemplate != null);
    }

    private void markDeleted(
        BigInteger labId,
        String metadataUri,
        String transactionHash,
        Instant deletedAt,
        boolean persistOutbox
    ) throws IOException {
        if (labId == null || labId.signum() <= 0) {
            throw new IllegalArgumentException("labId must be greater than zero");
        }
        if (persistOutbox && jdbcTemplate == null) {
            throw new IOException("Durable lab deletion outbox is unavailable");
        }

        DataAccessException outboxFailure = null;
        if (persistOutbox) {
            try {
                upsertOutbox(labId, metadataUri, transactionHash, PENDING_TOMBSTONE, deletedAt);
            } catch (DataAccessException ex) {
                outboxFailure = ex;
                log.warn("Unable to persist lab {} deletion hand-off: {}", labId, ex.getMessage());
            }
        }

        writeTombstoneFiles(labId, metadataUri, transactionHash, deletedAt);

        if (persistOutbox && outboxFailure == null) {
            try {
                markTombstoned(labId, transactionHash);
            } catch (DataAccessException ex) {
                outboxFailure = ex;
                log.warn("Unable to mark lab {} deletion hand-off complete: {}", labId, ex.getMessage());
            }
        }
        if (outboxFailure != null) {
            throw new IOException("Lab content tombstone was written but its durable state could not be updated", outboxFailure);
        }
    }

    private void writeTombstoneFiles(
        BigInteger labId,
        String metadataUri,
        String transactionHash,
        Instant deletedAt
    ) throws IOException {
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
        if (contentDir != null && Files.isRegularFile(contentDir.resolve(TOMBSTONE_FILE))) {
            return true;
        }
        return isDeletionBlocked(contentDirectoryRelativePath(relative).orElse(null));
    }

    public void assertAvailable(String relativePath) throws IOException {
        if (isTombstoned(relativePath)) {
            throw new FileNotFoundException("Content not found");
        }
    }

    /**
     * Fails closed when durable deletion state says the content is pending or
     * when that state cannot be read. A transient database outage must not
     * turn a confirmed deletion into readable content.
     */
    private boolean isDeletionBlocked(String contentRelativePath) {
        if (contentRelativePath == null || jdbcTemplate == null) {
            return false;
        }
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM lab_content_deletion_outbox "
                    + "WHERE content_relative_path = ? AND status <> ?",
                Integer.class,
                contentRelativePath,
                CANCELLED
            );
            return count != null && count > 0;
        } catch (DataAccessException ex) {
            log.warn("Unable to verify lab content deletion state; denying content: {}", ex.getMessage());
            return true;
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

    @Scheduled(fixedDelayString = "${lab.content.deletion.outbox.interval-ms:30000}")
    public void processDeletionOutbox() {
        if (jdbcTemplate == null || deletionOutboxBatchSize <= 0) {
            return;
        }
        for (OutboxRow row : findDueOutboxRows(Math.max(1, deletionOutboxBatchSize))) {
            if (!claimOutbox(row.id())) {
                continue;
            }
            try {
                Instant deletedAt = row.deletedAt() == null ? Instant.now() : row.deletedAt();
                writeTombstoneFiles(row.labId(), row.metadataUri(), row.transactionHash(), deletedAt);
                markTombstoned(row.labId(), row.transactionHash());
            } catch (Exception ex) {
                scheduleOutboxRetry(row, ex);
            }
        }
    }

    /** Called by the durable contract-event journal after a canonical LabDeleted event. */
    public void reconcileLabDeleted(BigInteger labId, String transactionHash) {
        if (labId == null || labId.signum() <= 0 || jdbcTemplate == null) {
            return;
        }
        try {
            upsertOutbox(labId, null, transactionHash, PENDING_TOMBSTONE, Instant.now());
        } catch (DataAccessException ex) {
            log.warn("Unable to create lab {} deletion hand-off from LabDeleted event: {}", labId, ex.getMessage());
            throw ex;
        }
    }

    /** Removes a reservation only when the receipt positively confirms a revert. */
    public void cancelPreparedDeletion(BigInteger labId) {
        if (labId == null || jdbcTemplate == null) {
            return;
        }
        try {
            jdbcTemplate.update(
                "UPDATE lab_content_deletion_outbox SET status=?, last_error=?, updated_at=CURRENT_TIMESTAMP "
                    + "WHERE lab_id=? AND status IN (?, ?)",
                CANCELLED,
                "deleteLab transaction reverted",
                labId.toString(),
                PENDING_TOMBSTONE,
                PROCESSING
            );
        } catch (DataAccessException ex) {
            log.warn("Unable to cancel reverted lab {} deletion hand-off: {}", labId, ex.getMessage());
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
                    markPurged(tombstone);
                    Files.deleteIfExists(tombstoneFile);
                } catch (RuntimeException ex) {
                    log.warn("Skipping invalid lab tombstone {}", tombstoneFile.getFileName());
                }
            }
        }
    }

    private void validateDeletion(BigInteger labId) {
        if (labId == null || labId.signum() <= 0) {
            throw new IllegalArgumentException("labId must be greater than zero");
        }
    }

    private void upsertOutbox(
        BigInteger labId,
        String metadataUri,
        String transactionHash,
        String status,
        Instant deletedAt
    ) {
        String contentPath = contentRelativePath(metadataUri).orElse(null);
        jdbcTemplate.update(
            "INSERT INTO lab_content_deletion_outbox "
                + "(lab_id, metadata_uri, content_relative_path, transaction_hash, status, attempts, "
                + "next_attempt_at, deleted_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, "
                + "CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
                + "ON DUPLICATE KEY UPDATE "
                + "metadata_uri=COALESCE(VALUES(metadata_uri), metadata_uri), "
                + "content_relative_path=COALESCE(VALUES(content_relative_path), content_relative_path), "
                + "transaction_hash=COALESCE(VALUES(transaction_hash), transaction_hash), "
                + "deleted_at=COALESCE(VALUES(deleted_at), deleted_at), "
                + "status=CASE WHEN status IN (?, ?, ?) THEN status ELSE VALUES(status) END, "
                + "last_error=NULL, next_attempt_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP",
            labId.toString(),
            metadataUri,
            contentPath,
            transactionHash,
            status,
            deletedAt == null ? null : java.sql.Timestamp.from(deletedAt),
            PROCESSING,
            TOMBSTONED,
            PURGED
        );
    }

    private void markTombstoned(BigInteger labId, String transactionHash) {
        jdbcTemplate.update(
            "UPDATE lab_content_deletion_outbox SET status=?, transaction_hash=COALESCE(?, transaction_hash), "
                + "lease_id=NULL, lease_expires_at=NULL, last_error=NULL, updated_at=CURRENT_TIMESTAMP "
                + "WHERE lab_id=? AND status IN (?, ?)",
            TOMBSTONED,
            transactionHash,
            labId.toString(),
            PENDING_TOMBSTONE,
            PROCESSING
        );
    }

    private void markPurged(Map<?, ?> tombstone) {
        if (jdbcTemplate == null || tombstone.get("labId") == null) {
            return;
        }
        jdbcTemplate.update(
            "UPDATE lab_content_deletion_outbox SET status=?, updated_at=CURRENT_TIMESTAMP WHERE lab_id=?",
            PURGED,
            String.valueOf(tombstone.get("labId"))
        );
    }

    private List<OutboxRow> findDueOutboxRows(int limit) {
        try {
            return jdbcTemplate.query(
                "SELECT id, lab_id, metadata_uri, content_relative_path, transaction_hash, status, attempts, "
                    + "deleted_at FROM lab_content_deletion_outbox "
                    + "WHERE status=? AND transaction_hash IS NOT NULL AND next_attempt_at <= CURRENT_TIMESTAMP "
                    + "ORDER BY next_attempt_at, id LIMIT ?",
                (rs, rowNum) -> new OutboxRow(
                    rs.getLong("id"),
                    new BigInteger(rs.getString("lab_id")),
                    rs.getString("metadata_uri"),
                    rs.getString("content_relative_path"),
                    rs.getString("transaction_hash"),
                    rs.getInt("attempts"),
                    rs.getTimestamp("deleted_at") == null
                        ? null
                        : rs.getTimestamp("deleted_at").toInstant()
                ),
                PENDING_TOMBSTONE,
                limit
            );
        } catch (DataAccessException ex) {
            log.warn("Unable to load lab deletion outbox: {}", ex.getMessage());
            return List.of();
        }
    }

    private boolean claimOutbox(long id) {
        String leaseId = workerId + ":" + UUID.randomUUID();
        int updated = jdbcTemplate.update(
            "UPDATE lab_content_deletion_outbox SET status=?, lease_id=?, lease_expires_at=?, "
                + "attempts=attempts+1, updated_at=CURRENT_TIMESTAMP "
                + "WHERE id=? AND status=? AND (lease_expires_at IS NULL OR lease_expires_at < CURRENT_TIMESTAMP)",
            PROCESSING,
            leaseId,
            java.sql.Timestamp.from(Instant.now().plusSeconds(PROCESSING_LEASE_SECONDS)),
            id,
            PENDING_TOMBSTONE
        );
        return updated == 1;
    }

    private void scheduleOutboxRetry(OutboxRow row, Exception ex) {
        long base = Math.max(1L, deletionOutboxRetryBaseDelayMs);
        long max = Math.max(base, deletionOutboxRetryMaxDelayMs);
        int exponent = Math.min(Math.max(0, row.attempts()), 10);
        long delay = Math.min(max, base * (1L << exponent));
        try {
            jdbcTemplate.update(
                "UPDATE lab_content_deletion_outbox SET status=?, next_attempt_at=?, last_error=?, "
                    + "lease_id=NULL, lease_expires_at=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=? AND status=?",
                PENDING_TOMBSTONE,
                java.sql.Timestamp.from(Instant.now().plusMillis(delay)),
                truncateError(ex.getMessage()),
                row.id(),
                PROCESSING
            );
        } catch (DataAccessException updateFailure) {
            log.warn("Unable to schedule lab deletion retry for {}: {}", row.labId(), updateFailure.getMessage());
        }
    }

    private String truncateError(String error) {
        if (error == null || error.isBlank()) {
            return "Unknown lab content tombstone failure";
        }
        return error.length() <= 1024 ? error : error.substring(0, 1024);
    }

    private Optional<String> contentDirectoryRelativePath(Path relative) {
        if (relative == null || relative.isAbsolute() || relative.getNameCount() < 2
            || !"content".equals(relative.getName(0).toString())) {
            return Optional.empty();
        }
        return Optional.of(relative.getName(0) + "/" + relative.getName(1));
    }

    private record OutboxRow(
        long id,
        BigInteger labId,
        String metadataUri,
        String contentRelativePath,
        String transactionHash,
        int attempts,
        Instant deletedAt
    ) { }

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
                : path.startsWith("content/") ? path : "";
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
