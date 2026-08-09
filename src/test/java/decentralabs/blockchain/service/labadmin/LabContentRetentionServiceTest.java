package decentralabs.blockchain.service.labadmin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

class LabContentRetentionServiceTest {

    @TempDir
    Path tempDir;

    private LabContentRetentionService service;

    @BeforeEach
    void setUp() {
        service = new LabContentRetentionService();
        ReflectionTestUtils.setField(service, "contentBasePath", tempDir.toString());
        ReflectionTestUtils.setField(service, "retention", Duration.ofDays(7));
    }

    @Test
    void marksContentAsTombstonedAfterSuccessfulChainDelete() throws Exception {
        Path contentDir = tempDir.resolve("content/lab-42");
        Files.createDirectories(contentDir.resolve("images"));
        Files.writeString(contentDir.resolve("metadata.json"), "{\"name\":\"deleted\"}");
        Files.writeString(contentDir.resolve("images/cover.png"), "image");

        service.markDeleted(
            BigInteger.valueOf(42),
            "https://gateway.example/lab-content/content/lab-42/metadata.json",
            "0xdelete42",
            Instant.now()
        );

        assertThat(service.isTombstoned("content/lab-42/metadata.json")).isTrue();
        assertThat(service.isTombstoned("content/lab-42/images/cover.png")).isTrue();
        assertThat(Files.exists(tempDir.resolve("tombstones/lab-42.json"))).isTrue();
        assertThat(Files.exists(contentDir.resolve("metadata.json"))).isTrue();
    }

    @Test
    void marksContentWhenMetadataUriUsesRelativeContentPath() throws Exception {
        Path contentDir = tempDir.resolve("content/lab-44");
        Files.createDirectories(contentDir);
        Files.writeString(contentDir.resolve("metadata.json"), "{\"name\":\"deleted\"}");

        service.markDeleted(
            BigInteger.valueOf(44),
            "content/lab-44/metadata.json",
            "0xdelete44",
            Instant.now()
        );

        assertThat(service.isTombstoned("content/lab-44/metadata.json")).isTrue();
    }

    @Test
    void garbageCollectionDeletesOnlyExpiredTombstonedContent() throws Exception {
        Path contentDir = tempDir.resolve("content/lab-43");
        Files.createDirectories(contentDir.resolve("docs"));
        Files.writeString(contentDir.resolve("docs/manual.pdf"), "pdf");

        service.markDeleted(
            BigInteger.valueOf(43),
            "https://gateway.example/lab-content/content/lab-43/metadata.json",
            "0xdelete43",
            Instant.parse("2020-01-01T00:00:00Z")
        );
        service.garbageCollect(Instant.parse("2020-01-09T00:00:00Z"));

        assertThat(Files.exists(contentDir)).isFalse();
        assertThat(Files.exists(tempDir.resolve("tombstones/lab-43.json"))).isFalse();
    }

    @Test
    void pendingDurableDeletionBlocksContentBeforeFilesystemTombstoneExists() throws Exception {
        @SuppressWarnings("unchecked")
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        service = new LabContentRetentionService(provider);
        ReflectionTestUtils.setField(service, "contentBasePath", tempDir.toString());
        when(jdbcTemplate.queryForObject(
            anyString(), eq(Integer.class), eq("content/lab-45"), eq("CANCELLED")
        )).thenReturn(1);

        Files.createDirectories(tempDir.resolve("content/lab-45"));
        Files.writeString(tempDir.resolve("content/lab-45/metadata.json"), "{\"name\":\"pending\"}");

        assertThatThrownBy(() -> service.assertAvailable("content/lab-45/metadata.json"))
            .isInstanceOf(java.io.FileNotFoundException.class);
    }

    @Test
    void refusesToPrepareDeletionWithoutMetadataUri() {
        assertThatThrownBy(() -> service.prepareDeletion(BigInteger.valueOf(46), null, "operation-46"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Metadata URI is unavailable");
    }

    @Test
    @SuppressWarnings("unchecked")
    void preparationPersistsOperationKeyAndExplicitBroadcastState() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        service = new LabContentRetentionService(provider);

        service.prepareDeletion(
            BigInteger.valueOf(47),
            "https://gateway.example/lab-content/content/lab-47/metadata.json",
            "lab-admin:delete:47:command-1"
        );

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> parameters = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(sql.capture(), parameters.capture());
        assertThat(sql.getValue())
            .contains("operation_key")
            .contains("broadcast_status");
        assertThat(Arrays.asList(parameters.getValue()))
            .contains("lab-admin:delete:47:command-1", "PREPARED");
    }

    @Test
    @SuppressWarnings("unchecked")
    void dueLookupReclaimsExpiredProcessingDeletionLeases() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.query(any(String.class), any(RowMapper.class), any(Object[].class)))
            .thenReturn(java.util.List.of());
        service = new LabContentRetentionService(provider);

        service.processDeletionOutbox();

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> parameters = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).query(sql.capture(), any(RowMapper.class), parameters.capture());
        assertThat(sql.getValue())
            .contains("broadcast_status=?")
            .contains("status=? AND next_attempt_at <= CURRENT_TIMESTAMP")
            .contains("status=? AND (lease_expires_at IS NULL OR lease_expires_at < CURRENT_TIMESTAMP)");
        assertThat(Arrays.asList(parameters.getValue()))
            .containsExactly("CONFIRMED_DELETED", "PENDING_TOMBSTONE", "PROCESSING", 25);
    }

    @Test
    @SuppressWarnings("unchecked")
    void claimCanReacquireAnExpiredProcessingDeletionLease() {
        ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(provider.getIfAvailable()).thenReturn(jdbcTemplate);
        when(jdbcTemplate.update(any(String.class), any(Object[].class))).thenReturn(1);
        service = new LabContentRetentionService(provider);

        boolean claimed = ReflectionTestUtils.invokeMethod(service, "claimOutbox", 7L);

        assertThat(claimed).isTrue();
        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> parameters = ArgumentCaptor.forClass(Object[].class);
        verify(jdbcTemplate).update(sql.capture(), parameters.capture());
        assertThat(sql.getValue())
            .contains("status=? OR (status=? AND (lease_expires_at IS NULL OR lease_expires_at < CURRENT_TIMESTAMP))");
        assertThat(Arrays.asList(parameters.getValue()))
            .contains("PENDING_TOMBSTONE", "PROCESSING");
    }
}
