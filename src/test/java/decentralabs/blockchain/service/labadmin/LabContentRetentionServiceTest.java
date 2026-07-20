package decentralabs.blockchain.service.labadmin;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
}
