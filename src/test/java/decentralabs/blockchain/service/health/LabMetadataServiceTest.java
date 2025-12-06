package decentralabs.blockchain.service.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DayOfWeek;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import decentralabs.blockchain.dto.health.LabMetadata;

@ExtendWith(MockitoExtension.class)
class LabMetadataServiceTest {

    @Mock
    private RestTemplate restTemplate;

    private LabMetadataService metadataService;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        metadataService = new LabMetadataService();
        ReflectionTestUtils.setField(metadataService, "restTemplate", restTemplate);
        ReflectionTestUtils.setField(metadataService, "cacheEnabled", true);
    }

    @Nested
    @DisplayName("HTTP Metadata Fetch Tests")
    class HttpFetchTests {

        @Test
        @DisplayName("Should fetch and parse metadata from HTTP URL")
        void shouldFetchAndParseMetadataFromHttpUrl() {
            String json = createMinimalMetadataJson("Test Lab", "A test laboratory", "https://image.url/lab.png");
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata).isNotNull();
            assertThat(metadata.getName()).isEqualTo("Test Lab");
            assertThat(metadata.getDescription()).isEqualTo("A test laboratory");
            assertThat(metadata.getImage()).isEqualTo("https://image.url/lab.png");
        }

        @Test
        @DisplayName("Should parse metadata with all attributes")
        void shouldParseMetadataWithAllAttributes() {
            String json = createCompleteMetadataJson();
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/complete.json");

            assertThat(metadata.getName()).isEqualTo("Complete Lab");
            assertThat(metadata.getCategory()).isEqualTo("physics");
            assertThat(metadata.getKeywords()).containsExactly("electronics", "robotics");
            assertThat(metadata.getTimeSlots()).containsExactly(30, 60, 90);
            assertThat(metadata.getMaxConcurrentUsers()).isEqualTo(5);
            assertThat(metadata.getAvailableDays()).contains(DayOfWeek.MONDAY, DayOfWeek.WEDNESDAY);
        }

        @Test
        @DisplayName("Should throw exception when HTTP fetch fails")
        void shouldThrowExceptionWhenHttpFetchFails() {
            when(restTemplate.getForObject(anyString(), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));

            assertThatThrownBy(() -> metadataService.getLabMetadata("https://unreachable.com/metadata.json"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Unable to load lab metadata");
        }

        @Test
        @DisplayName("Should throw exception for invalid JSON")
        void shouldThrowExceptionForInvalidJson() {
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn("not valid json");

            assertThatThrownBy(() -> metadataService.getLabMetadata("https://example.com/invalid.json"))
                .isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("Should handle null response")
        void shouldHandleNullResponse() {
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(null);

            assertThatThrownBy(() -> metadataService.getLabMetadata("https://example.com/null.json"))
                .isInstanceOf(RuntimeException.class);
        }
    }

    @Nested
    @DisplayName("Local File Metadata Tests")
    class LocalFileTests {

        @Test
        @DisplayName("Should fetch and parse metadata from local file")
        void shouldFetchAndParseMetadataFromLocalFile() throws Exception {
            String json = createMinimalMetadataJson("Local Lab", "Local description", "file:///image.png");
            Path metadataFile = tempDir.resolve("metadata.json");
            Files.writeString(metadataFile, json);

            LabMetadata metadata = metadataService.getLabMetadata(metadataFile.toString());

            assertThat(metadata).isNotNull();
            assertThat(metadata.getName()).isEqualTo("Local Lab");
            assertThat(metadata.getDescription()).isEqualTo("Local description");
        }

        @Test
        @DisplayName("Should throw exception when file not found")
        void shouldThrowExceptionWhenFileNotFound() {
            String nonexistentPath = tempDir.resolve("nonexistent.json").toString();

            assertThatThrownBy(() -> metadataService.getLabMetadata(nonexistentPath))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Unable to load lab metadata");
        }
    }

    @Nested
    @DisplayName("Attribute Parsing Tests")
    class AttributeParsingTests {

        @Test
        @DisplayName("Should parse epoch seconds for opens/closes")
        void shouldParseEpochSecondsForOpensCloses() {
            String json = createMetadataJsonWithOpensCloses(1704067200L, 1735689600L);
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata.getOpens()).isEqualTo(1704067200L);
            assertThat(metadata.getCloses()).isEqualTo(1735689600L);
        }

        @Test
        @DisplayName("Should parse available hours time range")
        void shouldParseAvailableHoursTimeRange() {
            String json = createMetadataJsonWithAvailableHours("09:00", "18:00");
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata.getAvailableHours()).isNotNull();
            assertThat(metadata.getAvailableHours().getStart().toString()).isEqualTo("09:00");
            assertThat(metadata.getAvailableHours().getEnd().toString()).isEqualTo("18:00");
        }

        @Test
        @DisplayName("Should parse unavailable windows")
        void shouldParseUnavailableWindows() {
            String json = createMetadataJsonWithUnavailableWindows();
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata.getUnavailableWindows()).isNotNull();
            assertThat(metadata.getUnavailableWindows()).hasSize(1);
        }

        @Test
        @DisplayName("Should handle missing optional attributes")
        void shouldHandleMissingOptionalAttributes() {
            String json = createMinimalMetadataJson("Minimal Lab", "Minimal desc", "https://img.url");
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata.getCategory()).isNull();
            assertThat(metadata.getKeywords()).isNull();
            assertThat(metadata.getTimeSlots()).isNull();
            assertThat(metadata.getMaxConcurrentUsers()).isNull();
        }

        @Test
        @DisplayName("Should parse documentation links")
        void shouldParseDocumentationLinks() {
            String json = createMetadataJsonWithDocs();
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata.getDocumentation()).containsExactly(
                "https://docs.example.com/manual.pdf",
                "https://docs.example.com/guide.html"
            );
        }

        @Test
        @DisplayName("Should handle backwards compatible attribute names")
        void shouldHandleBackwardsCompatibleAttributeNames() {
            String json = createMetadataJsonWithSpacedAttributeNames();
            when(restTemplate.getForObject(anyString(), eq(String.class))).thenReturn(json);

            LabMetadata metadata = metadataService.getLabMetadata("https://example.com/metadata.json");

            assertThat(metadata.getAvailableDays()).contains(DayOfWeek.TUESDAY);
            assertThat(metadata.getMaxConcurrentUsers()).isEqualTo(3);
        }
    }

    @Nested
    @DisplayName("Cache Configuration Tests")
    class CacheTests {

        @Test
        @DisplayName("Should have cache enabled property")
        void shouldHaveCacheEnabledProperty() {
            Boolean cacheEnabled = (Boolean) ReflectionTestUtils.getField(metadataService, "cacheEnabled");
            assertThat(cacheEnabled).isTrue();
        }
    }

    // Helper methods to create test JSON

    private String createMinimalMetadataJson(String name, String description, String image) {
        return String.format("""
            {
                "name": "%s",
                "description": "%s",
                "image": "%s",
                "attributes": []
            }
            """, name, description, image);
    }

    private String createCompleteMetadataJson() {
        return """
            {
                "name": "Complete Lab",
                "description": "A fully configured lab",
                "image": "https://image.url/complete.png",
                "attributes": [
                    { "trait_type": "category", "value": "physics" },
                    { "trait_type": "keywords", "value": ["electronics", "robotics"] },
                    { "trait_type": "timeslots", "value": [30, 60, 90] },
                    { "trait_type": "maxConcurrentUsers", "value": 5 },
                    { "trait_type": "availableDays", "value": ["MONDAY", "WEDNESDAY", "FRIDAY"] }
                ]
            }
            """;
    }

    private String createMetadataJsonWithOpensCloses(long opens, long closes) {
        return String.format("""
            {
                "name": "Timed Lab",
                "description": "Lab with opening hours",
                "image": "https://image.url",
                "attributes": [
                    { "trait_type": "opens", "value": %d },
                    { "trait_type": "closes", "value": %d }
                ]
            }
            """, opens, closes);
    }

    private String createMetadataJsonWithAvailableHours(String start, String end) {
        return String.format("""
            {
                "name": "Hours Lab",
                "description": "Lab with available hours",
                "image": "https://image.url",
                "attributes": [
                    { "trait_type": "availableHours", "value": { "start": "%s", "end": "%s" } }
                ]
            }
            """, start, end);
    }

    private String createMetadataJsonWithUnavailableWindows() {
        return """
            {
                "name": "Maintenance Lab",
                "description": "Lab with maintenance windows",
                "image": "https://image.url",
                "attributes": [
                    { "trait_type": "unavailableWindows", "value": [
                        { "startUnix": 1704067200, "endUnix": 1704153600, "reason": "scheduled maintenance" }
                    ]}
                ]
            }
            """;
    }

    private String createMetadataJsonWithDocs() {
        return """
            {
                "name": "Documented Lab",
                "description": "Lab with documentation",
                "image": "https://image.url",
                "attributes": [
                    { "trait_type": "docs", "value": [
                        "https://docs.example.com/manual.pdf",
                        "https://docs.example.com/guide.html"
                    ]}
                ]
            }
            """;
    }

    private String createMetadataJsonWithSpacedAttributeNames() {
        return """
            {
                "name": "Legacy Lab",
                "description": "Lab with spaced attribute names",
                "image": "https://image.url",
                "attributes": [
                    { "trait_type": "available days", "value": ["TUESDAY", "THURSDAY"] },
                    { "trait_type": "max concurrent users", "value": 3 }
                ]
            }
            """;
    }
}
