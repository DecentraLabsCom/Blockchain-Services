package decentralabs.blockchain.service.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

class SafeLabMetadataClientTest {

    private SafeLabMetadataClient client;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        client = new SafeLabMetadataClient();
        ReflectionTestUtils.setField(client, "maxBytes", 1024L);
        ReflectionTestUtils.setField(client, "connectTimeoutMs", 500L);
        ReflectionTestUtils.setField(client, "readTimeoutMs", 500L);
        ReflectionTestUtils.setField(client, "callTimeoutMs", 1000L);
        ReflectionTestUtils.setField(client, "maxConcurrentFetches", 2);
        ReflectionTestUtils.setField(client, "localMetadataEnabled", true);
        ReflectionTestUtils.setField(client, "localMetadataRoot", tempDir.toString());
        ReflectionTestUtils.invokeMethod(client, "initialize");
    }

    @Test
    void rejectsNonHttpsRemoteMetadata() {
        assertThatThrownBy(() -> client.fetch("http://example.com/lab.json", List.of("https://example.com")))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("HTTPS");
    }

    @Test
    void rejectsRemoteOriginThatIsNotRegistered() {
        assertThatThrownBy(() -> client.fetch("https://example.com/lab.json", List.of("https://other.example")))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("not registered");
    }

    @Test
    void rejectsPrivateAddressEvenWhenOriginIsRegistered() {
        assertThatThrownBy(() -> client.fetch("https://127.0.0.1/lab.json", List.of("https://127.0.0.1")))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("private or reserved");
    }

    @Test
    void rejectsPrivateAddressForAuthoritativeOnChainUri() {
        assertThatThrownBy(() -> client.fetchFromAuthoritativeUri("https://127.0.0.1/lab.json"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("private or reserved");
    }

    @Test
    void readsOnlyFilesBelowExplicitFixtureRoot() throws Exception {
        Path metadata = tempDir.resolve("Lab-demo.json");
        Files.writeString(metadata, "{\"name\":\"Fixture\"}");

        assertThat(client.fetch("Lab-demo.json", List.of()))
            .isEqualTo(Files.readAllBytes(metadata));

        assertThatThrownBy(() -> client.fetch("../outside.json", List.of()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("escapes");
    }

    @Test
    void localFixturesAreDisabledByDefault() {
        ReflectionTestUtils.setField(client, "localMetadataEnabled", false);

        assertThatThrownBy(() -> client.fetch("Lab-demo.json", List.of()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("disabled");
    }
}
