package decentralabs.blockchain.service.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StationCapacityServiceTest {

    private StationCapacityService service;
    private HttpServer capacityServer;

    @BeforeEach
    void setUp() {
        service = new StationCapacityService(
            new ObjectMapper(),
            "",
            "",
            100,
            false
        );
    }

    @AfterEach
    void tearDown() {
        if (capacityServer != null) {
            capacityServer.stop(0);
        }
    }

    @Test
    void rejectsMissingDeclaredCapacity() {
        assertThatThrownBy(() -> service.validateDeclaredCapacity(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("maxConcurrentUsers is required for FMU resources");
    }

    @Test
    void rejectsNonPositiveDeclaredCapacity() {
        assertThatThrownBy(() -> service.validateDeclaredCapacity(0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("maxConcurrentUsers must be a positive integer");
    }

    @Test
    void acceptsCapacityEqualToTheStationAuthority() throws Exception {
        service = serviceBackedByStation("{\"capacity\":3}");

        assertThat(service.requireCapacity()).isEqualTo(3);
        service.validateDeclaredCapacity(3);
    }

    @Test
    void rejectsDeclaredCapacityAboveTheStationAuthority() throws Exception {
        service = serviceBackedByStation("{\"capacity\":3}");

        assertThatThrownBy(() -> service.validateDeclaredCapacity(4))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("maxConcurrentUsers 4 exceeds effective Station capacity 3");
    }

    @Test
    void rejectsZeroCapacityReportedByTheStation() throws Exception {
        service = serviceBackedByStation("{\"capacity\":0}");

        assertThatThrownBy(service::requireCapacity)
            .isInstanceOf(StationCapacityUnavailableException.class)
            .hasMessage("Station returned an invalid execution capacity");
    }

    @Test
    void failsClosedWhenTheStationCapacityAuthorityIsUnavailable() throws Exception {
        capacityServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = capacityServer.getAddress().getPort();
        capacityServer.start();
        capacityServer.stop(0);
        capacityServer = null;

        service = new StationCapacityService(
            new ObjectMapper(),
            "http://127.0.0.1:" + port,
            "internal-token",
            100,
            true
        );

        assertThatThrownBy(service::requireCapacity)
            .isInstanceOf(StationCapacityUnavailableException.class)
            .hasMessage("Unable to read FMU capacity from Station");
    }

    private StationCapacityService serviceBackedByStation(String body) throws Exception {
        capacityServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        capacityServer.createContext("/internal/fmu/capacity", exchange -> {
            byte[] response = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            try (var output = exchange.getResponseBody()) {
                output.write(response);
            }
        });
        capacityServer.start();
        return new StationCapacityService(
            new ObjectMapper(),
            "http://127.0.0.1:" + capacityServer.getAddress().getPort(),
            "internal-token",
            1000,
            true
        );
    }
}
