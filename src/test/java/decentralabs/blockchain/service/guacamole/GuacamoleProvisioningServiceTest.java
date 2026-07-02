package decentralabs.blockchain.service.guacamole;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class GuacamoleProvisioningServiceTest {

    private HttpServer server;
    private HttpServer secondServer;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
        if (secondServer != null) {
            secondServer.stop(0);
        }
    }

    @Test
    void parsesOnlyPrefixedPositiveConnectionSelectors() {
        assertThat(GuacamoleProvisioningService.parseConnectionId("guac:id:42")).isEqualTo(42);

        assertThatThrownBy(() -> GuacamoleProvisioningService.parseConnectionId("42"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("guac:id");
        assertThatThrownBy(() -> GuacamoleProvisioningService.parseConnectionId("guac:id:0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("guac:id");
    }

    @Test
    void provisionsTemporaryUserThroughGatewayProvisioner() throws Exception {
        server = startServer();
        server.createContext("/internal/guacamole/provision", exchange -> {
            String token = exchange.getRequestHeaders().getFirst("X-Guacamole-Provisioner-Token");
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int status = "secret".equals(token) && body.contains("\"selector\":\"guac:id:42\"") ? 200 : 401;
            byte[] response = """
                {
                  "success": true,
                  "sessionId": "session-1",
                  "username": "dlabs-res-session-1",
                  "connection": {
                    "id": 42,
                    "selector": "guac:id:42",
                    "name": "Oscilloscope RDP",
                    "protocol": "rdp",
                    "hostname": "lab-ws-01",
                    "port": "3389"
                  }
                }
                """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        GuacamoleProvisioningService service = service(server, "/internal/guacamole/provision", "/internal/guacamole/connections");

        var result = service.provisionTemporaryUser(
            "guac:id:42",
            "session-1",
            BigInteger.valueOf(1_800_000_000L)
        );

        assertThat(result.username()).isEqualTo("dlabs-res-session-1");
        assertThat(result.connection().id()).isEqualTo(42L);
        assertThat(result.connection().selector()).isEqualTo("guac:id:42");
    }

    @Test
    void listsConnectionsThroughGatewayProvisioner() throws Exception {
        server = startServer();
        server.createContext("/internal/guacamole/connections", exchange -> {
            byte[] response = """
                {
                  "success": true,
                  "connections": [
                    {"id": 7, "selector": "guac:id:7", "name": "RDP Lab", "protocol": "rdp"}
                  ]
                }
                """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        GuacamoleProvisioningService service = service(server, "/internal/guacamole/provision", "/internal/guacamole/connections");

        assertThat(service.listSafeConnections().getFirst())
            .containsEntry("selector", "guac:id:7");
    }

    @Test
    void selectsProvisionerRouteFromAccessUri() throws Exception {
        server = startServer();
        secondServer = startServer();
        AtomicInteger firstCalls = new AtomicInteger();
        AtomicInteger secondCalls = new AtomicInteger();
        createProvisionContext(server, firstCalls, "first-session");
        createProvisionContext(secondServer, secondCalls, "second-session");

        String firstBase = "http://127.0.0.1:" + server.getAddress().getPort();
        String secondBase = "http://127.0.0.1:" + secondServer.getAddress().getPort();
        GuacamoleProvisioningService service = new GuacamoleProvisioningService(
            HttpClient.newHttpClient(),
            new ObjectMapper(),
            new GuacamoleProvisioningService.ProvisionerRoute(firstBase, "/internal/guacamole", "X-Guacamole-Provisioner-Token", "secret"),
            Map.of(
                "https://lite-b.example.edu",
                new GuacamoleProvisioningService.ProvisionerRoute(secondBase, "/internal/guacamole", "X-Guacamole-Provisioner-Token", "secret")
            ),
            null,
            null
        );

        service.provisionTemporaryUser("guac:id:42", "session-a", BigInteger.valueOf(1_800_000_000L), "https://lite-a.example.edu/guacamole");
        service.provisionTemporaryUser("guac:id:42", "session-b", BigInteger.valueOf(1_800_000_000L), "https://lite-b.example.edu/guacamole");

        assertThat(firstCalls).hasValue(1);
        assertThat(secondCalls).hasValue(1);
    }

    @Test
    void routesJsonCanUseAccessUriOriginAsImplicitBaseUrl() throws Exception {
        server = startServer();
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/gateway-provisioner/guacamole/provision", exchange -> {
            String token = exchange.getRequestHeaders().getFirst("X-Guacamole-Provisioner-Token");
            calls.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] response = """
                {"success":true,"sessionId":"session-a","username":"dlabs-res-session-a","connection":{"id":42,"selector":"guac:id:42"}}
                """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders("secret-a".equals(token) ? 200 : 401, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        MockEnvironment environment = new MockEnvironment()
            .withProperty("GUACAMOLE_PROVISIONER_ROUTES_JSON", """
                {"%s":{"token":"secret-a"}}
                """.formatted(base));
        GuacamoleProvisioningService service = new GuacamoleProvisioningService(environment, new ObjectMapper());

        service.provisionTemporaryUser("guac:id:42", "session-a", BigInteger.valueOf(1_800_000_000L), base + "/guacamole");

        assertThat(calls).hasValue(1);
    }

    @Test
    void sharedProvisionerTokenDerivesRouteFromAccessUriWhenNoRouteMapExists() throws Exception {
        server = startServer();
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/gateway-provisioner/guacamole/provision", exchange -> {
            String token = exchange.getRequestHeaders().getFirst("X-Guacamole-Provisioner-Token");
            calls.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] response = """
                {"success":true,"sessionId":"session-a","username":"dlabs-res-session-a","connection":{"id":42,"selector":"guac:id:42"}}
                """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders("shared-secret".equals(token) ? 200 : 401, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        MockEnvironment environment = new MockEnvironment()
            .withProperty("GUACAMOLE_PROVISIONER_TOKEN", "shared-secret");
        GuacamoleProvisioningService service = new GuacamoleProvisioningService(environment, new ObjectMapper());

        service.provisionTemporaryUser("guac:id:42", "session-a", BigInteger.valueOf(1_800_000_000L), base + "/guacamole");

        assertThat(calls).hasValue(1);
    }

    @Test
    void sharedProvisionerTokenStillUsesLocalDefaultForLocalAccessUri() throws Exception {
        server = startServer();
        secondServer = startServer();
        AtomicInteger localCalls = new AtomicInteger();
        AtomicInteger derivedCalls = new AtomicInteger();
        createProvisionContext(server, localCalls, "local-session");
        secondServer.createContext("/gateway-provisioner/guacamole/provision", exchange -> {
            derivedCalls.incrementAndGet();
            byte[] response = """
                {"success":true,"sessionId":"derived-session","username":"dlabs-res-derived-session","connection":{"id":42,"selector":"guac:id:42"}}
                """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });

        String localBase = "http://127.0.0.1:" + server.getAddress().getPort();
        MockEnvironment environment = new MockEnvironment()
            .withProperty("GUACAMOLE_PROVISIONER_BASE_URL", localBase)
            .withProperty("GUACAMOLE_PROVISIONER_PATH_PREFIX", "/internal/guacamole")
            .withProperty("GUACAMOLE_PROVISIONER_TOKEN", "shared-secret")
            .withProperty("SERVER_NAME", "127.0.0.1")
            .withProperty("HTTPS_PORT", String.valueOf(secondServer.getAddress().getPort()));
        GuacamoleProvisioningService service = new GuacamoleProvisioningService(environment, new ObjectMapper());

        String localAccessUri = "https://127.0.0.1:" + secondServer.getAddress().getPort() + "/guacamole";
        service.provisionTemporaryUser("guac:id:42", "session-a", BigInteger.valueOf(1_800_000_000L), localAccessUri);

        assertThat(localCalls).hasValue(1);
        assertThat(derivedCalls).hasValue(0);
    }

    private HttpServer startServer() throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.start();
        return httpServer;
    }

    private GuacamoleProvisioningService service(HttpServer httpServer, String provisionPath, String connectionsPath) {
        String base = "http://127.0.0.1:" + httpServer.getAddress().getPort();
        return new GuacamoleProvisioningService(
            HttpClient.newHttpClient(),
            new ObjectMapper(),
            URI.create(base + provisionPath),
            URI.create(base + connectionsPath),
            "X-Guacamole-Provisioner-Token",
            "secret"
        );
    }

    private void createProvisionContext(HttpServer httpServer, AtomicInteger calls, String responseSession) {
        httpServer.createContext("/internal/guacamole/provision", exchange -> {
            calls.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] response = ("""
                {
                  "success": true,
                  "sessionId": "%s",
                  "username": "dlabs-res-%s",
                  "connection": {"id": 42, "selector": "guac:id:42"}
                }
                """.formatted(responseSession, responseSession)).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
    }

}
