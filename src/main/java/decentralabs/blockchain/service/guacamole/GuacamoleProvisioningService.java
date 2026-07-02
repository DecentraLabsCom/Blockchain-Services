package decentralabs.blockchain.service.guacamole;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@Slf4j
public class GuacamoleProvisioningService {

    private static final Pattern SELECTOR = Pattern.compile("^guac:id:([1-9][0-9]*)$");
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ProvisionerRoute defaultRoute;
    private final Map<String, ProvisionerRoute> routesByKey;
    private final ProvisionerRoute derivedRouteTemplate;
    private final String localAccessOrigin;

    public record ConnectionMetadata(
        long id,
        String selector,
        String name,
        String protocol,
        String hostname,
        String port
    ) {}

    public record ProvisioningResult(String sessionId, String username, ConnectionMetadata connection) {}

    record ProvisionerRoute(String baseUrl, String pathPrefix, String tokenHeader, String token) {
        URI provisionUri() {
            return uri("provision");
        }

        URI connectionsUri() {
            return uri("connections");
        }

        URI uri(String endpoint) {
            String normalizedBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            String normalizedPrefix = pathPrefix.startsWith("/") ? pathPrefix : "/" + pathPrefix;
            normalizedPrefix = normalizedPrefix.endsWith("/")
                ? normalizedPrefix.substring(0, normalizedPrefix.length() - 1)
                : normalizedPrefix;
            return URI.create(normalizedBase + normalizedPrefix + "/" + endpoint);
        }
    }

    public GuacamoleProvisioningService(Environment environment, ObjectMapper objectMapper) {
        this(
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
            objectMapper,
            buildDefaultRoute(environment),
            buildRoutesByKey(environment, objectMapper),
            buildDerivedRouteTemplate(environment),
            buildLocalAccessOrigin(environment)
        );
    }

    GuacamoleProvisioningService(
        HttpClient httpClient,
        ObjectMapper objectMapper,
        URI provisionUri,
        URI connectionsUri,
        String tokenHeader,
        String token
    ) {
        this(
            httpClient,
            objectMapper,
            routeFromUris(provisionUri, connectionsUri, tokenHeader, token),
            Map.of(),
            null,
            null
        );
    }

    GuacamoleProvisioningService(
        HttpClient httpClient,
        ObjectMapper objectMapper,
        ProvisionerRoute defaultRoute,
        Map<String, ProvisionerRoute> routesByKey,
        ProvisionerRoute derivedRouteTemplate,
        String localAccessOrigin
    ) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.defaultRoute = defaultRoute;
        this.routesByKey = routesByKey == null ? Map.of() : Map.copyOf(routesByKey);
        this.derivedRouteTemplate = derivedRouteTemplate;
        this.localAccessOrigin = normalizeOrigin(localAccessOrigin);
    }

    public static boolean isGuacamoleSelector(String accessKey) {
        return accessKey != null && SELECTOR.matcher(accessKey.trim()).matches();
    }

    public static long parseConnectionId(String accessKey) {
        Matcher matcher = SELECTOR.matcher(Optional.ofNullable(accessKey).orElse("").trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Physical Guacamole labs require accessKey format guac:id:<connection_id>");
        }
        return Long.parseLong(matcher.group(1));
    }

    public boolean isConfigured() {
        return defaultRoute != null || !routesByKey.isEmpty() || derivedRouteTemplate != null;
    }

    public ProvisioningResult provisionTemporaryUser(String selector, String sessionId, BigInteger validUntilEpochSeconds) {
        return provisionTemporaryUser(selector, sessionId, validUntilEpochSeconds, null);
    }

    public ProvisioningResult provisionTemporaryUser(String selector, String sessionId, BigInteger validUntilEpochSeconds, String accessUri) {
        if (!isConfigured()) {
            throw new IllegalStateException("Guacamole provisioner is not configured");
        }
        ProvisionerRoute route = resolveRoute(accessUri);
        parseConnectionId(selector);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("selector", selector);
        payload.put("sessionId", sessionId);
        payload.put("validUntilEpochSeconds", validUntilEpochSeconds);
        Map<String, Object> response = postJson(route.provisionUri(), route, payload);
        if (!Boolean.TRUE.equals(response.get("success"))) {
            throw new IllegalStateException("Guacamole provisioner rejected the request");
        }
        String username = stringValue(response.get("username"));
        if (!StringUtils.hasText(username)) {
            throw new IllegalStateException("Guacamole provisioner response did not include username");
        }
        return new ProvisioningResult(
            stringValue(response.getOrDefault("sessionId", sessionId)),
            username,
            connectionMetadata(response.get("connection"))
        );
    }

    public List<Map<String, Object>> listSafeConnections() {
        if (!isConfigured()) {
            throw new IllegalStateException("Guacamole provisioner is not configured");
        }
        ProvisionerRoute route = resolveRoute(null);
        Map<String, Object> response = getJson(route.connectionsUri(), route);
        Object connections = response.get("connections");
        if (connections instanceof List<?> list) {
            return list.stream()
                .filter(Map.class::isInstance)
                .map(GuacamoleProvisioningService::stringKeyMap)
                .toList();
        }
        return List.of();
    }

    private static Map<String, Object> stringKeyMap(Object raw) {
        Map<?, ?> source = (Map<?, ?>) raw;
        Map<String, Object> copy = new LinkedHashMap<>();
        source.forEach((key, value) -> copy.put(String.valueOf(key), value));
        return copy;
    }

    private Map<String, Object> postJson(URI uri, ProvisionerRoute route, Map<String, Object> payload) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)));
            addAuthHeader(builder, route);
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return parseResponse(response);
        } catch (Exception ex) {
            throw new IllegalStateException("Guacamole provisioner request failed: " + ex.getMessage(), ex);
        }
    }

    private Map<String, Object> getJson(URI uri, ProvisionerRoute route) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .GET();
            addAuthHeader(builder, route);
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return parseResponse(response);
        } catch (Exception ex) {
            throw new IllegalStateException("Guacamole provisioner request failed: " + ex.getMessage(), ex);
        }
    }

    private Map<String, Object> parseResponse(HttpResponse<String> response) throws Exception {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("HTTP " + response.statusCode() + ": " + response.body());
        }
        return objectMapper.readValue(response.body(), new TypeReference<>() {});
    }

    private void addAuthHeader(HttpRequest.Builder builder, ProvisionerRoute route) {
        if (route != null && StringUtils.hasText(route.token()) && StringUtils.hasText(route.tokenHeader())) {
            builder.header(route.tokenHeader(), route.token());
        }
    }

    private ProvisionerRoute resolveRoute(String accessUri) {
        String origin = originOf(accessUri);
        if (StringUtils.hasText(origin)) {
            ProvisionerRoute route = routesByKey.get(origin.toLowerCase());
            if (route != null) {
                return route;
            }
            String host = hostOf(accessUri);
            if (StringUtils.hasText(host)) {
                route = routesByKey.get(host.toLowerCase());
                if (route != null) {
                    return route;
                }
            }
            if (derivedRouteTemplate != null && !origin.equals(localAccessOrigin)) {
                return new ProvisionerRoute(origin, "/gateway-provisioner/guacamole",
                    derivedRouteTemplate.tokenHeader(),
                    derivedRouteTemplate.token());
            }
        }
        if (defaultRoute != null) {
            return defaultRoute;
        }
        throw new IllegalStateException("No Guacamole provisioner route configured for accessURI: " + accessUri);
    }

    private ConnectionMetadata connectionMetadata(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        long id = longValue(map.get("id"));
        String selector = stringValue(map.get("selector"));
        if (!StringUtils.hasText(selector)) {
            selector = "guac:id:" + id;
        }
        return new ConnectionMetadata(
            id,
            selector,
            stringValue(map.get("name")),
            stringValue(map.get("protocol")),
            stringValue(map.get("hostname")),
            stringValue(map.get("port"))
        );
    }

    private static ProvisionerRoute buildDefaultRoute(Environment environment) {
        String base = firstText(
            environment.getProperty("guacamole.provisioner.base-url"),
            environment.getProperty("GUACAMOLE_PROVISIONER_BASE_URL"),
            "http://ops-worker:8081"
        );
        String prefix = firstText(
            environment.getProperty("guacamole.provisioner.path-prefix"),
            environment.getProperty("GUACAMOLE_PROVISIONER_PATH_PREFIX"),
            "/internal/guacamole"
        );
        String tokenHeader = firstText(
            environment.getProperty("guacamole.provisioner.token-header"),
            environment.getProperty("GUACAMOLE_PROVISIONER_TOKEN_HEADER"),
            "X-Guacamole-Provisioner-Token"
        );
        String token = firstText(
            environment.getProperty("guacamole.provisioner.token"),
            environment.getProperty("GUACAMOLE_PROVISIONER_TOKEN"),
            environment.getProperty("LAB_MANAGER_TOKEN")
        );
        if (!StringUtils.hasText(base)) {
            return null;
        }
        return new ProvisionerRoute(base, prefix, tokenHeader, token);
    }

    private static ProvisionerRoute buildDerivedRouteTemplate(Environment environment) {
        String token = firstText(
            environment.getProperty("guacamole.provisioner.token"),
            environment.getProperty("GUACAMOLE_PROVISIONER_TOKEN")
        );
        if (!StringUtils.hasText(token)) {
            return null;
        }
        String tokenHeader = firstText(
            environment.getProperty("guacamole.provisioner.token-header"),
            environment.getProperty("GUACAMOLE_PROVISIONER_TOKEN_HEADER"),
            "X-Guacamole-Provisioner-Token"
        );
        return new ProvisionerRoute("", "/gateway-provisioner/guacamole", tokenHeader, token);
    }

    private static String buildLocalAccessOrigin(Environment environment) {
        String serverName = firstText(environment.getProperty("SERVER_NAME"), "localhost");
        String httpsPort = firstText(environment.getProperty("HTTPS_PORT"), "443");
        String portPart = "443".equals(httpsPort) ? "" : ":" + httpsPort;
        return normalizeOrigin("https://" + serverName + portPart);
    }

    private static Map<String, ProvisionerRoute> buildRoutesByKey(Environment environment, ObjectMapper objectMapper) {
        String json = firstText(
            environment.getProperty("guacamole.provisioner.routes-json"),
            environment.getProperty("GUACAMOLE_PROVISIONER_ROUTES_JSON")
        );
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Map<String, Object>> raw = objectMapper.readValue(json, new TypeReference<>() {});
            Map<String, ProvisionerRoute> routes = new HashMap<>();
            for (Map.Entry<String, Map<String, Object>> entry : raw.entrySet()) {
                Map<String, Object> config = entry.getValue();
                String baseUrl = firstText(stringValue(config.get("baseUrl")), originOf(entry.getKey()));
                if (!StringUtils.hasText(baseUrl)) {
                    continue;
                }
                routes.put(entry.getKey().toLowerCase(), new ProvisionerRoute(
                    baseUrl,
                    Optional.ofNullable(stringValue(config.get("pathPrefix"))).filter(StringUtils::hasText)
                        .orElse("/gateway-provisioner/guacamole"),
                    Optional.ofNullable(stringValue(config.get("tokenHeader"))).filter(StringUtils::hasText)
                        .orElse("X-Guacamole-Provisioner-Token"),
                    stringValue(config.get("token"))
                ));
            }
            return routes;
        } catch (Exception ex) {
            throw new IllegalStateException("Invalid Guacamole provisioner routes JSON", ex);
        }
    }

    private static ProvisionerRoute routeFromUris(URI provisionUri, URI connectionsUri, String tokenHeader, String token) {
        if (provisionUri == null || connectionsUri == null) {
            return null;
        }
        String provision = provisionUri.toString();
        String suffix = "/provision";
        String baseAndPrefix = provision.endsWith(suffix)
            ? provision.substring(0, provision.length() - suffix.length())
            : provision;
        int slash = baseAndPrefix.indexOf('/', baseAndPrefix.indexOf("://") + 3);
        String base = slash < 0 ? baseAndPrefix : baseAndPrefix.substring(0, slash);
        String prefix = slash < 0 ? "" : baseAndPrefix.substring(slash);
        return new ProvisionerRoute(base, prefix, tokenHeader, token);
    }

    private static String originOf(String uri) {
        if (!StringUtils.hasText(uri)) {
            return null;
        }
        try {
            URI parsed = new URI(uri);
            if (!StringUtils.hasText(parsed.getScheme()) || !StringUtils.hasText(parsed.getHost())) {
                return null;
            }
            int port = parsed.getPort();
            String portPart = port < 0 ? "" : ":" + port;
            return parsed.getScheme() + "://" + parsed.getHost() + portPart;
        } catch (URISyntaxException ex) {
            return null;
        }
    }

    private static String normalizeOrigin(String origin) {
        return StringUtils.hasText(origin) ? origin.toLowerCase() : null;
    }

    private static String hostOf(String uri) {
        if (!StringUtils.hasText(uri)) {
            return null;
        }
        try {
            return new URI(uri).getHost();
        } catch (URISyntaxException ex) {
            return null;
        }
    }

    private static String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private static String stringValue(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static long longValue(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(String.valueOf(value));
    }
}
