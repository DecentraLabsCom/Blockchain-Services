package decentralabs.blockchain.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.util.GatewayIdentity;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Validates the per-Lite backend credentials that bind each request to one Gateway. */
@Service
public class LabAdminGatewayCredentialService {
    private final List<GatewayCredential> credentials;

    public LabAdminGatewayCredentialService(
        ObjectMapper objectMapper,
        @Value("${gateway.lab-manager.gateway-credentials-json:{}}") String credentialsJson
    ) {
        this.credentials = parseCredentials(objectMapper, credentialsJson);
    }

    public Optional<String> gatewayIdForToken(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        String candidate = token.trim();
        for (GatewayCredential credential : credentials) {
            if (constantTimeEquals(credential.token(), candidate)) {
                return Optional.of(credential.gatewayId());
            }
        }
        return Optional.empty();
    }

    /** Returns the configured Lite inventory without exposing its credentials. */
    public List<ConfiguredGateway> configuredGateways() {
        return credentials.stream()
            .map(credential -> new ConfiguredGateway(credential.gatewayId(), credential.accessUri()))
            .sorted(Comparator.comparing(ConfiguredGateway::gatewayId))
            .toList();
    }

    private List<GatewayCredential> parseCredentials(ObjectMapper objectMapper, String json) {
        String configured = json == null || json.isBlank() ? "{}" : json;
        try {
            JsonNode root = objectMapper.readTree(configured);
            if (root == null || !root.isObject()) {
                throw new IllegalArgumentException("Expected a JSON object");
            }
            List<GatewayCredential> parsed = new ArrayList<>();
            Set<String> seenGatewayIds = new HashSet<>();
            Set<String> seenTokens = new HashSet<>();
            for (var field : root.properties()) {
                String gatewayId = GatewayIdentity.normalizeGatewayId(field.getKey());
                JsonNode node = field.getValue();
                String token = node != null && node.isObject() ? text(node.get("token")) : null;
                String accessUri = node != null && node.isObject() ? text(node.get("accessUri")) : null;
                if (gatewayId == null || token == null || !isHttpsOrigin(accessUri)
                    || !gatewayId.equals(GatewayIdentity.fromAccessUri(accessUri))) {
                    throw new IllegalArgumentException("Invalid Gateway credential entry");
                }
                if (!seenGatewayIds.add(gatewayId) || !seenTokens.add(token)) {
                    throw new IllegalArgumentException("Duplicate Gateway credential entry");
                }
                parsed.add(new GatewayCredential(gatewayId, accessUri, token));
            }
            return List.copyOf(parsed);
        } catch (Exception ex) {
            throw new IllegalArgumentException(
                "Invalid LAB_ADMIN_GATEWAY_CREDENTIALS_JSON configuration", ex
            );
        }
    }

    private String text(JsonNode node) {
        if (node == null || !node.isTextual()) {
            return null;
        }
        String value = node.asText().trim();
        return value.isBlank() ? null : value;
    }

    private boolean isHttpsOrigin(String value) {
        if (value == null) {
            return false;
        }
        try {
            URI uri = URI.create(value);
            return "https".equalsIgnoreCase(uri.getScheme())
                && uri.getHost() != null
                && uri.getUserInfo() == null
                && uri.getQuery() == null
                && uri.getFragment() == null
                && (uri.getPath() == null || uri.getPath().isEmpty() || "/".equals(uri.getPath()));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            actual.getBytes(StandardCharsets.UTF_8)
        );
    }

    public record ConfiguredGateway(String gatewayId, String accessUri) { }

    private record GatewayCredential(String gatewayId, String accessUri, String token) { }
}
