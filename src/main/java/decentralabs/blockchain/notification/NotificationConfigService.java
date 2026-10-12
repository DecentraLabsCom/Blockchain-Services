package decentralabs.blockchain.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import decentralabs.blockchain.service.BackendUrlResolver;
import decentralabs.blockchain.util.GatewayIdentity;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Stores an independent mail configuration for each Gateway. */
@Service
@Slf4j
public class NotificationConfigService {

    private static final int CONFIG_VERSION = 2;

    private final NotificationProperties properties;
    private final ObjectMapper objectMapper;
    private final BackendUrlResolver backendUrlResolver;
    private final String issuer;
    private final String labManagerToken;
    private final Map<String, NotificationProperties.Mail> gatewayConfigs = new LinkedHashMap<>();
    private NotificationProperties.Mail unassignedLegacyConfig;
    private String localGatewayId;

    @Autowired
    public NotificationConfigService(
        NotificationProperties properties,
        ObjectMapper objectMapper,
        BackendUrlResolver backendUrlResolver,
        @Value("${ISSUER:}") String issuer,
        @Value("${gateway.lab-manager.token:}") String labManagerToken
    ) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.backendUrlResolver = backendUrlResolver;
        this.issuer = issuer;
        this.labManagerToken = labManagerToken;
    }

    /** Constructor retained for isolated service tests. */
    public NotificationConfigService(NotificationProperties properties, ObjectMapper objectMapper) {
        this(properties, objectMapper, null, "", "");
    }

    @jakarta.annotation.PostConstruct
    public synchronized void init() {
        localGatewayId = resolveLocalGatewayId();
        loadFromDiskIfPresent();
    }

    public synchronized NotificationProperties.Mail getMailConfig(String gatewayId) {
        String normalizedGatewayId = requireGatewayId(gatewayId);
        NotificationProperties.Mail configured = gatewayConfigs.get(normalizedGatewayId);
        if (configured != null) {
            return copy(configured);
        }
        if (normalizedGatewayId.equals(localGatewayId)) {
            return copy(properties.getMail());
        }
        return new NotificationProperties.Mail();
    }

    public synchronized Map<String, Object> getPublicConfig(String gatewayId) {
        return publicConfig(getMailConfig(gatewayId));
    }

    public synchronized NotificationProperties.Mail updateMailConfig(
        String gatewayId,
        NotificationUpdateRequest request
    ) {
        String normalizedGatewayId = requireGatewayId(gatewayId);
        NotificationProperties.Mail updated = getMailConfig(normalizedGatewayId);
        applyUpdate(updated, request);
        List<String> errors = validateMail(updated);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(String.join("; ", errors));
        }
        gatewayConfigs.put(normalizedGatewayId, copy(updated));
        persistConfig();
        return copy(updated);
    }

    public synchronized List<String> validateUpdate(
        String gatewayId,
        NotificationUpdateRequest request
    ) {
        NotificationProperties.Mail snapshot = getMailConfig(gatewayId);
        applyUpdate(snapshot, request);
        return validateMail(snapshot);
    }

    public synchronized List<String> validateMailConfig(String gatewayId) {
        return validateMail(getMailConfig(gatewayId));
    }

    public synchronized NotificationProperties.Mail getLocalMailConfig() {
        return localGatewayId == null ? new NotificationProperties.Mail() : getMailConfig(localGatewayId);
    }

    public synchronized void loadFromDiskIfPresent() {
        Path path = configPath();
        if (!Files.exists(path)) {
            return;
        }
        try {
            JsonNode root = objectMapper.readTree(path.toFile());
            if (root == null || !root.isObject()) {
                throw new IllegalArgumentException("Expected a JSON object");
            }
            if (root.path("gateways").isObject()) {
                loadGatewayConfigs(root.path("gateways"));
                JsonNode legacy = root.get("unassignedLegacy");
                if (legacy != null && legacy.isObject()) {
                    unassignedLegacyConfig = objectMapper.treeToValue(
                        legacy,
                        NotificationProperties.Mail.class
                    );
                }
                return;
            }

            // A pre-v2 file contained one global mail config. Keep it local to
            // the Full Gateway when this backend actually owns a Lab Manager.
            // A standalone authority has no single Gateway to inherit it.
            NotificationProperties.Mail legacy = objectMapper.treeToValue(
                root,
                NotificationProperties.Mail.class
            );
            if (localGatewayId != null) {
                gatewayConfigs.put(localGatewayId, legacy);
                persistConfig();
            } else {
                unassignedLegacyConfig = legacy;
                log.warn("Legacy global notification config is unassigned; configure mail separately for each Gateway.");
            }
        } catch (Exception ex) {
            log.warn("Failed to load per-Gateway notification config from {}: {}", path, ex.getMessage());
        }
    }

    private String resolveLocalGatewayId() {
        if (labManagerToken == null || labManagerToken.isBlank()
            || (issuer != null && !issuer.isBlank())
            || backendUrlResolver == null) {
            return null;
        }
        return GatewayIdentity.fromAccessUri(backendUrlResolver.resolveBaseDomain());
    }

    private void loadGatewayConfigs(JsonNode configuredGateways) throws IOException {
        configuredGateways.properties().forEach(entry -> {
            String gatewayId = GatewayIdentity.normalizeGatewayId(entry.getKey());
            if (gatewayId == null || !entry.getValue().isObject()) {
                log.warn("Ignoring invalid Gateway notification config entry");
                return;
            }
            try {
                gatewayConfigs.put(
                    gatewayId,
                    objectMapper.treeToValue(entry.getValue(), NotificationProperties.Mail.class)
                );
            } catch (Exception ex) {
                log.warn("Ignoring unreadable notification config for Gateway {}", gatewayId);
            }
        });
    }

    private void applyUpdate(NotificationProperties.Mail mail, NotificationUpdateRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Notification config is required");
        }
        if (request.enabled() != null) mail.setEnabled(request.enabled());
        if (request.driver() != null) mail.setDriver(request.driver());
        if (request.from() != null) mail.setFrom(request.from());
        if (request.fromName() != null) mail.setFromName(request.fromName());
        if (request.defaultTo() != null) mail.setDefaultTo(normalizeRecipients(request.defaultTo()));
        if (request.timezone() != null) mail.setTimezone(request.timezone());

        NotificationProperties.Smtp smtp = mail.getSmtp();
        if (smtp != null && request.smtp() != null) {
            NotificationUpdateRequest.Smtp input = request.smtp();
            if (input.host() != null) smtp.setHost(input.host());
            if (input.port() != null) smtp.setPort(input.port());
            if (input.username() != null) smtp.setUsername(input.username());
            if (hasText(input.password())) smtp.setPassword(input.password());
            if (input.auth() != null) smtp.setAuth(input.auth());
            if (input.startTls() != null) smtp.setStartTls(input.startTls());
            if (input.timeoutMs() != null) smtp.setTimeoutMs(input.timeoutMs());
        }

        NotificationProperties.Graph graph = mail.getGraph();
        if (graph != null && request.graph() != null) {
            NotificationUpdateRequest.Graph input = request.graph();
            if (input.tenantId() != null) graph.setTenantId(input.tenantId());
            if (input.clientId() != null) graph.setClientId(input.clientId());
            if (hasText(input.clientSecret())) graph.setClientSecret(input.clientSecret());
            if (input.from() != null) graph.setFrom(input.from());
        }
    }

    private Map<String, Object> publicConfig(NotificationProperties.Mail mail) {
        NotificationProperties.Smtp smtpConfig = mail.getSmtp();
        Map<String, Object> smtp = new LinkedHashMap<>();
        smtp.put("host", smtpConfig.getHost());
        smtp.put("port", smtpConfig.getPort());
        smtp.put("username", smtpConfig.getUsername());
        smtp.put("auth", smtpConfig.isAuth());
        smtp.put("startTls", smtpConfig.isStartTls());
        smtp.put("timeoutMs", smtpConfig.getTimeoutMs());
        smtp.put("passwordConfigured", hasText(smtpConfig.getPassword()));

        NotificationProperties.Graph graphConfig = mail.getGraph();
        Map<String, Object> graph = new LinkedHashMap<>();
        graph.put("tenantId", graphConfig.getTenantId());
        graph.put("clientId", graphConfig.getClientId());
        graph.put("from", graphConfig.getFrom());
        graph.put("clientSecretConfigured", hasText(graphConfig.getClientSecret()));

        Map<String, Object> config = new LinkedHashMap<>();
        config.put("enabled", mail.isEnabled());
        config.put("driver", mail.getDriver());
        config.put("from", mail.getFrom());
        config.put("fromName", mail.getFromName());
        config.put("defaultTo", mail.getDefaultTo());
        config.put("timezone", mail.getTimezone());
        config.put("smtp", smtp);
        config.put("graph", graph);
        return config;
    }

    private List<String> validateMail(NotificationProperties.Mail mail) {
        List<String> errors = new ArrayList<>();
        MailDriver driver = mail.getDriver() != null ? mail.getDriver() : MailDriver.NOOP;
        if (!mail.isEnabled() || driver == MailDriver.NOOP) {
            return errors;
        }
        if (driver == MailDriver.SMTP) {
            NotificationProperties.Smtp smtp = mail.getSmtp();
            if (smtp == null) {
                errors.add("SMTP settings are required");
            } else {
                if (!hasText(smtp.getHost())) errors.add("SMTP host is required");
                if (smtp.getPort() <= 0) errors.add("SMTP port must be > 0");
                if (smtp.isAuth()) {
                    if (!hasText(smtp.getUsername())) errors.add("SMTP username is required when auth=true");
                    if (!hasText(smtp.getPassword())) errors.add("SMTP password is required when auth=true");
                }
            }
        } else if (driver == MailDriver.GRAPH) {
            NotificationProperties.Graph graph = mail.getGraph();
            if (graph == null) {
                errors.add("Graph settings are required");
            } else {
                if (!hasText(graph.getTenantId())) errors.add("Graph tenantId is required");
                if (!hasText(graph.getClientId())) errors.add("Graph clientId is required");
                if (!hasText(graph.getClientSecret())) errors.add("Graph clientSecret is required");
                if (!hasText(graph.getFrom()) && !hasText(mail.getFrom())) {
                    errors.add("Graph from is required (graph.from or mail.from)");
                }
            }
        }
        return errors;
    }

    private NotificationProperties.Mail copy(NotificationProperties.Mail mail) {
        return objectMapper.convertValue(mail, NotificationProperties.Mail.class);
    }

    private String requireGatewayId(String value) {
        String gatewayId = GatewayIdentity.normalizeGatewayId(value);
        if (gatewayId == null) {
            throw new IllegalArgumentException("A valid Gateway ID is required");
        }
        return gatewayId;
    }

    private void persistConfig() {
        Path path = configPath();
        Path temporary = null;
        try {
            if (path.getParent() != null) Files.createDirectories(path.getParent());
            ObjectNode root = objectMapper.createObjectNode();
            root.put("version", CONFIG_VERSION);
            ObjectNode gatewayNode = root.putObject("gateways");
            for (Map.Entry<String, NotificationProperties.Mail> entry : gatewayConfigs.entrySet()) {
                gatewayNode.set(entry.getKey(), objectMapper.valueToTree(entry.getValue()));
            }
            if (unassignedLegacyConfig != null) {
                root.set("unassignedLegacy", objectMapper.valueToTree(unassignedLegacyConfig));
            }
            byte[] serialized = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(root);
            String prefix = path.getFileName().toString();
            try {
                var ownerOnly = PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")
                );
                temporary = path.getParent() == null
                    ? Files.createTempFile(prefix, ".tmp", ownerOnly)
                    : Files.createTempFile(path.getParent(), prefix, ".tmp", ownerOnly);
            } catch (UnsupportedOperationException ex) {
                temporary = path.getParent() == null
                    ? Files.createTempFile(prefix, ".tmp")
                    : Files.createTempFile(path.getParent(), prefix, ".tmp");
            }
            Files.write(temporary, serialized);
            try {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
            temporary = null;
            try {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // Windows deployments rely on the protected Docker secret/data directory ACL.
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to persist Gateway notification config", ex);
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // Preserve the original persistence error.
                }
            }
        }
    }

    private Path configPath() {
        return Path.of(properties.getConfigFile());
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private List<String> normalizeRecipients(List<String> recipients) {
        if (recipients == null || recipients.isEmpty()) {
            return List.of();
        }
        return recipients.stream()
            .map(value -> value == null ? "" : value.trim())
            .filter(value -> !value.isEmpty())
            .toList();
    }
}
