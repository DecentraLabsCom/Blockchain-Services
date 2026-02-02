package decentralabs.blockchain.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationConfigService {

    private final NotificationProperties properties;
    private final ObjectMapper objectMapper;

    @jakarta.annotation.PostConstruct
    public void init() {
        loadFromDiskIfPresent();
    }

    public NotificationProperties.Mail getMailConfig() {
        return properties.getMail();
    }

    public NotificationProperties.Mail updateMailConfig(NotificationUpdateRequest request) {
        List<String> errors = validateUpdate(request);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(String.join("; ", errors));
        }
        NotificationProperties.Mail mail = properties.getMail();
        applyUpdate(mail, request);
        persistConfig(mail);
        return mail;
    }

    public List<String> validateUpdate(NotificationUpdateRequest request) {
        NotificationProperties.Mail snapshot = objectMapper.convertValue(properties.getMail(), NotificationProperties.Mail.class);
        applyUpdate(snapshot, request);
        return validateMail(snapshot);
    }

    private void applyUpdate(NotificationProperties.Mail mail, NotificationUpdateRequest request) {
        if (request.enabled() != null) {
            mail.setEnabled(request.enabled());
        }
        if (request.driver() != null) {
            mail.setDriver(request.driver());
        }
        if (request.from() != null) {
            mail.setFrom(request.from());
        }
        if (request.fromName() != null) {
            mail.setFromName(request.fromName());
        }
        if (request.defaultTo() != null) {
            mail.setDefaultTo(normalizeRecipients(request.defaultTo()));
        }
        if (request.timezone() != null) {
            mail.setTimezone(request.timezone());
        }

        NotificationProperties.Smtp smtp = mail.getSmtp();
        if (smtp != null && request.smtp() != null) {
            NotificationUpdateRequest.Smtp reqSmtp = request.smtp();
            if (reqSmtp.host() != null) smtp.setHost(reqSmtp.host());
            if (reqSmtp.port() != null) smtp.setPort(reqSmtp.port());
            if (reqSmtp.username() != null) smtp.setUsername(reqSmtp.username());
            if (reqSmtp.password() != null) smtp.setPassword(reqSmtp.password());
            if (reqSmtp.auth() != null) smtp.setAuth(reqSmtp.auth());
            if (reqSmtp.startTls() != null) smtp.setStartTls(reqSmtp.startTls());
            if (reqSmtp.timeoutMs() != null) smtp.setTimeoutMs(reqSmtp.timeoutMs());
        }

        NotificationProperties.Graph graph = mail.getGraph();
        if (graph != null && request.graph() != null) {
            NotificationUpdateRequest.Graph reqGraph = request.graph();
            if (reqGraph.tenantId() != null) graph.setTenantId(reqGraph.tenantId());
            if (reqGraph.clientId() != null) graph.setClientId(reqGraph.clientId());
            if (reqGraph.clientSecret() != null) graph.setClientSecret(reqGraph.clientSecret());
            if (reqGraph.from() != null) graph.setFrom(reqGraph.from());
        }
    }

    public Map<String, Object> getPublicConfig() {
        NotificationProperties.Mail mail = properties.getMail();
        return Map.of(
            "enabled", mail.isEnabled(),
            "driver", mail.getDriver(),
            "from", mail.getFrom(),
            "fromName", mail.getFromName(),
            "defaultTo", mail.getDefaultTo(),
            "timezone", mail.getTimezone(),
            "smtp", Map.of(
                "host", mail.getSmtp().getHost(),
                "port", mail.getSmtp().getPort(),
                "username", mail.getSmtp().getUsername()
            ),
            "graph", Map.of(
                "tenantId", mail.getGraph().getTenantId(),
                "clientId", mail.getGraph().getClientId(),
                "from", mail.getGraph().getFrom()
            )
        );
    }

    public void loadFromDiskIfPresent() {
        Path path = Path.of(properties.getConfigFile());
        if (!Files.exists(path)) {
            return;
        }
        try {
            NotificationProperties.Mail loaded = objectMapper.readValue(path.toFile(), NotificationProperties.Mail.class);
            mergeMailConfig(loaded);
            log.info("Loaded notification mail config from {}", path);
        } catch (IOException e) {
            log.warn("Failed to load notification config from {}: {}", path, e.getMessage());
        }
    }

    private void mergeMailConfig(NotificationProperties.Mail loaded) {
        if (loaded == null) {
            return;
        }
        NotificationProperties.Mail mail = properties.getMail();
        mail.setEnabled(loaded.isEnabled());
        Optional.ofNullable(loaded.getDriver()).ifPresent(mail::setDriver);
        Optional.ofNullable(loaded.getFrom()).ifPresent(mail::setFrom);
        Optional.ofNullable(loaded.getFromName()).ifPresent(mail::setFromName);
        Optional.ofNullable(loaded.getDefaultTo()).ifPresent(list -> mail.setDefaultTo(normalizeRecipients(list)));
        Optional.ofNullable(loaded.getTimezone()).ifPresent(mail::setTimezone);

        if (loaded.getSmtp() != null) {
            NotificationProperties.Smtp smtp = mail.getSmtp();
            Optional.ofNullable(loaded.getSmtp().getHost()).ifPresent(smtp::setHost);
            smtp.setPort(loaded.getSmtp().getPort());
            Optional.ofNullable(loaded.getSmtp().getUsername()).ifPresent(smtp::setUsername);
            Optional.ofNullable(loaded.getSmtp().getPassword()).ifPresent(smtp::setPassword);
            smtp.setAuth(loaded.getSmtp().isAuth());
            smtp.setStartTls(loaded.getSmtp().isStartTls());
            smtp.setTimeoutMs(loaded.getSmtp().getTimeoutMs());
        }
        if (loaded.getGraph() != null) {
            NotificationProperties.Graph graph = mail.getGraph();
            Optional.ofNullable(loaded.getGraph().getTenantId()).ifPresent(graph::setTenantId);
            Optional.ofNullable(loaded.getGraph().getClientId()).ifPresent(graph::setClientId);
            Optional.ofNullable(loaded.getGraph().getClientSecret()).ifPresent(graph::setClientSecret);
            Optional.ofNullable(loaded.getGraph().getFrom()).ifPresent(graph::setFrom);
        }
    }

    private void persistConfig(NotificationProperties.Mail mail) {
        Path path = Path.of(properties.getConfigFile());
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), mail);
        } catch (IOException e) {
            log.warn("Failed to persist notification config to {}: {}", path, e.getMessage());
        }
    }

    public List<String> validateMailConfig() {
        return validateMail(properties.getMail());
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
                if (smtp.getHost() == null || smtp.getHost().isBlank()) {
                    errors.add("SMTP host is required");
                }
                if (smtp.getPort() <= 0) {
                    errors.add("SMTP port must be > 0");
                }
                if (smtp.isAuth()) {
                    if (smtp.getUsername() == null || smtp.getUsername().isBlank()) {
                        errors.add("SMTP username is required when auth=true");
                    }
                    if (smtp.getPassword() == null || smtp.getPassword().isBlank()) {
                        errors.add("SMTP password is required when auth=true");
                    }
                }
            }
        } else if (driver == MailDriver.GRAPH) {
            NotificationProperties.Graph graph = mail.getGraph();
            if (graph == null) {
                errors.add("Graph settings are required");
            } else {
                if (graph.getTenantId() == null || graph.getTenantId().isBlank()) {
                    errors.add("Graph tenantId is required");
                }
                if (graph.getClientId() == null || graph.getClientId().isBlank()) {
                    errors.add("Graph clientId is required");
                }
                if (graph.getClientSecret() == null || graph.getClientSecret().isBlank()) {
                    errors.add("Graph clientSecret is required");
                }
                boolean hasFrom = (graph.getFrom() != null && !graph.getFrom().isBlank())
                    || (mail.getFrom() != null && !mail.getFrom().isBlank());
                if (!hasFrom) {
                    errors.add("Graph from is required (graph.from or mail.from)");
                }
            }
        }
        return errors;
    }

    private List<String> normalizeRecipients(List<String> recipients) {
        if (CollectionUtils.isEmpty(recipients)) {
            return List.of();
        }
        return recipients.stream()
            .filter(Objects::nonNull)
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .collect(Collectors.toCollection(ArrayList::new));
    }
}
