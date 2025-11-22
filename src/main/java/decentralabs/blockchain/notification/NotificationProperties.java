package decentralabs.blockchain.notification;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "notifications")
public class NotificationProperties {

    private Mail mail = new Mail();
    /**
     * Optional path to persist runtime overrides (set via API).
     */
    private String configFile = "./data/notifications-config.json";

    @Data
    public static class Mail {
        private boolean enabled = true;
        private MailDriver driver = MailDriver.NOOP;
        private String from;
        private String fromName;
        private List<String> defaultTo = new ArrayList<>();
        private String timezone = "UTC";
        private Smtp smtp = new Smtp();
        private Graph graph = new Graph();
    }

    @Data
    public static class Smtp {
        private String host;
        private int port = 587;
        private String username;
        private String password;
        private boolean auth = true;
        private boolean startTls = true;
        private int timeoutMs = 10000;
    }

    @Data
    public static class Graph {
        private String tenantId;
        private String clientId;
        private String clientSecret;
        private String from;
    }
}
