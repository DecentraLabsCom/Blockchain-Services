package decentralabs.blockchain.notification;

import java.util.List;

public record NotificationUpdateRequest(
    Boolean enabled,
    MailDriver driver,
    String from,
    String fromName,
    List<String> defaultTo,
    String timezone,
    Smtp smtp,
    Graph graph
) {
    public record Smtp(
        String host,
        Integer port,
        String username,
        String password,
        Boolean auth,
        Boolean startTls,
        Integer timeoutMs
    ) { }

    public record Graph(
        String tenantId,
        String clientId,
        String clientSecret,
        String from
    ) { }
}
