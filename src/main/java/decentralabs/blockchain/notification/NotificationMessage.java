package decentralabs.blockchain.notification;

import java.util.List;

public record NotificationMessage(
    List<String> recipients,
    String subject,
    String textBody,
    String htmlBody,
    String icsContent,
    String icsFileName
) { }
