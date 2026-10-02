package decentralabs.blockchain.notification;

public interface MailSenderAdapter {
    MailSendResult send(NotificationMessage message);
}
