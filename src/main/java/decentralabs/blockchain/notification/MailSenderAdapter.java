package decentralabs.blockchain.notification;

public interface MailSenderAdapter {
    void send(NotificationMessage message);
}
