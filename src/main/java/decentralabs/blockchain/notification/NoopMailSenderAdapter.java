package decentralabs.blockchain.notification;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NoopMailSenderAdapter implements MailSenderAdapter {

    @Override
    public void send(NotificationMessage message) {
        log.info(
            "Notification suppressed (driver=noop). Subject='{}' recipients={}",
            message.subject(),
            message.recipients()
        );
    }
}
