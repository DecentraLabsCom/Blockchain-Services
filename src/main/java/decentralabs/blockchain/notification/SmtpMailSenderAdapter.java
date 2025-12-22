package decentralabs.blockchain.notification;

import java.nio.charset.StandardCharsets;
import java.util.Properties;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

@Slf4j
public class SmtpMailSenderAdapter implements MailSenderAdapter {

    private final JavaMailSenderImpl mailSender;
    private final NotificationProperties.Mail mailProps;

    public SmtpMailSenderAdapter(NotificationProperties.Mail mailProps) {
        this.mailProps = mailProps;
        this.mailSender = buildMailSender(mailProps.getSmtp());
    }

    @Override
    public void send(NotificationMessage message) {
        String host = mailSender.getHost();
        if (host == null || host.isBlank()) {
            log.warn("SMTP host not configured. Skipping email notification.");
            return;
        }
        if (mailProps.getFrom() == null || mailProps.getFrom().isBlank()) {
            log.warn("SMTP sender (notifications.mail.from) not configured. Skipping email notification.");
            return;
        }

        if (message.recipients() == null || message.recipients().isEmpty()) {
            log.warn("No recipients provided. Skipping email notification.");
            return;
        }

        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, StandardCharsets.UTF_8.name());

            if (mailProps.getFromName() != null && !mailProps.getFromName().isBlank()) {
                helper.setFrom(mailProps.getFrom(), mailProps.getFromName());
            } else {
                helper.setFrom(mailProps.getFrom());
            }

            helper.setTo(message.recipients().toArray(new String[0]));
            helper.setSubject(message.subject());
            String textBody = message.textBody() != null ? message.textBody() : "";
            String htmlBody = message.htmlBody();
            if (htmlBody == null || htmlBody.isBlank()) {
                helper.setText(textBody, false);
            } else {
                helper.setText(textBody, htmlBody);
            }

            if (message.icsContent() != null && !message.icsContent().isBlank()) {
                ByteArrayResource ics = new ByteArrayResource(message.icsContent().getBytes(StandardCharsets.UTF_8));
                String contentType = "text/calendar; charset=UTF-8; method=REQUEST";
                String fileName = message.icsFileName() != null ? message.icsFileName() : "reservation.ics";
                helper.addAttachment(fileName, ics, contentType);
                helper.addInline("invite", ics, contentType);
            }

            mailSender.send(mimeMessage);
            log.info("Sent reservation notification via SMTP to {}", message.recipients());
        } catch (Exception ex) {
            log.error("Failed to send reservation notification via SMTP: {}", ex.getMessage(), ex);
        }
    }

    private JavaMailSenderImpl buildMailSender(NotificationProperties.Smtp smtp) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(smtp.getHost());
        sender.setPort(smtp.getPort());
        sender.setUsername(smtp.getUsername());
        sender.setPassword(smtp.getPassword());
        sender.setDefaultEncoding(StandardCharsets.UTF_8.name());

        Properties props = sender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", String.valueOf(smtp.isAuth()));
        props.put("mail.smtp.starttls.enable", String.valueOf(smtp.isStartTls()));
        props.put("mail.smtp.connectiontimeout", smtp.getTimeoutMs());
        props.put("mail.smtp.timeout", smtp.getTimeoutMs());
        props.put("mail.smtp.writetimeout", smtp.getTimeoutMs());
        return sender;
    }
}
