package decentralabs.blockchain.notification;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
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
        NotificationProperties.Smtp smtp = mailProps.getSmtp();
        if (smtp == null) {
            smtp = new NotificationProperties.Smtp();
        }
        this.mailSender = buildMailSender(smtp);
    }

    @Override
    public void send(NotificationMessage message) {
        String host = mailSender.getHost();
        if (host == null || host.isBlank()) {
            log.warn("SMTP host not configured. Skipping email notification.");
            return;
        }
        String from = mailProps.getFrom();
        if (from == null || from.isBlank()) {
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

            String fromName = mailProps.getFromName();
            if (fromName != null && !fromName.isBlank()) {
                helper.setFrom(from, fromName);
            } else {
                helper.setFrom(from);
            }

            String[] recipients = message.recipients().stream()
                .filter(Objects::nonNull)
                .toArray(String[]::new);
            if (recipients.length == 0) {
                log.warn("No recipients provided. Skipping email notification.");
                return;
            }
            helper.setTo(recipients);
            String subject = Objects.requireNonNullElse(message.subject(), "");
            helper.setSubject(Objects.requireNonNull(subject, "subject"));
            String textBody = Objects.requireNonNullElse(message.textBody(), "");
            String nonNullTextBody = Objects.requireNonNull(textBody, "textBody");
            String htmlBody = message.htmlBody();
            if (htmlBody == null || htmlBody.isBlank()) {
                helper.setText(nonNullTextBody, false);
            } else {
                String nonNullHtmlBody = Objects.requireNonNull(htmlBody, "htmlBody");
                helper.setText(nonNullTextBody, nonNullHtmlBody);
            }

            String icsContent = message.icsContent();
            if (icsContent != null && !icsContent.isBlank()) {
                byte[] icsBytes = Objects.requireNonNull(icsContent.getBytes(StandardCharsets.UTF_8), "icsBytes");
                ByteArrayResource ics = new ByteArrayResource(icsBytes);
                String contentType = "text/calendar; charset=UTF-8; method=REQUEST";
                String fileName = Objects.requireNonNull(Objects.requireNonNullElse(message.icsFileName(), "reservation.ics"), "fileName");
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
        String host = smtp.getHost() != null ? smtp.getHost() : "";
        sender.setHost(host);
        sender.setPort(smtp.getPort());
        String username = smtp.getUsername() != null ? smtp.getUsername() : "";
        String password = smtp.getPassword() != null ? smtp.getPassword() : "";
        sender.setUsername(username);
        sender.setPassword(password);
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
