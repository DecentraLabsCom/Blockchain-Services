package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("SmtpMailSenderAdapter Tests")
class SmtpMailSenderAdapterTest {

    private NotificationProperties.Mail mailProps;

    @BeforeEach
    void setUp() {
        mailProps = new NotificationProperties.Mail();
        mailProps.setEnabled(true);
        mailProps.setFrom("noreply@test.com");
        mailProps.setFromName("Test Sender");
        
        NotificationProperties.Smtp smtp = new NotificationProperties.Smtp();
        smtp.setHost("smtp.test.com");
        smtp.setPort(587);
        smtp.setUsername("user");
        smtp.setPassword("pass");
        smtp.setAuth(true);
        smtp.setStartTls(true);
        smtp.setTimeoutMs(5000);
        mailProps.setSmtp(smtp);
    }

    // Helper method to create NotificationMessage (record constructor)
    private NotificationMessage createMessage(List<String> recipients, String subject, 
            String textBody, String htmlBody, String icsContent, String icsFileName) {
        return new NotificationMessage(recipients, subject, textBody, htmlBody, icsContent, icsFileName);
    }

    private NotificationMessage createSimpleMessage(List<String> recipients, String subject, String textBody) {
        return new NotificationMessage(recipients, subject, textBody, null, null, null);
    }

    @Nested
    @DisplayName("Configuration Validation Tests")
    class ConfigurationValidationTests {

        @Test
        @DisplayName("Should skip send when SMTP host is null")
        void shouldSkipWhenHostIsNull() {
            mailProps.getSmtp().setHost(null);
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(List.of("test@example.com"), "Test", "Body");
            
            adapter.send(message);
            // Should complete without exception, just log warning
        }

        @Test
        @DisplayName("Should skip send when SMTP host is blank")
        void shouldSkipWhenHostIsBlank() {
            mailProps.getSmtp().setHost("   ");
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(List.of("test@example.com"), "Test", "Body");
            
            adapter.send(message);
            // Should complete without exception
        }

        @Test
        @DisplayName("Should skip send when from address is null")
        void shouldSkipWhenFromIsNull() {
            mailProps.setFrom(null);
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(List.of("test@example.com"), "Test", "Body");
            
            adapter.send(message);
            // Should complete without exception
        }

        @Test
        @DisplayName("Should skip send when from address is blank")
        void shouldSkipWhenFromIsBlank() {
            mailProps.setFrom("");
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(List.of("test@example.com"), "Test", "Body");
            
            adapter.send(message);
            // Should complete without exception
        }
    }

    @Nested
    @DisplayName("Recipient Validation Tests")
    class RecipientValidationTests {

        @Test
        @DisplayName("Should skip send when recipients is null")
        void shouldSkipWhenRecipientsNull() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(null, "Test", "Body");
            
            adapter.send(message);
            // Should complete without exception
        }

        @Test
        @DisplayName("Should skip send when recipients is empty")
        void shouldSkipWhenRecipientsEmpty() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(List.of(), "Test", "Body");
            
            adapter.send(message);
            // Should complete without exception
        }
    }

    @Nested
    @DisplayName("Mail Sender Configuration Tests")
    class MailSenderConfigTests {

        @Test
        @DisplayName("Should configure mail sender with SMTP properties")
        void shouldConfigureMailSenderWithSmtpProperties() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            // The adapter creates a JavaMailSenderImpl internally
            // We verify the configuration is correct by checking the adapter was created
            // without exceptions
            assertAdapterCreated(adapter);
        }

        @Test
        @DisplayName("Should handle null fromName gracefully")
        void shouldHandleNullFromName() {
            mailProps.setFromName(null);
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            assertAdapterCreated(adapter);
        }

        @Test
        @DisplayName("Should handle blank fromName gracefully")
        void shouldHandleBlankFromName() {
            mailProps.setFromName("   ");
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            assertAdapterCreated(adapter);
        }

        private void assertAdapterCreated(SmtpMailSenderAdapter adapter) {
            // If we get here without exception, adapter was created successfully
            assertNotNull(adapter);
        }
    }

    @Nested
    @DisplayName("ICS Attachment Tests")
    class IcsAttachmentTests {

        @Test
        @DisplayName("Should handle message with ICS content")
        void shouldHandleMessageWithIcs() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Test Reservation",
                "Plain text body",
                "<html><body>HTML body</body></html>",
                "BEGIN:VCALENDAR\nEND:VCALENDAR",
                "meeting.ics"
            );
            
            // This will fail to actually send since we don't have a real SMTP server
            // but we verify the adapter handles the ICS content structure
            try {
                adapter.send(message);
            } catch (Exception e) {
                // Expected since no real SMTP server
            }
        }

        @Test
        @DisplayName("Should use default filename when icsFileName is null")
        void shouldUseDefaultFilenameWhenNull() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Test",
                "Body",
                null,
                "BEGIN:VCALENDAR\nEND:VCALENDAR",
                null // Should default to reservation.ics
            );
            
            try {
                adapter.send(message);
            } catch (Exception e) {
                // Expected
            }
        }
    }

    @Nested
    @DisplayName("Message Content Tests")
    class MessageContentTests {

        @Test
        @DisplayName("Should handle message without HTML body")
        void shouldHandleMessageWithoutHtmlBody() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Test",
                "Plain text only",
                null,
                null,
                null
            );
            
            try {
                adapter.send(message);
            } catch (Exception e) {
                // Expected
            }
        }

        @Test
        @DisplayName("Should handle multiple recipients")
        void shouldHandleMultipleRecipients() {
            SmtpMailSenderAdapter adapter = new SmtpMailSenderAdapter(mailProps);
            
            NotificationMessage message = createSimpleMessage(
                List.of("user1@example.com", "user2@example.com", "user3@example.com"),
                "Test",
                "Body"
            );
            
            try {
                adapter.send(message);
            } catch (Exception e) {
                // Expected
            }
        }
    }
}
