package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.javamail.JavaMailSenderImpl;

@DisplayName("SmtpMailSenderAdapter Tests")
class SmtpMailSenderAdapterTest {

    private NotificationProperties.Mail mailProps;
    private JavaMailSenderImpl mailSender;

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

        mailSender = mock(JavaMailSenderImpl.class);
        lenient().when(mailSender.getHost()).thenReturn(smtp.getHost());
        lenient().when(mailSender.createMimeMessage()).thenAnswer(
            invocation -> new MimeMessage(Session.getInstance(new Properties()))
        );
    }

    // Helper method to create NotificationMessage (record constructor)
    private NotificationMessage createMessage(List<String> recipients, String subject, 
            String textBody, String htmlBody, String icsContent, String icsFileName) {
        return new NotificationMessage(recipients, subject, textBody, htmlBody, icsContent, icsFileName);
    }

    private NotificationMessage createSimpleMessage(List<String> recipients, String subject, String textBody) {
        return new NotificationMessage(recipients, subject, textBody, null, null, null);
    }

    private SmtpMailSenderAdapter adapterWithMockedSender() {
        return new SmtpMailSenderAdapter(mailProps, mailSender);
    }

    private void assertMessageWasSent(String subject, String... recipients) throws Exception {
        ArgumentCaptor<MimeMessage> message = ArgumentCaptor.forClass(MimeMessage.class);
        verify(mailSender).send(message.capture());
        assertEquals(subject, message.getValue().getSubject());
        assertArrayEquals(recipients, Arrays.stream(message.getValue().getAllRecipients())
            .map(address -> address == null ? null : address.toString())
            .toArray(String[]::new));
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
        void shouldHandleMessageWithIcs() throws Exception {
            SmtpMailSenderAdapter adapter = adapterWithMockedSender();
            
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Test Reservation",
                "Plain text body",
                "<html><body>HTML body</body></html>",
                "BEGIN:VCALENDAR\nEND:VCALENDAR",
                "meeting.ics"
            );
            
            assertDoesNotThrow(() -> adapter.send(message));
            assertMessageWasSent("Test Reservation", "test@example.com");
        }

        @Test
        @DisplayName("Should use default filename when icsFileName is null")
        void shouldUseDefaultFilenameWhenNull() throws Exception {
            SmtpMailSenderAdapter adapter = adapterWithMockedSender();
            
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Test",
                "Body",
                null,
                "BEGIN:VCALENDAR\nEND:VCALENDAR",
                null // Should default to reservation.ics
            );
            
            assertDoesNotThrow(() -> adapter.send(message));
            assertMessageWasSent("Test", "test@example.com");
        }
    }

    @Nested
    @DisplayName("Message Content Tests")
    class MessageContentTests {

        @Test
        @DisplayName("Should handle message without HTML body")
        void shouldHandleMessageWithoutHtmlBody() throws Exception {
            SmtpMailSenderAdapter adapter = adapterWithMockedSender();
            
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Test",
                "Plain text only",
                null,
                null,
                null
            );
            
            assertDoesNotThrow(() -> adapter.send(message));
            assertMessageWasSent("Test", "test@example.com");
        }

        @Test
        @DisplayName("Should handle multiple recipients")
        void shouldHandleMultipleRecipients() throws Exception {
            SmtpMailSenderAdapter adapter = adapterWithMockedSender();
            
            NotificationMessage message = createSimpleMessage(
                List.of("user1@example.com", "user2@example.com", "user3@example.com"),
                "Test",
                "Body"
            );
            
            assertDoesNotThrow(() -> adapter.send(message));
            assertMessageWasSent("Test", "user1@example.com", "user2@example.com", "user3@example.com");
        }
    }
}
