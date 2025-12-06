package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("NoopMailSenderAdapter Tests")
class NoopMailSenderAdapterTest {

    private NoopMailSenderAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new NoopMailSenderAdapter();
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
    @DisplayName("send Tests")
    class SendTests {

        @Test
        @DisplayName("Should log message without sending")
        void shouldLogWithoutSending() {
            NotificationMessage message = createSimpleMessage(
                List.of("test@example.com"),
                "Test Subject",
                "Test Body"
            );

            // Should complete without exception
            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle multiple recipients")
        void shouldHandleMultipleRecipients() {
            NotificationMessage message = createSimpleMessage(
                List.of("user1@example.com", "user2@example.com", "user3@example.com"),
                "Multi-recipient Test",
                "Body"
            );

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle null recipients")
        void shouldHandleNullRecipients() {
            NotificationMessage message = createSimpleMessage(null, "Test", "Body");

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle empty recipients list")
        void shouldHandleEmptyRecipients() {
            NotificationMessage message = createSimpleMessage(List.of(), "Test", "Body");

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle message with ICS content")
        void shouldHandleMessageWithIcs() {
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "Calendar Event",
                "Event details",
                "<html><body>Event details</body></html>",
                "BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR",
                "event.ics"
            );

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle long subject")
        void shouldHandleLongSubject() {
            String longSubject = "A".repeat(500);
            NotificationMessage message = createSimpleMessage(
                List.of("test@example.com"),
                longSubject,
                "Body"
            );

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle null subject")
        void shouldHandleNullSubject() {
            NotificationMessage message = createSimpleMessage(
                List.of("test@example.com"),
                null,
                "Body"
            );

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle HTML body")
        void shouldHandleHtmlBody() {
            NotificationMessage message = createMessage(
                List.of("test@example.com"),
                "HTML Test",
                "Plain text",
                "<html><body><h1>Title</h1><p>Content</p></body></html>",
                null,
                null
            );

            assertDoesNotThrow(() -> adapter.send(message));
        }

        @Test
        @DisplayName("Should handle special characters in subject")
        void shouldHandleSpecialCharactersInSubject() {
            NotificationMessage message = createSimpleMessage(
                List.of("test@example.com"),
                "Test: <Special> & \"Characters\" [日本語]",
                "Body"
            );

            assertDoesNotThrow(() -> adapter.send(message));
        }
    }
}
