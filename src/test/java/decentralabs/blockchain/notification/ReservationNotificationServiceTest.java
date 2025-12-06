package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("ReservationNotificationService Tests")
class ReservationNotificationServiceTest {

    @Mock
    private MailSenderFactory mailSenderFactory;

    @Mock
    private NotificationConfigService notificationConfigService;

    @Mock
    private MailSenderAdapter mailSender;

    private ReservationNotificationService service;

    @BeforeEach
    void setUp() {
        service = new ReservationNotificationService(mailSenderFactory, notificationConfigService);
    }

    private ReservationNotificationData createTestData() {
        return new ReservationNotificationData(
            "0xreservation123",
            BigInteger.valueOf(42),
            "Physics Lab A",
            "user@university.edu",
            "University of Test",
            Instant.parse("2025-01-15T10:00:00Z"),
            Instant.parse("2025-01-15T12:00:00Z"),
            "0xtxhash123"
        );
    }

    private NotificationProperties.Mail createEnabledMailConfig() {
        NotificationProperties.Mail mail = new NotificationProperties.Mail();
        mail.setEnabled(true);
        mail.setFrom("noreply@lab.edu");
        mail.setFromName("Lab System");
        mail.setDefaultTo(List.of("admin@lab.edu"));
        mail.setTimezone("Europe/Madrid");
        return mail;
    }

    @Nested
    @DisplayName("notifyReservationApproved Tests")
    class NotifyReservationApprovedTests {

        @Test
        @DisplayName("Should skip notification when mail is disabled")
        void shouldSkipWhenDisabled() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setEnabled(false);
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            service.notifyReservationApproved(createTestData());

            verify(mailSenderFactory, never()).resolve();
        }

        @Test
        @DisplayName("Should skip notification when mail config is null")
        void shouldSkipWhenMailConfigNull() {
            when(notificationConfigService.getMailConfig()).thenReturn(null);

            service.notifyReservationApproved(createTestData());

            verify(mailSenderFactory, never()).resolve();
        }

        @Test
        @DisplayName("Should skip notification when no recipients configured")
        void shouldSkipWhenNoRecipients() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            mail.setDefaultTo(List.of());
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            service.notifyReservationApproved(createTestData());

            verify(mailSenderFactory, never()).resolve();
        }

        @Test
        @DisplayName("Should send notification with correct subject")
        void shouldSendWithCorrectSubject() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationApproved(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            NotificationMessage message = captor.getValue();
            assertTrue(message.subject().contains("Reserva aprobada"));
            assertTrue(message.subject().contains("Physics Lab A"));
        }

        @Test
        @DisplayName("Should include all recipients")
        void shouldIncludeAllRecipients() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            mail.setDefaultTo(List.of("admin@lab.edu", "manager@lab.edu"));
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationApproved(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            assertEquals(2, captor.getValue().recipients().size());
        }

        @Test
        @DisplayName("Should include HTML and text body")
        void shouldIncludeHtmlAndTextBody() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationApproved(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            NotificationMessage message = captor.getValue();
            assertNotNull(message.htmlBody());
            assertNotNull(message.textBody());
            assertTrue(message.htmlBody().contains("Physics Lab A"));
            assertTrue(message.textBody().contains("Physics Lab A"));
        }

        @Test
        @DisplayName("Should include ICS attachment")
        void shouldIncludeIcsAttachment() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationApproved(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            NotificationMessage message = captor.getValue();
            assertNotNull(message.icsFileName());
            assertTrue(message.icsFileName().contains(".ics"));
        }

        @Test
        @DisplayName("Should use lab ID when lab name is null")
        void shouldUseLabIdWhenNameNull() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            ReservationNotificationData data = new ReservationNotificationData(
                "0xreservation123",
                BigInteger.valueOf(42),
                null, // no lab name
                "user@university.edu",
                "University",
                Instant.now(),
                Instant.now().plusSeconds(7200),
                "0xtx"
            );

            service.notifyReservationApproved(data);

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            assertTrue(captor.getValue().subject().contains("Lab 42"));
        }

        @Test
        @DisplayName("Should filter duplicate and empty recipients")
        void shouldFilterDuplicateAndEmptyRecipients() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            mail.setDefaultTo(List.of("admin@lab.edu", "", "admin@lab.edu", "  ", "other@lab.edu"));
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationApproved(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            // Should have only unique, non-empty recipients
            assertEquals(2, captor.getValue().recipients().size());
        }

        @Test
        @DisplayName("Should use UTC timezone when configured timezone is invalid")
        void shouldFallbackToUtcForInvalidTimezone() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            mail.setTimezone("Invalid/Timezone");
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            // Should not throw exception
            assertDoesNotThrow(() -> service.notifyReservationApproved(createTestData()));
            verify(mailSender).send(any());
        }
    }

    @Nested
    @DisplayName("notifyReservationCancelled Tests")
    class NotifyReservationCancelledTests {

        @Test
        @DisplayName("Should skip when mail disabled")
        void shouldSkipWhenDisabled() {
            NotificationProperties.Mail mail = new NotificationProperties.Mail();
            mail.setEnabled(false);
            when(notificationConfigService.getMailConfig()).thenReturn(mail);

            service.notifyReservationCancelled(createTestData());

            verify(mailSenderFactory, never()).resolve();
        }

        @Test
        @DisplayName("Should send cancellation notification")
        void shouldSendCancellationNotification() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationCancelled(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            NotificationMessage message = captor.getValue();
            assertTrue(message.subject().contains("cancelada"));
        }

        @Test
        @DisplayName("Should include cancellation in HTML body")
        void shouldIncludeCancellationInBody() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationCancelled(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            assertTrue(captor.getValue().htmlBody().contains("cancelado") || 
                       captor.getValue().htmlBody().contains("cancelada"));
        }

        @Test
        @DisplayName("Should include cancel ICS filename")
        void shouldIncludeCancelIcsFilename() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationCancelled(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            
            assertTrue(captor.getValue().icsFileName().contains("cancel"));
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null renter")
        void shouldHandleNullRenter() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            ReservationNotificationData data = new ReservationNotificationData(
                "0xres", BigInteger.ONE, "Lab", null, null, Instant.now(), Instant.now(), "0xtx"
            );

            assertDoesNotThrow(() -> service.notifyReservationApproved(data));
            verify(mailSender).send(any());
        }

        @Test
        @DisplayName("Should handle null dates")
        void shouldHandleNullDates() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            ReservationNotificationData data = new ReservationNotificationData(
                "0xres", BigInteger.ONE, "Lab", "user@test.edu", "Uni", null, null, "0xtx"
            );

            assertDoesNotThrow(() -> service.notifyReservationApproved(data));
            
            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            assertTrue(captor.getValue().htmlBody().contains("Sin fecha"));
        }

        @Test
        @DisplayName("Should handle blank timezone as UTC")
        void shouldHandleBlankTimezone() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            mail.setTimezone("");
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            assertDoesNotThrow(() -> service.notifyReservationApproved(createTestData()));
            verify(mailSender).send(any());
        }

        @Test
        @DisplayName("Should handle recipients with null entries")
        void shouldHandleNullRecipientEntries() {
            NotificationProperties.Mail mail = createEnabledMailConfig();
            java.util.ArrayList<String> recipients = new java.util.ArrayList<>();
            recipients.add("valid@test.edu");
            recipients.add(null);
            recipients.add("other@test.edu");
            mail.setDefaultTo(recipients);
            
            when(notificationConfigService.getMailConfig()).thenReturn(mail);
            when(mailSenderFactory.resolve()).thenReturn(mailSender);

            service.notifyReservationApproved(createTestData());

            ArgumentCaptor<NotificationMessage> captor = ArgumentCaptor.forClass(NotificationMessage.class);
            verify(mailSender).send(captor.capture());
            assertEquals(2, captor.getValue().recipients().size());
        }
    }
}
