package decentralabs.blockchain.notification;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReservationNotificationService {

    private static final DateTimeFormatter HUMAN_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z");

    private final MailSenderFactory mailSenderFactory;
    private final NotificationConfigService notificationConfigService;
    private final IcsBuilder icsBuilder = new IcsBuilder();

    public void notifyReservationApproved(ReservationNotificationData data) {
        NotificationProperties.Mail mail = notificationConfigService.getMailConfig();
        if (mail == null || !mail.isEnabled()) {
            log.debug("Reservation notification disabled. Skipping reservation {}", data.reservationKey());
            return;
        }

        List<String> recipients = resolveRecipients(mail);
        if (recipients.isEmpty()) {
            log.warn(
                "No recipients configured for reservation {}. Set notifications.mail.default-to",
                data.reservationKey()
            );
            return;
        }

        ZoneId zoneId = resolveZone(mail.getTimezone());
        String subject = buildSubject(data, zoneId);
        String htmlBody = buildHtmlBody(data, zoneId);
        String textBody = buildTextBody(data, zoneId);

        String icsContent = icsBuilder
            .buildReservationInvite(data, zoneId, mail.getFrom(), mail.getFromName())
            .orElse(null);

        NotificationMessage message = new NotificationMessage(
            recipients,
            subject,
            textBody,
            htmlBody,
            icsContent,
            "reserva-" + data.reservationKey() + ".ics"
        );

        mailSenderFactory.resolve().send(message);
    }

    public void notifyReservationCancelled(ReservationNotificationData data) {
        NotificationProperties.Mail mail = notificationConfigService.getMailConfig();
        if (mail == null || !mail.isEnabled()) {
            log.debug("Reservation notification disabled. Skipping cancellation {}", data.reservationKey());
            return;
        }

        List<String> recipients = resolveRecipients(mail);
        if (recipients.isEmpty()) {
            log.warn(
                "No recipients configured for reservation {}. Set notifications.mail.default-to",
                data.reservationKey()
            );
            return;
        }

        ZoneId zoneId = resolveZone(mail.getTimezone());
        String subject = "Reserva cancelada: " + safeLabName(data);
        String htmlBody = buildCancelHtmlBody(data, zoneId);
        String textBody = buildCancelTextBody(data, zoneId);

        String icsContent = icsBuilder
            .buildReservationCancellation(data, zoneId, mail.getFrom(), mail.getFromName())
            .orElse(null);

        NotificationMessage message = new NotificationMessage(
            recipients,
            subject,
            textBody,
            htmlBody,
            icsContent,
            "reserva-" + data.reservationKey() + "-cancel.ics"
        );

        mailSenderFactory.resolve().send(message);
    }

    private List<String> resolveRecipients(NotificationProperties.Mail mail) {
        Set<String> sanitized = new LinkedHashSet<>();
        if (mail.getDefaultTo() != null) {
            for (String recipient : mail.getDefaultTo()) {
                if (recipient != null) {
                    String trimmed = recipient.trim();
                    if (!trimmed.isEmpty()) {
                        sanitized.add(trimmed);
                    }
                }
            }
        }
        return new ArrayList<>(sanitized);
    }

    private ZoneId resolveZone(String configured) {
        if (configured == null || configured.isBlank()) {
            return ZoneId.of("UTC");
        }
        try {
            return ZoneId.of(configured);
        } catch (Exception ex) {
            log.warn("Invalid timezone '{}', falling back to UTC", configured);
            return ZoneId.of("UTC");
        }
    }

    private String buildSubject(ReservationNotificationData data, ZoneId zoneId) {
        String lab = data.labName() != null && !data.labName().isBlank()
            ? data.labName()
            : "Lab " + data.labId();
        String when = formatInstant(data.start(), zoneId);
        return "Reserva aprobada: " + lab + (when.isEmpty() ? "" : " - " + when);
    }

    private String buildHtmlBody(ReservationNotificationData data, ZoneId zoneId) {
        String start = formatInstant(data.start(), zoneId);
        String end = formatInstant(data.end(), zoneId);
        return """
            <p>Se ha aprobado una reserva.</p>
            <ul>
              <li><strong>Laboratorio:</strong> %s (ID: %s)</li>
              <li><strong>Inicio:</strong> %s</li>
              <li><strong>Fin:</strong> %s</li>
              <li><strong>Reserva:</strong> %s</li>
              <li><strong>Solicitante:</strong> %s</li>
              <li><strong>Instituci\u00f3n pagadora:</strong> %s</li>
              <li><strong>Transacci\u00f3n:</strong> %s</li>
            </ul>
            <p>Adjuntamos una invitaci\u00f3n de calendario (.ics) para a\u00f1adir la reserva.</p>
            """.formatted(
                safeLabName(data),
                data.labId(),
                start.isEmpty() ? "Sin fecha" : start,
                end.isEmpty() ? "Sin fecha" : end,
                data.reservationKey(),
                data.renter() != null ? data.renter() : "Desconocido",
                data.payerInstitution() != null ? data.payerInstitution() : "Desconocida",
                data.transactionHash() != null ? data.transactionHash() : "N/A"
            );
    }

    private String buildTextBody(ReservationNotificationData data, ZoneId zoneId) {
        String start = formatInstant(data.start(), zoneId);
        String end = formatInstant(data.end(), zoneId);
        return """
            Reserva aprobada
            - Laboratorio: %s (ID: %s)
            - Inicio: %s
            - Fin: %s
            - Reserva: %s
            - Solicitante: %s
            - Instituci\u00f3n pagadora: %s
            - Transacci\u00f3n: %s

            Invitaci\u00f3n de calendario adjunta (ICS).
            """.formatted(
                safeLabName(data),
                data.labId(),
                start.isEmpty() ? "Sin fecha" : start,
                end.isEmpty() ? "Sin fecha" : end,
                data.reservationKey(),
                data.renter() != null ? data.renter() : "Desconocido",
                data.payerInstitution() != null ? data.payerInstitution() : "Desconocida",
                data.transactionHash() != null ? data.transactionHash() : "N/A"
            );
    }

    private String buildCancelHtmlBody(ReservationNotificationData data, ZoneId zoneId) {
        String start = formatInstant(data.start(), zoneId);
        String end = formatInstant(data.end(), zoneId);
        return """
            <p>Se ha cancelado una reserva.</p>
            <ul>
              <li><strong>Laboratorio:</strong> %s (ID: %s)</li>
              <li><strong>Inicio:</strong> %s</li>
              <li><strong>Fin:</strong> %s</li>
              <li><strong>Reserva:</strong> %s</li>
              <li><strong>Solicitante:</strong> %s</li>
              <li><strong>Transacci\u00f3n:</strong> %s</li>
            </ul>
            <p>Incluimos una cancelaci\u00f3n de calendario (ICS) para actualizar el evento.</p>
            """.formatted(
                safeLabName(data),
                data.labId(),
                start.isEmpty() ? "Sin fecha" : start,
                end.isEmpty() ? "Sin fecha" : end,
                data.reservationKey(),
                data.renter() != null ? data.renter() : "Desconocido",
                data.transactionHash() != null ? data.transactionHash() : "N/A"
            );
    }

    private String buildCancelTextBody(ReservationNotificationData data, ZoneId zoneId) {
        String start = formatInstant(data.start(), zoneId);
        String end = formatInstant(data.end(), zoneId);
        return """
            Reserva cancelada
            - Laboratorio: %s (ID: %s)
            - Inicio: %s
            - Fin: %s
            - Reserva: %s
            - Solicitante: %s
            - Transacci\u00f3n: %s

            Se adjunta cancelaci\u00f3n ICS para eliminar/actualizar el evento.
            """.formatted(
                safeLabName(data),
                data.labId(),
                start.isEmpty() ? "Sin fecha" : start,
                end.isEmpty() ? "Sin fecha" : end,
                data.reservationKey(),
                data.renter() != null ? data.renter() : "Desconocido",
                data.transactionHash() != null ? data.transactionHash() : "N/A"
            );
    }

    private String formatInstant(Instant instant, ZoneId zoneId) {
        if (instant == null) {
            return "";
        }
        return HUMAN_DATE
            .withLocale(Locale.getDefault())
            .withZone(zoneId)
            .format(instant);
    }

    private String safeLabName(ReservationNotificationData data) {
        if (data.labName() != null && !data.labName().isBlank()) {
            return data.labName();
        }
        return "Lab " + data.labId();
    }
}
