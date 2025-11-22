package decentralabs.blockchain.notification;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

public class IcsBuilder {

    private static final DateTimeFormatter ICS_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss");
    private static final DateTimeFormatter ICS_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
        .withZone(ZoneOffset.UTC);

    public Optional<String> buildReservationInvite(
        ReservationNotificationData data,
        ZoneId zoneId,
        String organizerEmail,
        String organizerName
    ) {
        return buildEvent(data, zoneId, organizerEmail, organizerName, false);
    }

    public Optional<String> buildReservationCancellation(
        ReservationNotificationData data,
        ZoneId zoneId,
        String organizerEmail,
        String organizerName
    ) {
        return buildEvent(data, zoneId, organizerEmail, organizerName, true);
    }

    private Optional<String> buildEvent(
        ReservationNotificationData data,
        ZoneId zoneId,
        String organizerEmail,
        String organizerName,
        boolean canceled
    ) {
        Instant start = data.start();
        Instant end = data.end();
        if (start == null || end == null) {
            return Optional.empty();
        }

        ZonedDateTime startZdt = ZonedDateTime.ofInstant(start, zoneId);
        ZonedDateTime endZdt = ZonedDateTime.ofInstant(end, zoneId);

        StringBuilder sb = new StringBuilder();
        sb.append("BEGIN:VCALENDAR").append("\r\n");
        sb.append("VERSION:2.0").append("\r\n");
        sb.append("PRODID:-//DecentraLabs//Lab Gateway//EN").append("\r\n");
        sb.append("METHOD:").append(canceled ? "CANCEL" : "REQUEST").append("\r\n");
        sb.append("BEGIN:VEVENT").append("\r\n");
        sb.append("UID:").append(data.reservationKey()).append("@lab-gateway").append("\r\n");
        sb.append("SEQUENCE:").append(canceled ? "1" : "0").append("\r\n");
        sb.append("STATUS:").append(canceled ? "CANCELLED" : "CONFIRMED").append("\r\n");
        sb.append("DTSTAMP:").append(ICS_STAMP.format(Instant.now())).append("\r\n");
        sb.append("DTSTART;TZID=").append(zoneId.getId()).append(":").append(ICS_DATE.format(startZdt)).append("\r\n");
        sb.append("DTEND;TZID=").append(zoneId.getId()).append(":").append(ICS_DATE.format(endZdt)).append("\r\n");
        if (organizerEmail != null && !organizerEmail.isBlank()) {
            String organizer = organizerName != null && !organizerName.isBlank()
                ? "CN=" + escape(organizerName) + ":mailto:" + organizerEmail
                : "mailto:" + organizerEmail;
            sb.append("ORGANIZER;").append(organizer).append("\r\n");
        }
        sb.append("SUMMARY:").append(escape((canceled ? "Reserva cancelada: " : "Reserva aprobada: ") + data.labName())).append("\r\n");
        sb.append("LOCATION:").append(escape(data.labName())).append("\r\n");
        sb.append("DESCRIPTION:").append(escape(buildDescription(data, canceled))).append("\r\n");
        sb.append("END:VEVENT").append("\r\n");
        sb.append("END:VCALENDAR");
        return Optional.of(sb.toString());
    }

    private String buildDescription(ReservationNotificationData data, boolean canceled) {
        String renter = data.renter() != null ? data.renter() : "Desconocido";
        String payer = data.payerInstitution() != null ? data.payerInstitution() : "Desconocido";
        String status = canceled ? "cancelada" : "aprobada";
        return "Reserva " + status + " para " + data.labName()
            + "\\nRenter: " + renter
            + "\\nInstitucion: " + payer
            + "\\nReserva: " + data.reservationKey();
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value
            .replace("\\", "\\\\")
            .replace("\r\n", "\\n")
            .replace("\n", "\\n")
            .replace(",", "\\,")
            .replace(";", "\\;");
    }
}
