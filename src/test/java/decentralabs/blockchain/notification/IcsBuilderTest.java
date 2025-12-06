package decentralabs.blockchain.notification;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("IcsBuilder Tests")
class IcsBuilderTest {

    private IcsBuilder icsBuilder;

    @BeforeEach
    void setUp() {
        icsBuilder = new IcsBuilder();
    }

    private ReservationNotificationData createTestData() {
        return new ReservationNotificationData(
            "0xreservation123abc",
            BigInteger.valueOf(42),
            "Physics Lab A",
            "user@university.edu",
            "University of Test",
            Instant.parse("2025-01-15T10:00:00Z"),
            Instant.parse("2025-01-15T12:00:00Z"),
            "0xtxhash123"
        );
    }

    @Nested
    @DisplayName("buildReservationInvite Tests")
    class BuildReservationInviteTests {

        @Test
        @DisplayName("Should build valid ICS invite")
        void shouldBuildValidIcsInvite() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("Europe/Madrid"), "organizer@lab.edu", "Lab System"
            );

            assertTrue(result.isPresent());
            String ics = result.get();
            
            assertTrue(ics.contains("BEGIN:VCALENDAR"));
            assertTrue(ics.contains("END:VCALENDAR"));
            assertTrue(ics.contains("VERSION:2.0"));
            assertTrue(ics.contains("METHOD:REQUEST"));
        }

        @Test
        @DisplayName("Should include event details")
        void shouldIncludeEventDetails() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "organizer@lab.edu", "Lab System"
            );

            String ics = result.get();
            
            assertTrue(ics.contains("BEGIN:VEVENT"));
            assertTrue(ics.contains("END:VEVENT"));
            assertTrue(ics.contains("UID:0xreservation123abc@lab-gateway"));
            assertTrue(ics.contains("STATUS:CONFIRMED"));
            assertTrue(ics.contains("SEQUENCE:0"));
        }

        @Test
        @DisplayName("Should include correct date/time")
        void shouldIncludeCorrectDateTime() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "organizer@lab.edu", null
            );

            String ics = result.get();
            
            assertTrue(ics.contains("DTSTART;TZID=UTC:20250115T100000"));
            assertTrue(ics.contains("DTEND;TZID=UTC:20250115T120000"));
        }

        @Test
        @DisplayName("Should include organizer when provided")
        void shouldIncludeOrganizer() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "organizer@lab.edu", "Lab System"
            );

            String ics = result.get();
            assertTrue(ics.contains("ORGANIZER;"));
            assertTrue(ics.contains("organizer@lab.edu"));
        }

        @Test
        @DisplayName("Should include summary with lab name")
        void shouldIncludeSummary() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "organizer@lab.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("SUMMARY:"));
            assertTrue(ics.contains("Reserva aprobada"));
            assertTrue(ics.contains("Physics Lab A"));
        }

        @Test
        @DisplayName("Should return empty when start date is null")
        void shouldReturnEmptyWhenStartNull() {
            ReservationNotificationData data = new ReservationNotificationData(
                "0xres", BigInteger.ONE, "Lab", "user@test.edu", "Uni",
                null, // null start
                Instant.now(),
                "0xtx"
            );
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("Should return empty when end date is null")
        void shouldReturnEmptyWhenEndNull() {
            ReservationNotificationData data = new ReservationNotificationData(
                "0xres", BigInteger.ONE, "Lab", "user@test.edu", "Uni",
                Instant.now(),
                null, // null end
                "0xtx"
            );
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("Should handle different timezones")
        void shouldHandleDifferentTimezones() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> resultMadrid = icsBuilder.buildReservationInvite(
                data, ZoneId.of("Europe/Madrid"), "org@test.edu", null
            );
            Optional<String> resultTokyo = icsBuilder.buildReservationInvite(
                data, ZoneId.of("Asia/Tokyo"), "org@test.edu", null
            );

            assertTrue(resultMadrid.get().contains("TZID=Europe/Madrid"));
            assertTrue(resultTokyo.get().contains("TZID=Asia/Tokyo"));
        }

        @Test
        @DisplayName("Should skip organizer when email is blank")
        void shouldSkipOrganizerWhenBlank() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "", null
            );

            String ics = result.get();
            assertFalse(ics.contains("ORGANIZER;"));
        }
    }

    @Nested
    @DisplayName("buildReservationCancellation Tests")
    class BuildReservationCancellationTests {

        @Test
        @DisplayName("Should build cancellation with correct method")
        void shouldBuildCancellationWithCorrectMethod() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationCancellation(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("METHOD:CANCEL"));
            assertTrue(ics.contains("STATUS:CANCELLED"));
        }

        @Test
        @DisplayName("Should have sequence 1 for cancellation")
        void shouldHaveSequence1ForCancellation() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationCancellation(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("SEQUENCE:1"));
        }

        @Test
        @DisplayName("Should include cancelled in summary")
        void shouldIncludeCancelledInSummary() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationCancellation(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("Reserva cancelada"));
        }

        @Test
        @DisplayName("Should return empty when dates are null")
        void shouldReturnEmptyWhenDatesNull() {
            ReservationNotificationData data = new ReservationNotificationData(
                "0xres", BigInteger.ONE, "Lab", "user@test.edu", "Uni",
                null, null, "0xtx"
            );
            
            Optional<String> result = icsBuilder.buildReservationCancellation(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("Escape Character Tests")
    class EscapeCharacterTests {

        @Test
        @DisplayName("Should escape special characters in lab name")
        void shouldEscapeSpecialCharacters() {
            ReservationNotificationData data = new ReservationNotificationData(
                "0xres123",
                BigInteger.ONE,
                "Lab, Room; A\\B",
                "user@test.edu",
                "Uni",
                Instant.parse("2025-01-15T10:00:00Z"),
                Instant.parse("2025-01-15T12:00:00Z"),
                "0xtx"
            );
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            // Commas and semicolons should be escaped
            assertTrue(ics.contains("\\,") || ics.contains("\\;") || ics.contains("\\\\"));
        }

        @Test
        @DisplayName("Should handle null values in description")
        void shouldHandleNullValuesInDescription() {
            ReservationNotificationData data = new ReservationNotificationData(
                "0xres123",
                BigInteger.ONE,
                "Lab Name",
                null, // null renter
                null, // null payer
                Instant.parse("2025-01-15T10:00:00Z"),
                Instant.parse("2025-01-15T12:00:00Z"),
                "0xtx"
            );
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            assertTrue(result.isPresent());
            String ics = result.get();
            assertTrue(ics.contains("Desconocido"));
        }

        @Test
        @DisplayName("Should escape newlines")
        void shouldEscapeNewlines() {
            ReservationNotificationData data = new ReservationNotificationData(
                "0xres123",
                BigInteger.ONE,
                "Lab\nWith\nNewlines",
                "user@test.edu",
                "Uni",
                Instant.parse("2025-01-15T10:00:00Z"),
                Instant.parse("2025-01-15T12:00:00Z"),
                "0xtx"
            );
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            // Raw newlines should be escaped to \\n
            assertFalse(ics.contains("Lab\nWith"));
        }
    }

    @Nested
    @DisplayName("ICS Structure Tests")
    class IcsStructureTests {

        @Test
        @DisplayName("Should produce valid ICS line endings (CRLF)")
        void shouldProduceValidLineEndings() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("\r\n"));
        }

        @Test
        @DisplayName("Should include PRODID")
        void shouldIncludeProdid() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("PRODID:-//DecentraLabs//Lab Gateway//EN"));
        }

        @Test
        @DisplayName("Should include DTSTAMP")
        void shouldIncludeDtstamp() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("DTSTAMP:"));
        }

        @Test
        @DisplayName("Should include LOCATION")
        void shouldIncludeLocation() {
            ReservationNotificationData data = createTestData();
            
            Optional<String> result = icsBuilder.buildReservationInvite(
                data, ZoneId.of("UTC"), "org@test.edu", null
            );

            String ics = result.get();
            assertTrue(ics.contains("LOCATION:Physics Lab A"));
        }
    }
}
