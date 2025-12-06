package decentralabs.blockchain.dto.intent;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.math.BigInteger;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("ReservationIntentPayload Tests")
class ReservationIntentPayloadTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should fail validation when executor is null")
        void shouldFailWhenExecutorNull() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setExecutor(null);

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("executor")));
        }

        @Test
        @DisplayName("Should fail validation when executor is blank")
        void shouldFailWhenExecutorBlank() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setExecutor("   ");

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("executor")));
        }

        @Test
        @DisplayName("Should fail validation when labId is null")
        void shouldFailWhenLabIdNull() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setLabId(null);

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("labId")));
        }

        @Test
        @DisplayName("Should fail validation when start is null")
        void shouldFailWhenStartNull() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setStart(null);

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("start")));
        }

        @Test
        @DisplayName("Should fail validation when end is null")
        void shouldFailWhenEndNull() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setEnd(null);

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("end")));
        }

        @Test
        @DisplayName("Should pass validation with valid data")
        void shouldPassWithValidData() {
            ReservationIntentPayload payload = createValidPayload();

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }
    }

    @Nested
    @DisplayName("Getter/Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("Should get and set executor")
        void shouldGetSetExecutor() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            String executor = "0x1234567890abcdef1234567890abcdef12345678";

            payload.setExecutor(executor);

            assertEquals(executor, payload.getExecutor());
        }

        @Test
        @DisplayName("Should get and set schacHomeOrganization")
        void shouldGetSetSchacHomeOrganization() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            String org = "university.edu";

            payload.setSchacHomeOrganization(org);

            assertEquals(org, payload.getSchacHomeOrganization());
        }

        @Test
        @DisplayName("Should get and set puc")
        void shouldGetSetPuc() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            String puc = "PUC123";

            payload.setPuc(puc);

            assertEquals(puc, payload.getPuc());
        }

        @Test
        @DisplayName("Should get and set assertionHash")
        void shouldGetSetAssertionHash() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            String hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

            payload.setAssertionHash(hash);

            assertEquals(hash, payload.getAssertionHash());
        }

        @Test
        @DisplayName("Should get and set labId")
        void shouldGetSetLabId() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            BigInteger labId = BigInteger.valueOf(42);

            payload.setLabId(labId);

            assertEquals(labId, payload.getLabId());
        }

        @Test
        @DisplayName("Should get and set start time")
        void shouldGetSetStart() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            Long start = 1704067200L; // 2024-01-01 00:00:00 UTC

            payload.setStart(start);

            assertEquals(start, payload.getStart());
        }

        @Test
        @DisplayName("Should get and set end time")
        void shouldGetSetEnd() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            Long end = 1704153600L; // 2024-01-02 00:00:00 UTC

            payload.setEnd(end);

            assertEquals(end, payload.getEnd());
        }

        @Test
        @DisplayName("Should get and set price")
        void shouldGetSetPrice() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            BigInteger price = BigInteger.valueOf(1000000);

            payload.setPrice(price);

            assertEquals(price, payload.getPrice());
        }

        @Test
        @DisplayName("Should get and set reservationKey")
        void shouldGetSetReservationKey() {
            ReservationIntentPayload payload = new ReservationIntentPayload();
            String key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

            payload.setReservationKey(key);

            assertEquals(key, payload.getReservationKey());
        }
    }

    @Nested
    @DisplayName("Time Range Tests")
    class TimeRangeTests {

        @Test
        @DisplayName("Should accept valid time range")
        void shouldAcceptValidTimeRange() {
            ReservationIntentPayload payload = createValidPayload();
            long now = System.currentTimeMillis() / 1000;
            payload.setStart(now);
            payload.setEnd(now + 3600); // 1 hour later

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should allow start equal to end")
        void shouldAllowStartEqualToEnd() {
            ReservationIntentPayload payload = createValidPayload();
            long time = System.currentTimeMillis() / 1000;
            payload.setStart(time);
            payload.setEnd(time);

            // No validation constraint for start < end in the DTO itself
            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should handle large timestamp values")
        void shouldHandleLargeTimestamps() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setStart(4102444800L); // 2100-01-01
            payload.setEnd(4102531200L);   // 2100-01-02

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }
    }

    @Nested
    @DisplayName("Price Tests")
    class PriceTests {

        @Test
        @DisplayName("Should accept zero price")
        void shouldAcceptZeroPrice() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setPrice(BigInteger.ZERO);

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should accept large price values")
        void shouldAcceptLargePriceValues() {
            ReservationIntentPayload payload = createValidPayload();
            // uint96 max value
            payload.setPrice(new BigInteger("79228162514264337593543950335"));

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should allow null price (optional field)")
        void shouldAllowNullPrice() {
            ReservationIntentPayload payload = createValidPayload();
            payload.setPrice(null);

            Set<ConstraintViolation<ReservationIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }
    }

    private ReservationIntentPayload createValidPayload() {
        ReservationIntentPayload payload = new ReservationIntentPayload();
        payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
        payload.setLabId(BigInteger.valueOf(42));
        payload.setStart(System.currentTimeMillis() / 1000);
        payload.setEnd((System.currentTimeMillis() / 1000) + 3600);
        return payload;
    }
}
