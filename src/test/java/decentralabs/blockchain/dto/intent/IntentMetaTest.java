package decentralabs.blockchain.dto.intent;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("IntentMeta Tests")
class IntentMetaTest {

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
        @DisplayName("Should fail validation when requestId is null")
        void shouldFailWhenRequestIdNull() {
            IntentMeta meta = createValidMeta();
            meta.setRequestId(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("requestId")));
        }

        @Test
        @DisplayName("Should fail validation when requestId is blank")
        void shouldFailWhenRequestIdBlank() {
            IntentMeta meta = createValidMeta();
            meta.setRequestId("   ");

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("requestId")));
        }

        @Test
        @DisplayName("Should fail validation when signer is null")
        void shouldFailWhenSignerNull() {
            IntentMeta meta = createValidMeta();
            meta.setSigner(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("signer")));
        }

        @Test
        @DisplayName("Should fail validation when executor is null")
        void shouldFailWhenExecutorNull() {
            IntentMeta meta = createValidMeta();
            meta.setExecutor(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("executor")));
        }

        @Test
        @DisplayName("Should fail validation when action is null")
        void shouldFailWhenActionNull() {
            IntentMeta meta = createValidMeta();
            meta.setAction(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("action")));
        }

        @Test
        @DisplayName("Should fail validation when payloadHash is null")
        void shouldFailWhenPayloadHashNull() {
            IntentMeta meta = createValidMeta();
            meta.setPayloadHash(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("payloadHash")));
        }

        @Test
        @DisplayName("Should fail validation when nonce is null")
        void shouldFailWhenNonceNull() {
            IntentMeta meta = createValidMeta();
            meta.setNonce(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("nonce")));
        }

        @Test
        @DisplayName("Should fail validation when requestedAt is null")
        void shouldFailWhenRequestedAtNull() {
            IntentMeta meta = createValidMeta();
            meta.setRequestedAt(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("requestedAt")));
        }

        @Test
        @DisplayName("Should fail validation when expiresAt is null")
        void shouldFailWhenExpiresAtNull() {
            IntentMeta meta = createValidMeta();
            meta.setExpiresAt(null);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("expiresAt")));
        }

        @Test
        @DisplayName("Should pass validation with all required fields")
        void shouldPassWithValidData() {
            IntentMeta meta = createValidMeta();

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }
    }

    @Nested
    @DisplayName("Getter/Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("Should get and set requestId")
        void shouldGetSetRequestId() {
            IntentMeta meta = new IntentMeta();
            String requestId = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

            meta.setRequestId(requestId);

            assertEquals(requestId, meta.getRequestId());
        }

        @Test
        @DisplayName("Should get and set signer")
        void shouldGetSetSigner() {
            IntentMeta meta = new IntentMeta();
            String signer = "0x1234567890abcdef1234567890abcdef12345678";

            meta.setSigner(signer);

            assertEquals(signer, meta.getSigner());
        }

        @Test
        @DisplayName("Should get and set executor")
        void shouldGetSetExecutor() {
            IntentMeta meta = new IntentMeta();
            String executor = "0x1234567890abcdef1234567890abcdef12345678";

            meta.setExecutor(executor);

            assertEquals(executor, meta.getExecutor());
        }

        @Test
        @DisplayName("Should get and set action")
        void shouldGetSetAction() {
            IntentMeta meta = new IntentMeta();
            Integer action = 1;

            meta.setAction(action);

            assertEquals(action, meta.getAction());
        }

        @Test
        @DisplayName("Should get and set payloadHash")
        void shouldGetSetPayloadHash() {
            IntentMeta meta = new IntentMeta();
            String payloadHash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

            meta.setPayloadHash(payloadHash);

            assertEquals(payloadHash, meta.getPayloadHash());
        }

        @Test
        @DisplayName("Should get and set nonce")
        void shouldGetSetNonce() {
            IntentMeta meta = new IntentMeta();
            Long nonce = 12345L;

            meta.setNonce(nonce);

            assertEquals(nonce, meta.getNonce());
        }

        @Test
        @DisplayName("Should get and set requestedAt")
        void shouldGetSetRequestedAt() {
            IntentMeta meta = new IntentMeta();
            Long requestedAt = System.currentTimeMillis() / 1000;

            meta.setRequestedAt(requestedAt);

            assertEquals(requestedAt, meta.getRequestedAt());
        }

        @Test
        @DisplayName("Should get and set expiresAt")
        void shouldGetSetExpiresAt() {
            IntentMeta meta = new IntentMeta();
            Long expiresAt = (System.currentTimeMillis() / 1000) + 3600;

            meta.setExpiresAt(expiresAt);

            assertEquals(expiresAt, meta.getExpiresAt());
        }
    }

    @Nested
    @DisplayName("Action Value Tests")
    class ActionValueTests {

        @Test
        @DisplayName("Should accept action value 0 (RESERVE)")
        void shouldAcceptActionZero() {
            IntentMeta meta = createValidMeta();
            meta.setAction(0);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should accept action value 1 (CANCEL)")
        void shouldAcceptActionOne() {
            IntentMeta meta = createValidMeta();
            meta.setAction(1);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should accept large action values")
        void shouldAcceptLargeActionValues() {
            IntentMeta meta = createValidMeta();
            meta.setAction(255); // max uint8

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }
    }

    @Nested
    @DisplayName("Timestamp Tests")
    class TimestampTests {

        @Test
        @DisplayName("Should accept current timestamp for requestedAt")
        void shouldAcceptCurrentTimestamp() {
            IntentMeta meta = createValidMeta();
            long now = System.currentTimeMillis() / 1000;
            meta.setRequestedAt(now);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should accept future expiresAt timestamp")
        void shouldAcceptFutureExpiresAt() {
            IntentMeta meta = createValidMeta();
            long future = (System.currentTimeMillis() / 1000) + 86400; // 24 hours
            meta.setExpiresAt(future);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should accept zero nonce")
        void shouldAcceptZeroNonce() {
            IntentMeta meta = createValidMeta();
            meta.setNonce(0L);

            Set<ConstraintViolation<IntentMeta>> violations = validator.validate(meta);

            assertTrue(violations.isEmpty());
        }
    }

    private IntentMeta createValidMeta() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        meta.setSigner("0x1234567890abcdef1234567890abcdef12345678");
        meta.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
        meta.setAction(1);
        meta.setPayloadHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        meta.setNonce(1L);
        meta.setRequestedAt(System.currentTimeMillis() / 1000);
        meta.setExpiresAt((System.currentTimeMillis() / 1000) + 3600);
        return meta;
    }
}
