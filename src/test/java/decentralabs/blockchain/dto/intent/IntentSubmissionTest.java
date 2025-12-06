package decentralabs.blockchain.dto.intent;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("IntentSubmission Tests")
class IntentSubmissionTest {

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
        @DisplayName("Should fail validation when meta is null")
        void shouldFailWhenMetaNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setMeta(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("meta")));
        }

        @Test
        @DisplayName("Should fail validation when signature is null")
        void shouldFailWhenSignatureNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setSignature(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("signature")));
        }

        @Test
        @DisplayName("Should fail validation when signature is blank")
        void shouldFailWhenSignatureBlank() {
            IntentSubmission submission = createValidSubmission();
            submission.setSignature("   ");

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("signature")));
        }

        @Test
        @DisplayName("Should fail validation when samlAssertion is null")
        void shouldFailWhenSamlAssertionNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setSamlAssertion(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("samlAssertion")));
        }

        @Test
        @DisplayName("Should fail validation when webauthnCredentialId is null")
        void shouldFailWhenWebauthnCredentialIdNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setWebauthnCredentialId(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("webauthnCredentialId")));
        }

        @Test
        @DisplayName("Should fail validation when webauthnClientDataJSON is null")
        void shouldFailWhenWebauthnClientDataJsonNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setWebauthnClientDataJSON(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("webauthnClientDataJSON")));
        }

        @Test
        @DisplayName("Should fail validation when webauthnAuthenticatorData is null")
        void shouldFailWhenWebauthnAuthenticatorDataNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setWebauthnAuthenticatorData(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("webauthnAuthenticatorData")));
        }

        @Test
        @DisplayName("Should fail validation when webauthnSignature is null")
        void shouldFailWhenWebauthnSignatureNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setWebauthnSignature(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("webauthnSignature")));
        }

        @Test
        @DisplayName("Should pass validation with all required fields")
        void shouldPassWithValidData() {
            IntentSubmission submission = createValidSubmission();

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should cascade validation to meta")
        void shouldCascadeValidationToMeta() {
            IntentSubmission submission = createValidSubmission();
            submission.getMeta().setRequestId(null); // Invalid meta

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> 
                v.getPropertyPath().toString().contains("meta.requestId")));
        }
    }

    @Nested
    @DisplayName("Getter/Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("Should get and set meta")
        void shouldGetSetMeta() {
            IntentSubmission submission = new IntentSubmission();
            IntentMeta meta = createValidMeta();

            submission.setMeta(meta);

            assertEquals(meta, submission.getMeta());
        }

        @Test
        @DisplayName("Should get and set actionPayload")
        void shouldGetSetActionPayload() {
            IntentSubmission submission = new IntentSubmission();
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            payload.setLabId(BigInteger.valueOf(42));

            submission.setActionPayload(payload);

            assertEquals(payload, submission.getActionPayload());
        }

        @Test
        @DisplayName("Should get and set reservationPayload")
        void shouldGetSetReservationPayload() {
            IntentSubmission submission = new IntentSubmission();
            ReservationIntentPayload payload = new ReservationIntentPayload();
            payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            payload.setLabId(BigInteger.valueOf(42));
            payload.setStart(System.currentTimeMillis() / 1000);
            payload.setEnd((System.currentTimeMillis() / 1000) + 3600);

            submission.setReservationPayload(payload);

            assertEquals(payload, submission.getReservationPayload());
        }

        @Test
        @DisplayName("Should get and set signature")
        void shouldGetSetSignature() {
            IntentSubmission submission = new IntentSubmission();
            String signature = "0xabcdef1234567890";

            submission.setSignature(signature);

            assertEquals(signature, submission.getSignature());
        }

        @Test
        @DisplayName("Should get and set samlAssertion")
        void shouldGetSetSamlAssertion() {
            IntentSubmission submission = new IntentSubmission();
            String saml = "PHNhbWw6QXNzZXJ0aW9uPjwvc2FtbDpBc3NlcnRpb24+";

            submission.setSamlAssertion(saml);

            assertEquals(saml, submission.getSamlAssertion());
        }

        @Test
        @DisplayName("Should get and set webauthnCredentialId")
        void shouldGetSetWebauthnCredentialId() {
            IntentSubmission submission = new IntentSubmission();
            String credentialId = "credential-id-123";

            submission.setWebauthnCredentialId(credentialId);

            assertEquals(credentialId, submission.getWebauthnCredentialId());
        }

        @Test
        @DisplayName("Should get and set webauthnClientDataJSON")
        void shouldGetSetWebauthnClientDataJson() {
            IntentSubmission submission = new IntentSubmission();
            String clientData = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYWJjIn0";

            submission.setWebauthnClientDataJSON(clientData);

            assertEquals(clientData, submission.getWebauthnClientDataJSON());
        }

        @Test
        @DisplayName("Should get and set webauthnAuthenticatorData")
        void shouldGetSetWebauthnAuthenticatorData() {
            IntentSubmission submission = new IntentSubmission();
            String authData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2M";

            submission.setWebauthnAuthenticatorData(authData);

            assertEquals(authData, submission.getWebauthnAuthenticatorData());
        }

        @Test
        @DisplayName("Should get and set webauthnSignature")
        void shouldGetSetWebauthnSignature() {
            IntentSubmission submission = new IntentSubmission();
            String sig = "MEUCIQCz...signature...";

            submission.setWebauthnSignature(sig);

            assertEquals(sig, submission.getWebauthnSignature());
        }

        @Test
        @DisplayName("Should get and set typedData")
        void shouldGetSetTypedData() {
            IntentSubmission submission = new IntentSubmission();
            Map<String, Object> typedData = new HashMap<>();
            typedData.put("domain", Map.of("name", "DecentraLabs"));
            typedData.put("types", Map.of());

            submission.setTypedData(typedData);

            assertEquals(typedData, submission.getTypedData());
        }
    }

    @Nested
    @DisplayName("Payload Tests")
    class PayloadTests {

        @Test
        @DisplayName("Should allow both payloads to be null")
        void shouldAllowBothPayloadsNull() {
            IntentSubmission submission = createValidSubmission();
            submission.setActionPayload(null);
            submission.setReservationPayload(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should allow actionPayload without reservationPayload")
        void shouldAllowActionPayloadOnly() {
            IntentSubmission submission = createValidSubmission();
            ActionIntentPayload actionPayload = new ActionIntentPayload();
            actionPayload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            actionPayload.setLabId(BigInteger.valueOf(42));
            submission.setActionPayload(actionPayload);
            submission.setReservationPayload(null);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should allow reservationPayload without actionPayload")
        void shouldAllowReservationPayloadOnly() {
            IntentSubmission submission = createValidSubmission();
            submission.setActionPayload(null);
            ReservationIntentPayload reservationPayload = new ReservationIntentPayload();
            reservationPayload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            reservationPayload.setLabId(BigInteger.valueOf(42));
            reservationPayload.setStart(System.currentTimeMillis() / 1000);
            reservationPayload.setEnd((System.currentTimeMillis() / 1000) + 3600);
            submission.setReservationPayload(reservationPayload);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.isEmpty());
        }

        @Test
        @DisplayName("Should cascade validation to actionPayload")
        void shouldCascadeValidationToActionPayload() {
            IntentSubmission submission = createValidSubmission();
            ActionIntentPayload invalidPayload = new ActionIntentPayload();
            invalidPayload.setExecutor(null); // Invalid
            invalidPayload.setLabId(null);    // Invalid
            submission.setActionPayload(invalidPayload);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> 
                v.getPropertyPath().toString().contains("actionPayload")));
        }

        @Test
        @DisplayName("Should cascade validation to reservationPayload")
        void shouldCascadeValidationToReservationPayload() {
            IntentSubmission submission = createValidSubmission();
            ReservationIntentPayload invalidPayload = new ReservationIntentPayload();
            invalidPayload.setExecutor(null); // Invalid
            submission.setReservationPayload(invalidPayload);

            Set<ConstraintViolation<IntentSubmission>> violations = validator.validate(submission);

            assertTrue(violations.stream().anyMatch(v -> 
                v.getPropertyPath().toString().contains("reservationPayload")));
        }
    }

    private IntentSubmission createValidSubmission() {
        IntentSubmission submission = new IntentSubmission();
        submission.setMeta(createValidMeta());
        submission.setSignature("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
        submission.setSamlAssertion("PHNhbWw6QXNzZXJ0aW9uPjwvc2FtbDpBc3NlcnRpb24+");
        submission.setWebauthnCredentialId("credential-id-123");
        submission.setWebauthnClientDataJSON("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYWJjIn0");
        submission.setWebauthnAuthenticatorData("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2M");
        submission.setWebauthnSignature("MEUCIQCz...signature...");
        return submission;
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
