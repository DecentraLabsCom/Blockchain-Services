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

@DisplayName("ActionIntentPayload Tests")
class ActionIntentPayloadTest {

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
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor(null);
            payload.setLabId(BigInteger.valueOf(42));

            Set<ConstraintViolation<ActionIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("executor")));
        }

        @Test
        @DisplayName("Should fail validation when executor is blank")
        void shouldFailWhenExecutorBlank() {
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("   ");
            payload.setLabId(BigInteger.valueOf(42));

            Set<ConstraintViolation<ActionIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("executor")));
        }

        @Test
        @DisplayName("Should fail validation when labId is null")
        void shouldFailWhenLabIdNull() {
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            payload.setLabId(null);

            Set<ConstraintViolation<ActionIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.stream().anyMatch(v -> v.getPropertyPath().toString().equals("labId")));
        }

        @Test
        @DisplayName("Should pass validation with valid data")
        void shouldPassWithValidData() {
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            payload.setLabId(BigInteger.valueOf(42));

            Set<ConstraintViolation<ActionIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }
    }

    @Nested
    @DisplayName("Getter/Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("Should get and set executor")
        void shouldGetSetExecutor() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String executor = "0x1234567890abcdef1234567890abcdef12345678";

            payload.setExecutor(executor);

            assertEquals(executor, payload.getExecutor());
        }

        @Test
        @DisplayName("Should get and set schacHomeOrganization")
        void shouldGetSetSchacHomeOrganization() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String org = "university.edu";

            payload.setSchacHomeOrganization(org);

            assertEquals(org, payload.getSchacHomeOrganization());
        }

        @Test
        @DisplayName("Should get and set puc")
        void shouldGetSetPuc() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String puc = "PUC123";

            payload.setPuc(puc);

            assertEquals(puc, payload.getPuc());
        }

        @Test
        @DisplayName("Should get and set assertionHash")
        void shouldGetSetAssertionHash() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

            payload.setAssertionHash(hash);

            assertEquals(hash, payload.getAssertionHash());
        }

        @Test
        @DisplayName("Should get and set labId")
        void shouldGetSetLabId() {
            ActionIntentPayload payload = new ActionIntentPayload();
            BigInteger labId = BigInteger.valueOf(42);

            payload.setLabId(labId);

            assertEquals(labId, payload.getLabId());
        }

        @Test
        @DisplayName("Should get and set reservationKey")
        void shouldGetSetReservationKey() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

            payload.setReservationKey(key);

            assertEquals(key, payload.getReservationKey());
        }

        @Test
        @DisplayName("Should get and set uri")
        void shouldGetSetUri() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String uri = "https://lab.example.com/access";

            payload.setUri(uri);

            assertEquals(uri, payload.getUri());
        }

        @Test
        @DisplayName("Should get and set price")
        void shouldGetSetPrice() {
            ActionIntentPayload payload = new ActionIntentPayload();
            BigInteger price = BigInteger.valueOf(1000000);

            payload.setPrice(price);

            assertEquals(price, payload.getPrice());
        }

        @Test
        @DisplayName("Should get and set maxBatch")
        void shouldGetSetMaxBatch() {
            ActionIntentPayload payload = new ActionIntentPayload();
            BigInteger maxBatch = BigInteger.valueOf(100);

            payload.setMaxBatch(maxBatch);

            assertEquals(maxBatch, payload.getMaxBatch());
        }

        @Test
        @DisplayName("Should get and set auth")
        void shouldGetSetAuth() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String auth = "bearer-token-123";

            payload.setAuth(auth);

            assertEquals(auth, payload.getAuth());
        }

        @Test
        @DisplayName("Should get and set accessURI")
        void shouldGetSetAccessUri() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String accessUri = "https://remote.example.com/lab";

            payload.setAccessURI(accessUri);

            assertEquals(accessUri, payload.getAccessURI());
        }

        @Test
        @DisplayName("Should get and set accessKey")
        void shouldGetSetAccessKey() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String accessKey = "secret-access-key";

            payload.setAccessKey(accessKey);

            assertEquals(accessKey, payload.getAccessKey());
        }

        @Test
        @DisplayName("Should get and set tokenURI")
        void shouldGetSetTokenUri() {
            ActionIntentPayload payload = new ActionIntentPayload();
            String tokenUri = "ipfs://QmXyz123/metadata.json";

            payload.setTokenURI(tokenUri);

            assertEquals(tokenUri, payload.getTokenURI());
        }
    }

    @Nested
    @DisplayName("Null Safety Tests")
    class NullSafetyTests {

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            ActionIntentPayload payload = new ActionIntentPayload();
            payload.setExecutor("0x1234567890abcdef1234567890abcdef12345678");
            payload.setLabId(BigInteger.valueOf(42));
            // All other fields remain null

            Set<ConstraintViolation<ActionIntentPayload>> violations = validator.validate(payload);

            assertTrue(violations.isEmpty());
        }
    }
}
