package decentralabs.blockchain.service.intent;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAction;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.service.intent.Eip712IntentVerifier.VerificationResult;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Eip712IntentVerifier Tests")
class Eip712IntentVerifierTest {

    private Eip712IntentVerifier verifier;
    @SuppressWarnings("unused")
    private Eip712IntentVerifier verifierWithTrustedSigner;

    private static final String TRUSTED_SIGNER = "0x1234567890123456789012345678901234567890";

    @BeforeEach
    void setUp() {
        verifier = new Eip712IntentVerifier(
            "",                       // trustedSigner
            "DecentraLabsIntent",     // domain name
            "1",                      // domain version
            11155111L,                // chain id (sepolia default in props)
            "0x0000000000000000000000000000000000000000" // verifying contract
        );

        verifierWithTrustedSigner = new Eip712IntentVerifier(
            TRUSTED_SIGNER,
            "DecentraLabsIntent",
            "1",
            11155111L,
            "0x0000000000000000000000000000000000000000"
        );
    }

    @Nested
    @DisplayName("Verification Input Validation Tests")
    class VerificationInputValidationTests {

        @Test
        @DisplayName("Should fail with missing_meta_or_signature when meta is null")
        void shouldFailWhenMetaIsNull() {
            VerificationResult result = verifier.verify(
                IntentAction.LAB_ADD,
                null,
                baseActionPayload(),
                null,
                "0xsignature"
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("missing_meta_or_signature");
        }

        @Test
        @DisplayName("Should fail with missing_meta_or_signature when signature is null")
        void shouldFailWhenSignatureIsNull() {
            VerificationResult result = verifier.verify(
                IntentAction.LAB_ADD,
                baseMeta(),
                baseActionPayload(),
                null,
                null
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("missing_meta_or_signature");
        }

        @Test
        @DisplayName("Should fail with missing_meta_or_signature when signature is blank")
        void shouldFailWhenSignatureIsBlank() {
            VerificationResult result = verifier.verify(
                IntentAction.LAB_ADD,
                baseMeta(),
                baseActionPayload(),
                null,
                "   "
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("missing_meta_or_signature");
        }

        @Test
        @DisplayName("Should fail with unknown_action when action is null")
        void shouldFailWhenActionIsNull() {
            VerificationResult result = verifier.verify(
                null,
                baseMeta(),
                baseActionPayload(),
                null,
                "0xvalidsignature"
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("unknown_action");
        }
    }

    @Nested
    @DisplayName("Action Payload Hash Tests")
    class ActionPayloadHashTests {

        @Test
        @DisplayName("Should compute hash that changes with maxBatch")
        void actionPayloadHashChangesWithMaxBatch() {
            ActionIntentPayload payload = baseActionPayload();
            payload.setMaxBatch(BigInteger.valueOf(5));
            String hashWithBatch5 = verifier.computeActionPayloadHash(payload);

            payload.setMaxBatch(BigInteger.valueOf(6));
            String hashWithBatch6 = verifier.computeActionPayloadHash(payload);

            assertThat(hashWithBatch5).isNotBlank();
            assertThat(hashWithBatch6).isNotBlank();
            assertThat(hashWithBatch5).isNotEqualTo(hashWithBatch6);
        }

        @Test
        @DisplayName("Should return null when payload is null")
        void shouldReturnNullWhenPayloadIsNull() {
            String hash = verifier.computeActionPayloadHash(null);

            assertThat(hash).isNull();
        }

        @Test
        @DisplayName("Should return null when executor is null")
        void shouldReturnNullWhenExecutorIsNull() {
            ActionIntentPayload payload = baseActionPayload();
            payload.setExecutor(null);

            String hash = verifier.computeActionPayloadHash(payload);

            assertThat(hash).isNull();
        }

        @Test
        @DisplayName("Should compute hash that changes with price")
        void actionPayloadHashChangesWithPrice() {
            ActionIntentPayload payload = baseActionPayload();
            payload.setPrice(BigInteger.valueOf(100));
            String hash1 = verifier.computeActionPayloadHash(payload);

            payload.setPrice(BigInteger.valueOf(200));
            String hash2 = verifier.computeActionPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute hash that changes with URI")
        void actionPayloadHashChangesWithUri() {
            ActionIntentPayload payload = baseActionPayload();
            payload.setUri("ipfs://hash1");
            String hash1 = verifier.computeActionPayloadHash(payload);

            payload.setUri("ipfs://hash2");
            String hash2 = verifier.computeActionPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute hash that changes with labId")
        void actionPayloadHashChangesWithLabId() {
            ActionIntentPayload payload = baseActionPayload();
            payload.setLabId(BigInteger.valueOf(1));
            String hash1 = verifier.computeActionPayloadHash(payload);

            payload.setLabId(BigInteger.valueOf(2));
            String hash2 = verifier.computeActionPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute hash that changes with executor address")
        void actionPayloadHashChangesWithExecutor() {
            ActionIntentPayload payload = baseActionPayload();
            payload.setExecutor("0x1111111111111111111111111111111111111111");
            String hash1 = verifier.computeActionPayloadHash(payload);

            payload.setExecutor("0x2222222222222222222222222222222222222222");
            String hash2 = verifier.computeActionPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute consistent hash for same payload")
        void shouldComputeConsistentHash() {
            ActionIntentPayload payload = baseActionPayload();
            String hash1 = verifier.computeActionPayloadHash(payload);
            String hash2 = verifier.computeActionPayloadHash(payload);

            assertThat(hash1).isEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute valid hex hash format")
        void shouldComputeValidHexFormat() {
            String hash = verifier.computeActionPayloadHash(baseActionPayload());

            assertThat(hash).startsWith("0x");
            assertThat(hash).hasSize(66); // 0x + 64 hex chars
            assertThat(hash.substring(2)).matches("[0-9a-fA-F]+");
        }
    }

    @Nested
    @DisplayName("Reservation Payload Hash Tests")
    class ReservationPayloadHashTests {

        @Test
        @DisplayName("Should return null when payload is null")
        void shouldReturnNullWhenPayloadIsNull() {
            String hash = verifier.computeReservationPayloadHash(null);

            assertThat(hash).isNull();
        }

        @Test
        @DisplayName("Should return null when executor is null")
        void shouldReturnNullWhenExecutorIsNull() {
            ReservationIntentPayload payload = baseReservationPayload();
            payload.setExecutor(null);

            String hash = verifier.computeReservationPayloadHash(payload);

            assertThat(hash).isNull();
        }

        @Test
        @DisplayName("Should compute hash that changes with start time")
        void hashChangesWithStartTime() {
            ReservationIntentPayload payload = baseReservationPayload();
            payload.setStart(1000L);
            String hash1 = verifier.computeReservationPayloadHash(payload);

            payload.setStart(2000L);
            String hash2 = verifier.computeReservationPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute hash that changes with end time")
        void hashChangesWithEndTime() {
            ReservationIntentPayload payload = baseReservationPayload();
            payload.setEnd(5000L);
            String hash1 = verifier.computeReservationPayloadHash(payload);

            payload.setEnd(6000L);
            String hash2 = verifier.computeReservationPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute hash that changes with labId")
        void hashChangesWithLabId() {
            ReservationIntentPayload payload = baseReservationPayload();
            payload.setLabId(BigInteger.ONE);
            String hash1 = verifier.computeReservationPayloadHash(payload);

            payload.setLabId(BigInteger.TWO);
            String hash2 = verifier.computeReservationPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute hash that changes with price")
        void hashChangesWithPrice() {
            ReservationIntentPayload payload = baseReservationPayload();
            payload.setPrice(BigInteger.valueOf(100));
            String hash1 = verifier.computeReservationPayloadHash(payload);

            payload.setPrice(BigInteger.valueOf(200));
            String hash2 = verifier.computeReservationPayloadHash(payload);

            assertThat(hash1).isNotEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute consistent hash for same payload")
        void shouldComputeConsistentHash() {
            ReservationIntentPayload payload = baseReservationPayload();
            String hash1 = verifier.computeReservationPayloadHash(payload);
            String hash2 = verifier.computeReservationPayloadHash(payload);

            assertThat(hash1).isEqualTo(hash2);
        }

        @Test
        @DisplayName("Should compute valid hex hash format")
        void shouldComputeValidHexFormat() {
            String hash = verifier.computeReservationPayloadHash(baseReservationPayload());

            assertThat(hash).startsWith("0x");
            assertThat(hash).hasSize(66);
            assertThat(hash.substring(2)).matches("[0-9a-fA-F]+");
        }
    }

    @Nested
    @DisplayName("Missing Payload Tests")
    class MissingPayloadTests {

        @Test
        @DisplayName("Should fail with missing_payload for action requiring actionPayload")
        void shouldFailWhenActionPayloadMissing() {
            IntentMeta meta = baseMeta();
            meta.setPayloadHash("0x" + "a".repeat(64));

            VerificationResult result = verifier.verify(
                IntentAction.LAB_ADD,
                meta,
                null, // missing action payload
                null,
                "0xsignature"
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("missing_payload");
        }

        @Test
        @DisplayName("Should fail with missing_payload for action requiring reservationPayload")
        void shouldFailWhenReservationPayloadMissing() {
            IntentMeta meta = baseMeta();
            meta.setPayloadHash("0x" + "a".repeat(64));

            VerificationResult result = verifier.verify(
                IntentAction.RESERVATION_REQUEST,
                meta,
                null,
                null, // missing reservation payload
                "0xsignature"
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("missing_payload");
        }
    }

    @Nested
    @DisplayName("Payload Hash Mismatch Tests")
    class PayloadHashMismatchTests {

        @Test
        @DisplayName("Should fail with payload_hash_mismatch when hashes differ")
        void shouldFailWhenHashesDiffer() {
            ActionIntentPayload payload = baseActionPayload();

            IntentMeta meta = baseMeta();
            meta.setPayloadHash("0x" + "0".repeat(64)); // wrong hash

            VerificationResult result = verifier.verify(
                IntentAction.LAB_ADD,
                meta,
                payload,
                null,
                "0xsignature"
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("payload_hash_mismatch");
            assertThat(result.computedPayloadHash()).isNotNull();
        }
    }

    @Nested
    @DisplayName("VerificationResult Tests")
    class VerificationResultTests {

        @Test
        @DisplayName("Should create valid result with all fields")
        void shouldCreateValidResult() {
            VerificationResult result = new VerificationResult(
                true,
                "0xrecoveredAddress",
                "0xcomputedHash",
                null
            );

            assertThat(result.valid()).isTrue();
            assertThat(result.recoveredAddress()).isEqualTo("0xrecoveredAddress");
            assertThat(result.computedPayloadHash()).isEqualTo("0xcomputedHash");
            assertThat(result.error()).isNull();
        }

        @Test
        @DisplayName("Should create failed result with error")
        void shouldCreateFailedResult() {
            VerificationResult result = new VerificationResult(
                false,
                null,
                null,
                "some_error"
            );

            assertThat(result.valid()).isFalse();
            assertThat(result.error()).isEqualTo("some_error");
        }
    }

    private ActionIntentPayload baseActionPayload() {
        ActionIntentPayload payload = new ActionIntentPayload();
        payload.setExecutor("0x1111111111111111111111111111111111111111");
        payload.setSchacHomeOrganization("");
        payload.setPuc("");
        payload.setAssertionHash(null);
        payload.setLabId(BigInteger.ONE);
        payload.setReservationKey(null);
        payload.setUri("");
        payload.setPrice(BigInteger.TEN);
        payload.setMaxBatch(BigInteger.ZERO);
        payload.setAuth("");
        payload.setAccessURI("");
        payload.setAccessKey("");
        payload.setTokenURI("");
        return payload;
    }

    private ReservationIntentPayload baseReservationPayload() {
        ReservationIntentPayload payload = new ReservationIntentPayload();
        payload.setExecutor("0x1111111111111111111111111111111111111111");
        payload.setSchacHomeOrganization("");
        payload.setPuc("");
        payload.setAssertionHash(null);
        payload.setLabId(BigInteger.ONE);
        payload.setStart(1000L);
        payload.setEnd(5000L);
        payload.setPrice(BigInteger.TEN);
        payload.setReservationKey(null);
        return payload;
    }

    private IntentMeta baseMeta() {
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("0x" + "a".repeat(64));
        meta.setSigner("0x1111111111111111111111111111111111111111");
        meta.setExecutor("0x2222222222222222222222222222222222222222");
        meta.setAction(1); // LAB_ADD
        meta.setPayloadHash("0x" + "b".repeat(64));
        meta.setNonce(1L);
        meta.setRequestedAt(System.currentTimeMillis() / 1000);
        meta.setExpiresAt(System.currentTimeMillis() / 1000 + 3600);
        return meta;
    }
}
