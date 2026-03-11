package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

class Eip712CheckInVerifierTest {

    private Eip712CheckInVerifier verifier;
    private Credentials credentials;

    @BeforeEach
    void setUp() {
        verifier = new Eip712CheckInVerifier(
            "DecentraLabsIntent",
            "1",
            11155111L,
            "0x2222222222222222222222222222222222222222"
        );
        credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
    }

    @Test
    void verify_acceptsValidSignature() {
        String signer = credentials.getAddress();
        String reservationKey = normalizeBytes32("0xabc");
        String pucHash = normalizeBytes32("0x1234");
        long timestamp = 1_710_000_000L;
        byte[] digest = verifier.buildDigest(signer, reservationKey, pucHash, timestamp);
        String signature = signatureToHex(Sign.signMessage(digest, credentials.getEcKeyPair(), false));

        Eip712CheckInVerifier.VerificationResult result = verifier.verify(
            signer,
            reservationKey,
            pucHash,
            timestamp,
            signature
        );

        assertThat(result.valid()).isTrue();
        assertThat(result.recoveredAddress()).isEqualToIgnoringCase(signer);
        assertThat(result.error()).isNull();
    }

    @Test
    void verify_rejectsSignerMismatch() {
        String reservationKey = normalizeBytes32("0xabc");
        String pucHash = normalizeBytes32("0x1234");
        long timestamp = 1_710_000_000L;
        byte[] digest = verifier.buildDigest(credentials.getAddress(), reservationKey, pucHash, timestamp);
        String signature = signatureToHex(Sign.signMessage(digest, credentials.getEcKeyPair(), false));

        Eip712CheckInVerifier.VerificationResult result = verifier.verify(
            "0x1111111111111111111111111111111111111111",
            reservationKey,
            pucHash,
            timestamp,
            signature
        );

        assertThat(result.valid()).isFalse();
        assertThat(result.recoveredAddress()).isNotNull();
        assertThat(result.recoveredAddress()).isNotEqualToIgnoringCase("0x1111111111111111111111111111111111111111");
        assertThat(result.error()).isEqualTo("signature_mismatch");
    }

    @Test
    void verify_rejectsMissingSignature() {
        Eip712CheckInVerifier.VerificationResult result = verifier.verify(
            credentials.getAddress(),
            normalizeBytes32("0xabc"),
            normalizeBytes32("0x1234"),
            1_710_000_000L,
            " "
        );

        assertThat(result.valid()).isFalse();
        assertThat(result.recoveredAddress()).isNull();
        assertThat(result.error()).isEqualTo("missing_signature");
    }

    @Test
    void verify_rejectsMalformedSignature() {
        Eip712CheckInVerifier.VerificationResult result = verifier.verify(
            credentials.getAddress(),
            normalizeBytes32("0xabc"),
            normalizeBytes32("0x1234"),
            1_710_000_000L,
            "0x1234"
        );

        assertThat(result.valid()).isFalse();
        assertThat(result.recoveredAddress()).isNull();
        assertThat(result.error()).contains("Invalid signature length");
    }

    @Test
    void buildDigest_isDeterministicAndSensitiveToInputs() {
        byte[] digestA = verifier.buildDigest(
            credentials.getAddress(),
            normalizeBytes32("0xabc"),
            normalizeBytes32("0x1234"),
            123L
        );
        byte[] digestB = verifier.buildDigest(
            credentials.getAddress(),
            normalizeBytes32("0xabc"),
            normalizeBytes32("0x1234"),
            123L
        );
        byte[] digestC = verifier.buildDigest(
            credentials.getAddress(),
            normalizeBytes32("0xabc"),
            normalizeBytes32("0x1234"),
            124L
        );

        assertThat(digestA).containsExactly(digestB);
        assertThat(Numeric.toHexString(digestA)).isNotEqualTo(Numeric.toHexString(digestC));
    }

    private static String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    private static String signatureToHex(Sign.SignatureData signatureData) {
        byte[] sigBytes = new byte[65];
        System.arraycopy(signatureData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(signatureData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = signatureData.getV()[0];
        return Numeric.toHexString(sigBytes);
    }
}
