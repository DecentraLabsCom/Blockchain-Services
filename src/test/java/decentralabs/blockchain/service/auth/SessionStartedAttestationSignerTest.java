package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;

import decentralabs.blockchain.service.auth.SessionStartedAttestationSigner.SessionStartedAttestationPayload;
import decentralabs.blockchain.service.auth.SessionStartedAttestationSigner.SignedSessionStartedAttestation;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

class SessionStartedAttestationSignerTest {

    private SessionStartedAttestationSigner signer;
    private Credentials credentials;

    @BeforeEach
    void setUp() {
        signer = new SessionStartedAttestationSigner(
            "DecentraLabsSession",
            "1",
            11155111L,
            "0x2222222222222222222222222222222222222222"
        );
        credentials = Credentials.create("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7f8f2f0d9f7d4c001");
    }

    @Test
    void sign_producesRecoverableProviderSignature() throws Exception {
        SessionStartedAttestationPayload payload = payload(1_700_010_000L);

        SignedSessionStartedAttestation signed = signer.sign(payload, credentials);

        BigInteger publicKey = Sign.signedMessageHashToKey(
            signer.buildDigest(payload),
            signatureToData(signed.signature())
        );
        String recoveredAddress = "0x" + Keys.getAddress(publicKey);

        assertThat(signed.digest()).startsWith("0x").hasSize(66);
        assertThat(signed.signature()).startsWith("0x").hasSize(132);
        assertThat(recoveredAddress).isEqualToIgnoringCase(credentials.getAddress());
    }

    @Test
    void buildDigest_isDeterministicAndSensitiveToInputs() {
        SessionStartedAttestationPayload payloadA = payload(1_700_010_000L);
        SessionStartedAttestationPayload payloadB = payload(1_700_010_000L);
        SessionStartedAttestationPayload payloadC = payload(1_700_010_001L);

        assertThat(Numeric.toHexString(signer.buildDigest(payloadA)))
            .isEqualTo(Numeric.toHexString(signer.buildDigest(payloadB)))
            .isNotEqualTo(Numeric.toHexString(signer.buildDigest(payloadC)));
    }

    private SessionStartedAttestationPayload payload(long startedAt) {
        return new SessionStartedAttestationPayload(
            credentials.getAddress(),
            normalizeBytes32("0xabc"),
            "42",
            normalizeBytes32("0x1234"),
            "gateway-a",
            "guac-session-1",
            "guacamole",
            startedAt,
            normalizeBytes32("0x9999"),
            normalizeBytes32("0x7777"),
            null
        );
    }

    private static Sign.SignatureData signatureToData(String signatureHex) {
        byte[] signatureBytes = Numeric.hexStringToByteArray(signatureHex);
        byte v = signatureBytes[64];
        if (v < 27) {
            v = (byte) (v + 27);
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signatureBytes, 0, r, 0, 32);
        System.arraycopy(signatureBytes, 32, s, 0, 32);
        return new Sign.SignatureData(v, r, s);
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
}
