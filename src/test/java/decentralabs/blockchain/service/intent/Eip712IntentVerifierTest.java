package decentralabs.blockchain.service.intent;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;

import static org.assertj.core.api.Assertions.assertThat;

class Eip712IntentVerifierTest {

    private Eip712IntentVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new Eip712IntentVerifier(
            "",                       // trustedSigner
            "DecentraLabsIntent",     // domain name
            "1",                      // domain version
            11155111L,                // chain id (sepolia default in props)
            "0x0000000000000000000000000000000000000000" // verifying contract
        );
    }

    @Test
    void actionPayloadHashChangesWithMaxBatch() {
        ActionIntentPayload payload = basePayload();
        payload.setMaxBatch(BigInteger.valueOf(5));
        String hashWithBatch5 = verifier.computeActionPayloadHash(payload);

        payload.setMaxBatch(BigInteger.valueOf(6));
        String hashWithBatch6 = verifier.computeActionPayloadHash(payload);

        assertThat(hashWithBatch5).isNotBlank();
        assertThat(hashWithBatch6).isNotBlank();
        assertThat(hashWithBatch5).isNotEqualTo(hashWithBatch6);
    }

    private ActionIntentPayload basePayload() {
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
}
