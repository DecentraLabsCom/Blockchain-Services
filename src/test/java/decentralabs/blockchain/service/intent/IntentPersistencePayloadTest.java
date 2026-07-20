package decentralabs.blockchain.service.intent;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.IntentSubmission;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class IntentPersistencePayloadTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void persistencePayloadDoesNotContainFederatedOrWebauthnMaterial() throws Exception {
        IntentSubmission submission = new IntentSubmission();
        IntentMeta meta = new IntentMeta();
        meta.setRequestId("0x" + "1".repeat(64));
        meta.setSigner("0x" + "2".repeat(40));
        meta.setExecutor("0x" + "3".repeat(40));
        meta.setAction(1);
        meta.setPayloadHash("0x" + "4".repeat(64));
        meta.setNonce(7L);
        meta.setRequestedAt(100L);
        meta.setExpiresAt(200L);
        submission.setMeta(meta);

        ActionIntentPayload actionPayload = new ActionIntentPayload();
        actionPayload.setExecutor(meta.getExecutor());
        actionPayload.setLabId(BigInteger.ONE);
        actionPayload.setAccessKey("execution-material");
        submission.setActionPayload(actionPayload);
        submission.setSignature("eip712-signature");
        submission.setSamlAssertion("full-saml-assertion");
        submission.setWebauthnCredentialId("credential-id");
        submission.setWebauthnClientDataJSON("client-data");
        submission.setWebauthnAuthenticatorData("authenticator-data");
        submission.setWebauthnSignature("webauthn-signature");

        String json = objectMapper.writeValueAsString(IntentPersistencePayload.from(submission));
        JsonNode persisted = objectMapper.readTree(json);

        assertThat(json).contains("execution-material");
        assertThat(json).doesNotContain(
            "full-saml-assertion",
            "credential-id",
            "client-data",
            "authenticator-data",
            "webauthn-signature",
            "eip712-signature"
        );
        assertThat(persisted.has("samlAssertion")).isFalse();
        assertThat(persisted.has("webauthnCredentialId")).isFalse();
        assertThat(persisted.has("webauthnClientDataJSON")).isFalse();
        assertThat(persisted.has("webauthnAuthenticatorData")).isFalse();
        assertThat(persisted.has("webauthnSignature")).isFalse();
        assertThat(persisted.has("signature")).isFalse();
        assertThat(persisted.has("typedData")).isFalse();
    }
}
