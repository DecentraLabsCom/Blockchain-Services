package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SamlAttestationHashServiceTest {

    private final SamlAttestationHashService service = new SamlAttestationHashService();

    @Test
    void hashesCanonicalSignedAssertionBytesWithTheV2DomainPrefix() {
        String hash = service.hashCanonicalSignedAssertion(
            "canonical-signed-assertion".getBytes(StandardCharsets.UTF_8)
        );

        assertThat(hash)
            .isEqualTo("0xc0208c8af7e731e62219c76036b652730a7a4be5916c7dd99e6813ec31931f81");
    }

    @Test
    void rejectsMissingCanonicalBytes() {
        assertThatThrownBy(() -> service.hashCanonicalSignedAssertion(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Canonical signed assertion bytes are required");
        assertThatThrownBy(() -> service.hashCanonicalSignedAssertion(new byte[0]))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Canonical signed assertion bytes are required");
    }
}
