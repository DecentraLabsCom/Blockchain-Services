package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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

    @Test
    void rejectsSha1ReferenceDigests() throws Exception {
        Reference reference = mock(Reference.class);
        DigestMethod digestMethod = mock(DigestMethod.class);
        when(reference.getTransforms()).thenReturn(List.of());
        when(reference.getCalculatedDigestValue()).thenReturn(new byte[] {1});
        when(reference.getDigestMethod()).thenReturn(digestMethod);
        when(digestMethod.getAlgorithm()).thenReturn(DigestMethod.SHA1);

        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element assertion = document.createElement("Assertion");
        document.appendChild(assertion);

        assertThatThrownBy(() -> service.hashValidatedReference(reference, assertion))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Unsupported SAML Reference digest algorithm: " + DigestMethod.SHA1);
    }
}
