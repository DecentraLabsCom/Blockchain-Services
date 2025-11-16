package decentralabs.blockchain.service.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SamlValidationServiceTest {

    private SamlValidationService samlValidationService;

    @BeforeEach
    void setUp() {
        samlValidationService = new SamlValidationService();
    }

    @Test
    void shouldAcceptAnyIdPInAnyMode() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of());

        boolean configured = samlValidationService.isConfigured();

        assertThat(configured).isTrue();
    }

    @Test
    void shouldRequireTrustedIdpsInWhitelistMode() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of());

        boolean configured = samlValidationService.isConfigured();

        assertThat(configured).isFalse();
    }

    @Test
    void shouldBeConfiguredWithTrustedIdpsInWhitelistMode() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "uned", "https://idp.uned.es"
        ));

        boolean configured = samlValidationService.isConfigured();

        assertThat(configured).isTrue();
    }

    @Test
    void shouldClearCertificateCache() {
        // Populate cache via reflection
        @SuppressWarnings("unchecked")
        Map<String, X509Certificate> cache = (Map<String, X509Certificate>) 
                ReflectionTestUtils.getField(samlValidationService, "certificateCache");
        
        assertThat(cache).isEmpty();

        samlValidationService.clearCertificateCache();

        assertThat(cache).isEmpty();
    }

    @Test
    void shouldRejectSamlAssertionWithoutIssuer() {
        String invalidSaml = Base64.getEncoder().encodeToString(
                "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>".getBytes()
        );

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(invalidSaml))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("No Issuer found");
    }

    @Test
    void shouldRejectUntrustedIdPInWhitelistMode() {
        String samlWithIssuer = createMinimalSamlAssertion("https://untrusted-idp.com");
        String encodedSaml = Base64.getEncoder().encodeToString(samlWithIssuer.getBytes());

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "uned", "https://idp.uned.es"
        ));

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(encodedSaml))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("not in trusted list");
    }

    @Test
    void shouldRejectSamlAssertionWithoutSignature() {
        String samlWithoutSignature = createMinimalSamlAssertion("https://idp.uned.es");
        String encodedSaml = Base64.getEncoder().encodeToString(samlWithoutSignature.getBytes());

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(encodedSaml))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldRejectSamlAssertionWithoutUserid() {
        String samlWithoutUserid = createSamlAssertionWithAttributes("https://idp.uned.es", Map.of(
                "affiliation", "student@uned.es"
        ));
        String encodedSaml = Base64.getEncoder().encodeToString(samlWithoutUserid.getBytes());

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(encodedSaml))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldRejectSamlAssertionWithoutAffiliation() {
        String samlWithoutAffiliation = createSamlAssertionWithAttributes("https://idp.uned.es", Map.of(
                "userid", "user123"
        ));
        String encodedSaml = Base64.getEncoder().encodeToString(samlWithoutAffiliation.getBytes());

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(encodedSaml))
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldExtractIssuerFromSamlAssertion() throws Exception {
        String saml = createMinimalSamlAssertion("https://idp.test.com");
        Document doc = parseXML(saml);

        String issuer = ReflectionTestUtils.invokeMethod(samlValidationService, "extractIssuer", doc);

        assertThat(issuer).isEqualTo("https://idp.test.com");
    }

    @Test
    void shouldReturnNullWhenIssuerNotPresent() throws Exception {
        String saml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></saml:Assertion>";
        Document doc = parseXML(saml);

        String issuer = ReflectionTestUtils.invokeMethod(samlValidationService, "extractIssuer", doc);

        assertThat(issuer).isNull();
    }

    @Test
    void shouldCheckTrustedIdPCorrectly() {
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "uned", "https://idp.uned.es",
                "ucm", "https://idp.ucm.es"
        ));

        Boolean trustedResult = ReflectionTestUtils.invokeMethod(
                samlValidationService, "isTrustedIdP", "https://idp.uned.es"
        );
        Boolean untrustedResult = ReflectionTestUtils.invokeMethod(
                samlValidationService, "isTrustedIdP", "https://idp.other.es"
        );

        assertThat(trustedResult).isNotNull().isTrue();
        assertThat(untrustedResult).isNotNull().isFalse();
    }

    @Test
    void shouldReturnFalseWhenTrustedIdpsIsNull() {
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", null);

        Boolean trustedResult = ReflectionTestUtils.invokeMethod(
                samlValidationService, "isTrustedIdP", "https://idp.test.com"
        );

        assertThat(trustedResult).isNotNull().isFalse();
    }

    // Helper methods

    private String createMinimalSamlAssertion(String issuer) {
        return "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
                "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " +
                "ID=\"_test123\" Version=\"2.0\">" +
                "<saml:Issuer>" + issuer + "</saml:Issuer>" +
                "</saml:Assertion>";
    }

    private String createSamlAssertionWithAttributes(String issuer, Map<String, String> attributes) {
        StringBuilder sb = new StringBuilder();
        sb.append("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
                "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " +
                "ID=\"_test123\" Version=\"2.0\">");
        sb.append("<saml:Issuer>").append(issuer).append("</saml:Issuer>");
        sb.append("<saml:AttributeStatement>");
        
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            sb.append("<saml:Attribute Name=\"").append(entry.getKey()).append("\">");
            sb.append("<saml:AttributeValue>").append(entry.getValue()).append("</saml:AttributeValue>");
            sb.append("</saml:Attribute>");
        }
        
        sb.append("</saml:AttributeStatement>");
        sb.append("</saml:Assertion>");
        
        return sb.toString();
    }

    private Document parseXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        
        // Prevent XXE attacks - disable external entities
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }
}
