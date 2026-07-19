package decentralabs.blockchain.service.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import decentralabs.blockchain.util.PucHashUtil;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class SamlValidationServiceTest {

    private static final String TEST_ISSUER = "https://idp.test.example";
    private static final String TEST_CERTIFICATE = """
        -----BEGIN CERTIFICATE-----
        MIICwTCCAamgAwIBAgIJAOCS6GnJozZdMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNV
        BAMTFURlY2VudHJhTGFicyBUZXN0IElkUDAeFw0yNjA3MDMxNzA3MTVaFw0zMTA3
        MDQxNzA3MTVaMCAxHjAcBgNVBAMTFURlY2VudHJhTGFicyBUZXN0IElkUDCCASIw
        DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANr1oNz3grhr9FplwGYD0oosLP0X
        X5JUlYPqa8FXHrnmx/K0Qtb3Gg6+IdxPcJllGpbJ7JWY8wZipNNDEE+CiTx/fQFT
        0iE1X5tPzEj6l677U1BBijyoziL47e8Z8voJ068aIXL7dDmpe/S7u9RavL3aQtfI
        gzd3M/AVu/M2BBX+j7u0p8LGCeKIEItwqRHI440dt8TYr/Ia3F+dv7Y5GtgtzUu7
        7j91jNMcYapnHtPJBd3fCevv/nOgpj0QOB6yOgLPW4EjLM9TCmmZ/8Qk1VlUZX7p
        /VmaMEn+FgmpxWveXXRt89h7sR7vAfjt7Xxkp48WSqOLMQjw0euFl4NYlJECAwEA
        ATANBgkqhkiG9w0BAQsFAAOCAQEAtSLy7RipWYhwLrGDlZOnNC9m832QhzibKP59
        Jn7IQaVumyflMpS6Y7TF3PNInrO7UJIirOpKYXPYoBurQoZv074G9KEG2cz1vlqZ
        UXokPBvRLObiJazK1waJz8z0fCV440aOOm2r7GPwxCgSkUr+M6CSvv2vcoAedhgB
        AeTAdWvvKOntYT5kl9XsigRP9CfsPCgPoiZtfgi5CTOJ2Wc4p32rSEb0+I7oJ4yK
        mhi+LjFhmuzezugwVrGH+UG5p03JGw8FgBusEyCLShJUc0FNgmXB+oBgTQ4gM6+x
        WFNKJemb0h0gzccExT9mjTwEwwvaXoZf/SGaORrLA5fv3khDyQ==
        -----END CERTIFICATE-----
        """;

    private SamlValidationService samlValidationService;

    @BeforeEach
    void setUp() throws Exception {
        samlValidationService = new SamlValidationService();
        seedTestMetadataCertificate();
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
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of(
                "https://idp.uned.es", "https://idp.uned.es/metadata"
        ));

        boolean configured = samlValidationService.isConfigured();

        assertThat(configured).isTrue();
    }

    @Test
    void shouldRequireMetadataOverrideForEveryWhitelistedIdp() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "uned", "https://idp.uned.es",
                "ucm", "https://idp.ucm.es"
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of(
                "https://idp.uned.es", "https://idp.uned.es/metadata"
        ));

        assertThat(samlValidationService.isConfigured()).isFalse();
        assertThat(samlValidationService.configurationErrors())
                .anyMatch(error -> error.contains("https://idp.ucm.es"));
    }

    @Test
    void shouldNotUseGlobalMetadataOverrideAsWhitelistConfiguration() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "uned", "https://idp.uned.es"
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataUrlOverride", "https://metadata.example/idp");
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of());

        assertThat(samlValidationService.isConfigured()).isFalse();
    }

    @Test
    void shouldRejectUnknownIssuerTlsProfile() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "uned", "https://idp.uned.es"
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of(
                "https://idp.uned.es", "https://idp.uned.es/metadata"
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataTlsProfiles", Map.of(
                "https://idp.uned.es", "legacy"
        ));

        assertThat(samlValidationService.isConfigured()).isFalse();
        assertThat(samlValidationService.configurationErrors())
                .anyMatch(error -> error.contains("legacy"));
    }

    @Test
    void shouldResolveCompatibilityTlsProfileOnlyForConfiguredIssuer() {
        ReflectionTestUtils.setField(samlValidationService, "metadataTlsProfiles", Map.of(
                TEST_ISSUER, "compatibility"
        ));

        String configured = ReflectionTestUtils.invokeMethod(
                samlValidationService, "resolveMetadataTlsProfile", TEST_ISSUER
        );
        String defaultProfile = ReflectionTestUtils.invokeMethod(
                samlValidationService, "resolveMetadataTlsProfile", "https://other-idp.example"
        );

        assertThat(configured).isEqualTo("compatibility");
        assertThat(defaultProfile).isEqualTo("modern");
    }

    @Test
    void shouldReportMetadataHealthDownWhenMetadataProbeFails() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "test", TEST_ISSUER
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of(
                TEST_ISSUER, "https://metadata.test.example/idp"
        ));
        ReflectionTestUtils.setField(
                samlValidationService,
                "metadataDownloader",
                (SamlValidationService.MetadataDownloader) (url, tlsProfile) -> {
                    throw new IOException("metadata unavailable");
                }
        );

        samlValidationService.refreshMetadataSnapshotsNow();
        Map<String, Object> health = samlValidationService.metadataHealth();

        assertThat(health).containsEntry("status", "DOWN");
        assertThat(health.get("failedIssuers").toString()).contains(TEST_ISSUER);
    }

    @Test
    void shouldReportMetadataHealthUpAfterConfiguredIssuerMetadataProbe() {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of(
                "test", TEST_ISSUER
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of(
                TEST_ISSUER, "https://metadata.test.example/idp"
        ));
        ReflectionTestUtils.setField(samlValidationService, "metadataTlsProfiles", Map.of(
                TEST_ISSUER, "compatibility"
        ));
        ReflectionTestUtils.setField(
                samlValidationService,
                "metadataDownloader",
                (SamlValidationService.MetadataDownloader) (url, tlsProfile) -> {
                    assertThat(url).isEqualTo("https://metadata.test.example/idp");
                    assertThat(tlsProfile).isEqualTo("compatibility");
                    return samlValidationService.parseCertificatesFromMetadataXml(testMetadataXml());
                }
        );

        samlValidationService.refreshMetadataSnapshotsNow();
        Map<String, Object> health = samlValidationService.metadataHealth();

        assertThat(health).containsEntry("status", "UP");
        assertThat(health.get("checkedIssuers").toString()).contains(TEST_ISSUER);
        assertThat(health.get("failedIssuers").toString()).isEqualTo("[]");
    }

    @Test
    void shouldClearCertificateCache() {
        // Populate cache via reflection
        @SuppressWarnings("unchecked")
        Map<String, X509Certificate> cache = (Map<String, X509Certificate>) 
                ReflectionTestUtils.getField(samlValidationService, "certificateCache");
        
        assertThat(cache).containsKey(TEST_ISSUER);

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
        String samlWithoutSignature = createMinimalSamlAssertion(TEST_ISSUER);
        String encodedSaml = Base64.getEncoder().encodeToString(samlWithoutSignature.getBytes());

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(encodedSaml))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("signature is INVALID");
    }

    @Test
    void shouldRejectSamlAssertionWithoutPucIdentityAttributes() throws Exception {
        String encodedSaml = createSignedSamlAssertionWithAttributes(Map.of(
                "affiliation", "student@uned.es"
        ));

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(encodedSaml))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("PUC identity attributes");
    }

    @Test
    void shouldAcceptSamlAssertionWithoutAffiliationWhenPucIdentityIsPresent() throws Exception {
        String encodedSaml = createSignedSamlAssertionWithAttributes(Map.of(
                "eduPersonPrincipalName", "user123"
        ));

        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");

        Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(encodedSaml);

        assertThat(attributes)
                .containsEntry("puc", "user123")
                .containsKey("affiliation");
        assertThat(attributes.get("affiliation")).isNull();
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

    @Test
    void shouldResolveStableUserIdWithCombinedEppnAndTargetedId() {
        String stableUserId = samlValidationService.resolveStableUserId(
                "user@university.edu",
                "targeted-user-1"
        );

        assertThat(stableUserId).isEqualTo("user@university.edu|targeted-user-1");
    }

    @Test
    void shouldResolveStableUserIdWithOnlyEppnWhenTargetedIdMissing() {
        String stableUserId = samlValidationService.resolveStableUserId(
                "user@university.edu",
                null
        );

        assertThat(stableUserId).isEqualTo("user@university.edu");
    }

    @Test
    void shouldValidateSignedAssertionUsingGeneratedMetadataCertificate() throws Exception {
        String signedAssertion = createSignedSamlAssertionWithAttributes(Map.of(
                "eduPersonPrincipalName", "user@university.edu",
                "eduPersonTargetedID", "targeted-user-1",
                "affiliation", "student@university.edu"
        ));

        Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(signedAssertion);

        assertThat(attributes)
                .containsEntry("puc", "user@university.edu|targeted-user-1")
                .containsEntry("eduPersonPrincipalName", "user@university.edu")
                .containsEntry("eduPersonTargetedID", "targeted-user-1");
    }

    @Test
    void shouldRefreshExactlyOnceWhenTheCachedCertificateCannotVerifyTheSignature() throws Exception {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");
        ReflectionTestUtils.setField(samlValidationService, "metadataUrlOverride", "https://metadata.test.example/idp");
        X509Certificate cachedCertificate = mock(X509Certificate.class);
        @SuppressWarnings("unchecked")
        Map<String, List<X509Certificate>> cache = (Map<String, List<X509Certificate>>)
                ReflectionTestUtils.getField(samlValidationService, "certificateCache");
        cache.put(TEST_ISSUER, List.of(cachedCertificate));

        AtomicInteger downloads = new AtomicInteger();
        ReflectionTestUtils.setField(
                samlValidationService,
                "metadataDownloader",
                (SamlValidationService.MetadataDownloader) (url, tlsProfile) -> {
                    downloads.incrementAndGet();
                    return samlValidationService.parseCertificatesFromMetadataXml(testMetadataXml());
                }
        );

        Map<String, String> attributes = samlValidationService.validateSamlAssertionWithSignature(
                createSignedSamlAssertionWithAttributes(Map.of(
                        "eduPersonPrincipalName", "user@university.edu",
                        "eduPersonTargetedID", "targeted-user-1",
                        "affiliation", "student@university.edu"
                ))
        );

        assertThat(attributes).containsEntry("puc", "user@university.edu|targeted-user-1");
        assertThat(downloads).hasValue(1);
    }

    @Test
    void shouldNotRetryMetadataMoreThanOnceAfterASecondInvalidSignature() throws Exception {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "any");
        ReflectionTestUtils.setField(samlValidationService, "metadataUrlOverride", "https://metadata.test.example/idp");
        X509Certificate cachedCertificate = mock(X509Certificate.class);
        @SuppressWarnings("unchecked")
        Map<String, List<X509Certificate>> cache = (Map<String, List<X509Certificate>>)
                ReflectionTestUtils.getField(samlValidationService, "certificateCache");
        cache.put(TEST_ISSUER, List.of(cachedCertificate));

        AtomicInteger downloads = new AtomicInteger();
        ReflectionTestUtils.setField(
                samlValidationService,
                "metadataDownloader",
                (SamlValidationService.MetadataDownloader) (url, tlsProfile) -> {
                    downloads.incrementAndGet();
                    return List.of(mock(X509Certificate.class));
                }
        );

        assertThatThrownBy(() -> samlValidationService.validateSamlAssertionWithSignature(
                createSignedSamlAssertionWithAttributes(Map.of(
                        "eduPersonPrincipalName", "user@university.edu",
                        "eduPersonTargetedID", "targeted-user-1",
                        "affiliation", "student@university.edu"
                ))
        )).hasMessageContaining("INVALID");
        assertThat(downloads).hasValue(1);
    }

    @Test
    void metadataHealthRefreshesTheAuthenticationSnapshotAndDoesNotDownloadOnRead() throws Exception {
        ReflectionTestUtils.setField(samlValidationService, "trustMode", "whitelist");
        ReflectionTestUtils.setField(samlValidationService, "trustedIdps", Map.of("test", TEST_ISSUER));
        ReflectionTestUtils.setField(samlValidationService, "metadataOverrides", Map.of(
                TEST_ISSUER, "https://metadata.test.example/idp"
        ));
        AtomicInteger downloads = new AtomicInteger();
        ReflectionTestUtils.setField(
                samlValidationService,
                "metadataDownloader",
                (SamlValidationService.MetadataDownloader) (url, tlsProfile) -> {
                    downloads.incrementAndGet();
                    return samlValidationService.parseCertificatesFromMetadataXml(testMetadataXml());
                }
        );

        samlValidationService.refreshMetadataSnapshotsNow();
        Map<String, Object> first = samlValidationService.metadataHealth();
        Map<String, Object> second = samlValidationService.metadataHealth();

        assertThat(first).containsEntry("status", "UP");
        assertThat(second).containsEntry("status", "UP");
        assertThat(downloads).hasValue(1);
        @SuppressWarnings("unchecked")
        Map<String, List<X509Certificate>> cache = (Map<String, List<X509Certificate>>)
                ReflectionTestUtils.getField(samlValidationService, "certificateCache");
        assertThat(cache.get(TEST_ISSUER)).hasSize(1);
    }

    @Test
    void shouldResolvePrincipalModeFromValidatedAttributes() {
        String stableUserId = samlValidationService.resolveStableUserId(
                Map.of(
                        "puc", "user@university.edu|targeted-user-1",
                        "eduPersonPrincipalName", "user@university.edu",
                        "eduPersonTargetedID", "targeted-user-1"
                ),
                SamlValidationService.STABLE_USER_ID_MODE_PRINCIPAL,
                null
        );

        assertThat(stableUserId).isEqualTo("user@university.edu");
    }

    @Test
    void shouldResolveCompositeModeFromValidatedAttributes() {
        String stableUserId = samlValidationService.resolveStableUserId(
                Map.of(
                        "puc", "user@university.edu|targeted-user-1",
                        "eduPersonPrincipalName", "user@university.edu",
                        "eduPersonTargetedID", "targeted-user-1"
                ),
                SamlValidationService.STABLE_USER_ID_MODE_PRINCIPAL_TARGETED_ID,
                null
        );

        assertThat(stableUserId).isEqualTo("user@university.edu|targeted-user-1");
    }

    @Test
    void shouldInferStableUserIdFromExpectedPucHashWhenModeMissing() {
        String stableUserId = samlValidationService.resolveStableUserId(
                Map.of(
                        "puc", "user@university.edu|targeted-user-1",
                        "eduPersonPrincipalName", "user@university.edu",
                        "eduPersonTargetedID", "targeted-user-1"
                ),
                null,
                PucHashUtil.hashPuc("user@university.edu")
        );

        assertThat(stableUserId).isEqualTo("user@university.edu");
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

    private String createSignedSamlAssertionWithAttributes(Map<String, String> attributes) throws Exception {
        String xml = createSamlAssertionWithAttributes(TEST_ISSUER, attributes)
                .replace("ID=\"_test123\"", "ID=\"_signed123\"");
        Document doc = parseXML(xml);
        doc.getDocumentElement().setIdAttribute("ID", true);

        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        Reference reference = signatureFactory.newReference(
                "#_signed123",
                signatureFactory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null,
                null
        );
        SignedInfo signedInfo = signatureFactory.newSignedInfo(
                signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                List.of(reference)
        );
        List<X509Certificate> certificates = samlValidationService.parseCertificatesFromMetadataXml(testMetadataXml());
        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(List.of(
                keyInfoFactory.newX509Data(List.of(certificates.get(0)))
        ));
        DOMSignContext signContext = new DOMSignContext(testPrivateKey(), doc.getDocumentElement());
        signatureFactory.newXMLSignature(signedInfo, keyInfo).sign(signContext);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        transformerFactory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "");
        var transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return Base64.getEncoder().encodeToString(writer.toString().getBytes());
    }

    private void seedTestMetadataCertificate() throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, List<X509Certificate>> cache = (Map<String, List<X509Certificate>>)
                ReflectionTestUtils.getField(samlValidationService, "certificateCache");
        cache.put(TEST_ISSUER, samlValidationService.parseCertificatesFromMetadataXml(testMetadataXml()));
    }

    private String testMetadataXml() {
        String certBody = TEST_CERTIFICATE
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        return """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing">
                      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:X509Data>
                          <ds:X509Certificate>%s</ds:X509Certificate>
                        </ds:X509Data>
                      </ds:KeyInfo>
                    </md:KeyDescriptor>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """.formatted(TEST_ISSUER, certBody);
    }

    private PrivateKey testPrivateKey() throws Exception {
        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                positive("2vWg3PeCuGv0WmXAZgPSiiws/RdfklSVg+prwVceuebH8rRC1vcaDr4h3E9wmWUalsnslZjzBmKk00MQT4KJPH99AVPSITVfm0/MSPqXrvtTUEGKPKjOIvjt7xny+gnTrxohcvt0Oal79Lu71Fq8vdpC18iDN3cz8BW78zYEFf6Pu7SnwsYJ4ogQi3CpEcjjjR23xNiv8hrcX52/tjka2C3NS7vuP3WM0xxhqmce08kF3d8J6+/+c6CmPRA4HrI6As9bgSMsz1MKaZn/xCTVWVRlfun9WZowSf4WCanFa95ddG3z2HuxHu8B+O3tfGSnjxZKo4sxCPDR64WXg1iUkQ=="),
                positive("AQAB"),
                positive("dFqWsxVsB6iGXws3JH7fgMFc3tlu1gnQshr+S+2JzGwQ0K5t3mHNHQx4XeRxB3KsoHiJGi3+5uPAhutaXYYWe2mb+fqa7T65oYTUH+vacwfnC/zoArgJYpg5iBeYALr8HE6ce8eXyZSA5Fpmw7+8EH9NifFpmS3lEa3bBLEtlqmFXScduz1UUeRgr1VKapRy5Aip6F6iXVGGtmeofDNDV2JJrZGflzskMaiGZ6vfxY1CRStLd3Asgv3PFnG8qSSvClEfVLbhVGB5lvEjNpXT7jfBKP1+NpkShYeH8gD1wiISIMu/fjRb517FO5JjjT8oIrXamnATmGKaugXue6uuCQ=="),
                positive("3FbpIuDVdfBRFOdwuG6aaIvFBez8uPurkSFrAHCPzCz9Dwu8HcJIYsz60qbGUWHww2JMNeWhBN6YJcNVJqjOQvfdRm1BSHblF+Zz2WcTrNsCQQerhfGcu9DyDtb/fj9b1w5dvY77g41jozIrsJ7p0UL9VMwnm5uzF0FO+GGmm2s="),
                positive("/mWKj4YigguVr9OHyQCxRTVVte/3Sijgfxih/PJVjikRmOTl8hc3DEMMqsi+9a/3ZizZb4TKHcxpeTJCiS8x7TMylMNFihyytQyH2x9bQ/SvrdFjyPwsX9tP/2yVQaNUdnhtNm856wBcTkdT2XSIv9lK1Vk6o6tTJCyRcdp6qvM="),
                positive("VMtpmw+VdnbObVIIEiIWcCdh4j7qnzHTO931dMzcugGSPakRcw5ilws1d73Q0l7zre11UMSXK+2R9e5vJZqPDjyfPkwrdHy0+3annMHLU5lRC7+s5bYu0CTAEq/w0SAG8wNHVfzhlCXkc1iKccUmTG8QWQLcN0k7KbbrcjD6UhM="),
                positive("3LEOMVB2I0cVhkEFrPQy1Q1d28XfS7CGgPvHm35HhlpOb8szSH+nO7X3CTm5n74V68fAoaQbCxrH7WISopwUvegKW0/Dxfr7dWD3grqDHELrHOlnnXZWsJm7nqR+H0EoBtaWOADpx9q6ORZbwWv9LiG9b7RG0LHSILGhQ5n7jM0="),
                positive("XTxRvwGFvTvqbiL6UsNtelJM1/Qycz+oW80/aAcgMj4ljJ+g0KHt+04eafr8Mdx4Ppcv5bFUxaxDE5J5fsRZkJvhXQTuMrrZEEHkYSzialH7US217JwnzsGrYS1FOs1cY+5Up10ZKfCWvvrgOKgHUbt0pib0oq1TXy42IcKlsPk=")
        );
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private BigInteger positive(String base64) {
        return new BigInteger(1, Base64.getDecoder().decode(base64));
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
