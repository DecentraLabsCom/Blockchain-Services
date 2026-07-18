package decentralabs.blockchain.service.auth;

import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.logging.HttpLoggingInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.PucNormalizer;

/**
 * Service for validating SAML assertions with automatic IdP discovery
 * 
 * Features:
 * - Automatic extraction of IdP metadata URL from SAML assertion
 * - Automatic certificate retrieval from IdP metadata endpoint
 * - Support for "trust any IdP" or "whitelist only" modes
 * - Certificate caching for performance
 */
@Service
public class SamlValidationService {
    
    private static final Logger logger = LoggerFactory.getLogger(SamlValidationService.class);
    public static final String STABLE_USER_ID_MODE_PRINCIPAL = "principal";
    public static final String STABLE_USER_ID_MODE_PRINCIPAL_TARGETED_ID = "principal_targeted_id";

    private static final String[] EDU_PERSON_TARGETED_ID_ATTRIBUTE_ALIASES = new String[] {
        "edupersontargetedid",
        "pairwise-id",
        "persistent-id",
        "urn:mace:dir:attribute-def:edupersontargetedid",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"
    };

    private static final String[] EDU_PERSON_PRINCIPAL_NAME_ATTRIBUTE_ALIASES = new String[] {
        "eppn",
        "edupersonprincipalname",
        "subject-id",
        "urn:oasis:names:tc:saml:attribute:subject-id",
        "urn:mace:dir:attribute-def:edupersonprincipalname",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
    };

    private static final String[] SCOPED_AFFILIATION_ATTRIBUTE_ALIASES = new String[] {
        "edupersonscopedaffiliation",
        "urn:mace:dir:attribute-def:edupersonscopedaffiliation",
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
    };

    private static final String[] EMAIL_ATTRIBUTE_ALIASES = new String[] {
        "mail",
        "email",
        "emailaddress",
        "mailprimaryaddress",
        "mailalternateaddress",
        "urn:mace:dir:attribute-def:mail",
        "urn:oid:1.2.840.113549.1.9.1",
        "urn:oid:0.9.2342.19200300.100.1.3"
    };

    private static final String[] DISPLAY_NAME_ATTRIBUTE_ALIASES = new String[] {
        "displayname",
        "display-name",
        "cn",
        "commonname",
        "givenname",
        "sn",
        "urn:mace:dir:attribute-def:displayname",
        "urn:mace:dir:attribute-def:cn",
        "urn:oid:2.16.840.1.113730.3.1.241",
        "urn:oid:2.5.4.42",
        "urn:oid:2.5.4.4",
        "urn:oid:2.5.4.3"
    };

    private static final String[] SCHAC_HOME_ORG_ATTRIBUTE_ALIASES = new String[] {
        "schachomeorganization",
        "urn:mace:dir:attribute-def:schachomeorganization",
        "urn:oid:1.3.6.1.4.1.25178.1.2.9"
    };
    
    @Value("${saml.idp.trust-mode:whitelist}")
    private String trustMode;

    @Value("${saml.metadata.allow-http:false}")
    private boolean allowHttpMetadata;

    @Value("${saml.idp.metadata.url:}")
    private String metadataUrlOverride;

    @Value("${saml.metadata.http.connect-timeout-ms:5000}")
    private int metadataHttpConnectTimeoutMs;

    @Value("${saml.metadata.http.read-timeout-ms:10000}")
    private int metadataHttpReadTimeoutMs;

    @Value("${saml.metadata.http.call-timeout-ms:15000}")
    private int metadataHttpCallTimeoutMs;

    @Value("${saml.metadata.http.logging.enabled:false}")
    private boolean metadataHttpLoggingEnabled;
    
    // Optional: only used in whitelist mode
    private Map<String, String> trustedIdps = Collections.emptyMap();
    private Map<String, String> metadataOverrides = Collections.emptyMap();
    
    @Autowired(required = false)
    public void setTrustedIdps(@Value("#{${saml.trusted.idp:{}}}") Map<String, String> trustedIdps) {
        if (trustedIdps != null) {
            this.trustedIdps = trustedIdps;
        }
    }

    @Autowired(required = false)
    public void setMetadataOverrides(@Value("#{${saml.idp.metadata.override:{}}}") Map<String, String> metadataOverrides) {
        if (metadataOverrides != null) {
            this.metadataOverrides = metadataOverrides;
        }
    }
    
    // Cache for IdP certificates (issuer -> certificates)
    private static final int MAX_CERTIFICATE_CACHE_SIZE = 500;
    private final Map<String, List<X509Certificate>> certificateCache = new ConcurrentHashMap<>();
    
    /**
     * Validates SAML assertion with signature verification and extracts attributes
     * Automatically discovers IdP metadata and retrieves certificate
     * 
     * @param samlAssertion Base64-encoded SAML assertion XML
     * @return Map of SAML attributes (puc, affiliation, etc.)
     * @throws Exception if validation fails or signature is invalid
     */
    public Map<String, String> validateSamlAssertionWithSignature(String samlAssertion) throws Exception {
        SamlAssertionAttributes attrs = validateSamlAssertionDetailed(samlAssertion);
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("puc", attrs.puc());
        attributes.put("affiliation", attrs.affiliation());
        if (attrs.email() != null) {
            attributes.put("email", attrs.email());
        }
        firstAttribute(attrs, "eduPersonPrincipalName").ifPresent(value -> attributes.put("eduPersonPrincipalName", value));
        firstAttribute(attrs, "eduPersonTargetedID").ifPresent(value -> attributes.put("eduPersonTargetedID", value));
        attributes.put("issuer", attrs.issuer());
        return attributes;
    }

    public String resolveStableUserId(
        Map<String, String> samlAttributes,
        String stableUserIdMode,
        String expectedPucHash
    ) {
        if (samlAttributes == null || samlAttributes.isEmpty()) {
            return null;
        }

        String explicitPuc = normalizeIdentifier(samlAttributes.get("puc"));
        String principal = normalizeIdentifier(samlAttributes.get("eduPersonPrincipalName"));
        String targetedId = normalizeIdentifier(samlAttributes.get("eduPersonTargetedID"));
        String composite = resolveStableUserId(principal, targetedId);
        String requestedMode = normalizeStableUserIdMode(stableUserIdMode);

        if (STABLE_USER_ID_MODE_PRINCIPAL.equals(requestedMode) && principal != null) {
            return principal;
        }
        if (STABLE_USER_ID_MODE_PRINCIPAL_TARGETED_ID.equals(requestedMode) && composite != null) {
            return composite;
        }

        String expectedHash = normalizeExpectedPucHash(expectedPucHash);
        if (expectedHash != null) {
            String matching = firstMatchingPucHash(expectedHash, explicitPuc, principal, composite);
            if (matching != null) {
                return matching;
            }
        }

        return firstNonBlank(composite, principal, explicitPuc);
    }

    public SamlAssertionAttributes validateSamlAssertionDetailed(String samlAssertion) throws Exception {
        // Decode Base64 using MIME decoder which is lenient with whitespace.
        // Some IdPs send SAMLResponse with "+" not percent-encoded; URLSearchParams
        // in the Marketplace decodes those as spaces. getMimeDecoder() handles them.
        byte[] decodedBytes = Base64.getMimeDecoder().decode(samlAssertion);
        String xmlContent = new String(decodedBytes);
        
        // Parse XML
        Document doc = parseXML(xmlContent);
        markIdAttributes(doc);
        
        // Extract IdP issuer from assertion
        String issuer = extractIssuer(doc);
        if (issuer == null) {
            throw new SecurityException("No Issuer found in SAML assertion");
        }
        
        // Check if IdP is trusted (if in whitelist mode)
        if ("whitelist".equalsIgnoreCase(trustMode)) {
            if (!isTrustedIdP(issuer)) {
                throw new SecurityException("IdP " + issuer + " is not in trusted list");
            }
        }
        
        String metadataUrl = resolveMetadataUrl(doc, issuer);
        List<X509Certificate> certs = getIdpCertificates(issuer, metadataUrl);
        if (certs.isEmpty()) {
            if (metadataUrl == null) {
                throw new SecurityException("No metadata URL found for IdP: " + issuer);
            }
            throw new SecurityException("Could not retrieve certificate for IdP: " + issuer);
        }
        
        // Verify signature
        boolean signatureValid = verifySignature(doc, certs);
        if (!signatureValid) {
            throw new SecurityException("SAML assertion signature is INVALID");
        }
        
        // Extract attributes after signature validation.
        // Keep alignment with Marketplace PUC resolution:
        // if both ePPN and eduPersonTargetedID exist, use "ePPN|targetedID";
        // if only ePPN exists, use ePPN.
        String eduPersonTargetedId = extractSamlAttributeValueByAliases(doc, EDU_PERSON_TARGETED_ID_ATTRIBUTE_ALIASES);
        String eduPersonPrincipalName = extractSamlAttributeValueByAliases(doc, EDU_PERSON_PRINCIPAL_NAME_ATTRIBUTE_ALIASES);
        String email = extractSamlAttributeValueByAliases(doc, EMAIL_ATTRIBUTE_ALIASES);
        String displayName = extractSamlAttributeValueByAliases(doc, DISPLAY_NAME_ATTRIBUTE_ALIASES);
        List<String> schacHomeOrganizations = normalizeOrganizationDomains(
            extractSamlAttributeValuesByAliases(doc, SCHAC_HOME_ORG_ATTRIBUTE_ALIASES)
        );
        String scopedAffiliation = extractSamlAttributeValueByAliases(doc, SCOPED_AFFILIATION_ATTRIBUTE_ALIASES);
        String nameId = extractNameId(doc);

        if ((email == null || email.isBlank()) && looksLikeEmail(nameId)) {
            email = nameId;
        }

        String normalizedEduPersonTargetedId = normalizeIdentifier(eduPersonTargetedId);
        String normalizedEduPersonPrincipalName = normalizeIdentifier(eduPersonPrincipalName);
        String puc = resolveStableUserId(normalizedEduPersonPrincipalName, normalizedEduPersonTargetedId);

        if (puc == null || puc.isBlank()) {
            throw new SecurityException("SAML assertion missing PUC identity attributes");
        }

        String affiliation = resolveInstitutionDomain(
            firstOrNull(schacHomeOrganizations),
            scopedAffiliation,
            email
        );
        if (affiliation != null && !affiliation.isBlank() && schacHomeOrganizations.isEmpty()) {
            schacHomeOrganizations = List.of(affiliation);
        }

        logger.info("SAML assertion validated WITH SIGNATURE for PUC: {}", puc);

        Map<String, List<String>> capturedAttributes = new LinkedHashMap<>();
        putAttribute(capturedAttributes, "puc", puc);
        putAttribute(capturedAttributes, "affiliation", affiliation);
        putAttribute(capturedAttributes, "email", email);
        putAttribute(capturedAttributes, "displayName", displayName);
        putAttribute(capturedAttributes, "eduPersonTargetedID", normalizedEduPersonTargetedId);
        putAttribute(capturedAttributes, "eduPersonPrincipalName", normalizedEduPersonPrincipalName);
        if (!schacHomeOrganizations.isEmpty()) {
            capturedAttributes.put("schacHomeOrganization", schacHomeOrganizations);
        }

        return new SamlAssertionAttributes(
            issuer,
            puc,
            affiliation,
            email,
            displayName,
            schacHomeOrganizations,
            capturedAttributes
        );
    }

    private String extractNameId(Document doc) {
        NodeList nameIds = doc.getElementsByTagNameNS("*", "NameID");
        if (nameIds.getLength() > 0) {
            return nameIds.item(0).getTextContent().trim();
        }
        return null;
    }

    private boolean looksLikeEmail(String value) {
        return value != null && value.contains("@");
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private Optional<String> firstAttribute(SamlAssertionAttributes attrs, String name) {
        if (attrs == null || attrs.attributes() == null || name == null) {
            return Optional.empty();
        }
        List<String> values = attrs.attributes().get(name);
        if (values == null || values.isEmpty()) {
            return Optional.empty();
        }
        String normalized = normalizeIdentifier(values.get(0));
        return normalized == null ? Optional.empty() : Optional.of(normalized);
    }

    private String normalizeStableUserIdMode(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (STABLE_USER_ID_MODE_PRINCIPAL.equals(normalized)) {
            return STABLE_USER_ID_MODE_PRINCIPAL;
        }
        if (STABLE_USER_ID_MODE_PRINCIPAL_TARGETED_ID.equals(normalized)
            || "principal-targeted-id".equals(normalized)
            || "principal+targeted_id".equals(normalized)
            || "principal_targetedid".equals(normalized)) {
            return STABLE_USER_ID_MODE_PRINCIPAL_TARGETED_ID;
        }
        return null;
    }

    private String normalizeExpectedPucHash(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = PucHashUtil.normalizeBytes32(value);
        return PucHashUtil.zeroHash().equalsIgnoreCase(normalized) ? null : normalized;
    }

    private String firstMatchingPucHash(String expectedHash, String... candidates) {
        if (expectedHash == null || candidates == null) {
            return null;
        }
        for (String candidate : candidates) {
            String normalized = normalizeIdentifier(candidate);
            if (normalized != null && expectedHash.equalsIgnoreCase(PucHashUtil.hashPuc(normalized))) {
                return normalized;
            }
        }
        return null;
    }

    private String firstOrNull(List<String> values) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.get(0);
    }

    private String normalizeIdentifier(String value) {
        String normalized = PucNormalizer.normalize(value);
        if (normalized == null) {
            return null;
        }
        String trimmed = normalized.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    String resolveStableUserId(
        String eduPersonPrincipalName,
        String eduPersonTargetedId
    ) {
        if (eduPersonPrincipalName != null && !eduPersonPrincipalName.isBlank()) {
            if (eduPersonTargetedId != null && !eduPersonTargetedId.isBlank()) {
                return eduPersonPrincipalName + "|" + eduPersonTargetedId;
            }
            return eduPersonPrincipalName;
        }

        return null;
    }

    private List<String> normalizeOrganizationDomains(List<String> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return Collections.emptyList();
        }

        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String candidate : candidates) {
            String domain = normalizeDomainCandidate(candidate);
            if (domain != null) {
                normalized.add(domain);
            }
        }
        if (normalized.isEmpty()) {
            return Collections.emptyList();
        }
        return List.copyOf(normalized);
    }

    private String resolveInstitutionDomain(String... candidates) {
        if (candidates == null) {
            return null;
        }
        for (String candidate : candidates) {
            String domain = normalizeDomainCandidate(candidate);
            if (domain != null) {
                return domain;
            }
        }
        return null;
    }

    private String normalizeDomainCandidate(String rawValue) {
        if (rawValue == null) {
            return null;
        }

        String trimmed = rawValue.trim().toLowerCase(Locale.ROOT);
        if (trimmed.isEmpty()) {
            return null;
        }

        String domain = trimmed;
        if (domain.contains("@")) {
            String[] parts = domain.split("@");
            domain = parts[parts.length - 1];
        }

        domain = domain.replaceAll("^\\.+|\\.+$", "");
        if (domain.isEmpty() || !domain.contains(".")) {
            return null;
        }
        if (!domain.matches("^[a-z0-9.-]+$")) {
            return null;
        }
        return domain;
    }
    
    /**
     * Extracts the IdP issuer from SAML assertion
     */
    private String extractIssuer(Document doc) {
        NodeList issuerNodes = doc.getElementsByTagNameNS("*", "Issuer");
        if (issuerNodes.getLength() > 0) {
            return issuerNodes.item(0).getTextContent().trim();
        }
        return null;
    }
    
    /**
     * Extracts metadata URL from SAML assertion (if present)
     * SAML2 can include this in AuthnStatement or custom extensions
     */
    private String extractMetadataUrl(Document doc) {
        // Check for standard SAML2 metadata location in AuthnStatement
        NodeList authnStatements = doc.getElementsByTagNameNS("*", "AuthnStatement");
        if (authnStatements.getLength() > 0) {
            Element authnStatement = (Element) authnStatements.item(0);
            NodeList authnContexts = authnStatement.getElementsByTagNameNS("*", "AuthnContext");
            if (authnContexts.getLength() > 0) {
                Element authnContext = (Element) authnContexts.item(0);
                NodeList authenticatingAuthorities = authnContext.getElementsByTagNameNS("*", "AuthenticatingAuthority");
                if (authenticatingAuthorities.getLength() > 0) {
                    String authority = authenticatingAuthorities.item(0).getTextContent().trim();
                    // Authority URL often points to metadata endpoint
                    if (authority.contains("/metadata") || authority.contains("/FederationMetadata")) {
                        return authority;
                    }
                }
            }
        }
        
        // Check for custom extension with metadata URL
        NodeList extensions = doc.getElementsByTagNameNS("*", "Extensions");
        if (extensions.getLength() > 0) {
            Element ext = (Element) extensions.item(0);
            NodeList metadataNodes = ext.getElementsByTagNameNS("*", "MetadataURL");
            if (metadataNodes.getLength() > 0) {
                return metadataNodes.item(0).getTextContent().trim();
            }
        }
        
        return null;
    }

    private String resolveMetadataUrl(Document doc, String issuer) {
        String override = metadataOverrides.get(issuer);
        if (override != null && !override.isBlank()) {
            logger.info("Using metadata URL override for issuer {}", issuer);
            return override.trim();
        }
        if (metadataUrlOverride != null && !metadataUrlOverride.isBlank()) {
            logger.info("Using global metadata URL override for issuer {}", issuer);
            return metadataUrlOverride.trim();
        }
        return extractMetadataUrl(doc);
    }
    
    /**
     * Checks if IdP issuer is in trusted list
     */
    private boolean isTrustedIdP(String issuer) {
        if (trustedIdps == null) {
            return false;
        }
        return trustedIdps.values().stream()
                .anyMatch(trustedIssuer -> issuer.equals(trustedIssuer));
    }
    
    /**
     * Gets IdP certificate from cache or retrieves from metadata endpoint
     */
    private List<X509Certificate> getIdpCertificates(String issuer, String metadataUrl) {
        // Check cache first
        if (certificateCache.containsKey(issuer)) {
            logger.debug("Using cached certificate for IdP: {}", issuer);
            return certificateCache.get(issuer);
        }

        if (metadataUrl == null || metadataUrl.isBlank()) {
            return Collections.emptyList();
        }
        
        // Try to retrieve from metadata URL
        try {
            List<X509Certificate> certs = retrieveCertificatesFromMetadata(metadataUrl);
            if (!certs.isEmpty()) {
                if (certificateCache.size() >= MAX_CERTIFICATE_CACHE_SIZE) {
                    logger.warn("Certificate cache reached max size ({}), evicting oldest entries", MAX_CERTIFICATE_CACHE_SIZE);
                    var iterator = certificateCache.entrySet().iterator();
                    int toRemove = certificateCache.size() / 4;
                    for (int i = 0; i < toRemove && iterator.hasNext(); i++) {
                        iterator.next();
                        iterator.remove();
                    }
                }
                certificateCache.put(issuer, certs);
                logger.info("Retrieved and cached certificate from metadata for IdP: {}", issuer);
                return certs;
            }
        } catch (Exception e) {
            logger.warn("Could not retrieve certificate from metadata URL: {}", metadataUrl, e);
        }
        
        return Collections.emptyList();
    }
    
    /**
     * Retrieves certificate from IdP metadata endpoint
     * Security: Validates URL to prevent SSRF attacks
     */
    private List<X509Certificate> retrieveCertificatesFromMetadata(String metadataUrl) throws Exception {
        logger.debug("Retrieving certificate from metadata: {}", metadataUrl);
        
        // Validate URL to prevent SSRF attacks
        validateMetadataUrl(metadataUrl);
        
        String metadataXml = downloadMetadataXml(metadataUrl);
        return parseCertificatesFromMetadataXml(metadataXml);
    }

    List<X509Certificate> parseCertificatesFromMetadataXml(String metadataXml) throws Exception {
        Document metadataDoc = parseXML(metadataXml);
        
        // Find X509Certificate element in metadata
        NodeList certNodes = metadataDoc.getElementsByTagNameNS("*", "X509Certificate");
        if (certNodes.getLength() == 0) {
            logger.warn("No X509Certificate found in metadata");
            return Collections.emptyList();
        }
        
        List<X509Certificate> signingCerts = new ArrayList<>();
        List<X509Certificate> allCerts = new ArrayList<>();
        for (int i = 0; i < certNodes.getLength(); i++) {
            Node certNode = certNodes.item(i);
            
            // Check if this is a signing certificate
            Node keyDescriptor = certNode.getParentNode().getParentNode();
            if (keyDescriptor.getNodeName().contains("KeyDescriptor")) {
                Element keyDesc = (Element) keyDescriptor;
                String use = keyDesc.getAttribute("use");
                if (use.isEmpty() || "signing".equals(use)) {
                    String certData = certNode.getTextContent().trim();
                    X509Certificate cert = parseCertificate(certData);
                    signingCerts.add(cert);
                }
            }
            String certData = certNode.getTextContent().trim();
            allCerts.add(parseCertificate(certData));
        }
        
        if (!signingCerts.isEmpty()) {
            return signingCerts;
        }
        return allCerts;
    }

    private String downloadMetadataXml(String metadataUrl) throws Exception {
        Request request = new Request.Builder()
            .url(metadataUrl)
            .get()
            .header("Accept", "application/samlmetadata+xml, application/xml, text/xml;q=0.9,*/*;q=0.8")
            .header("User-Agent", "DecentraLabs-Blockchain-Services/1.0")
            .build();

        return executeMetadataRequest(buildMetadataHttpClient(), request);

    }

    private String executeMetadataRequest(OkHttpClient client, Request request) throws IOException {
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Metadata request failed with HTTP " + response.code());
            }
            ResponseBody body = response.body();
            if (body == null) {
                throw new IOException("Metadata request failed with empty body");
            }
            String xml = body.string();
            if (xml.isBlank()) {
                throw new IOException("Metadata request returned blank body");
            }
            return xml;
        }
    }

    private OkHttpClient buildMetadataHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
            .connectTimeout(metadataHttpConnectTimeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(metadataHttpReadTimeoutMs, TimeUnit.MILLISECONDS)
            .callTimeout(metadataHttpCallTimeoutMs, TimeUnit.MILLISECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .connectionSpecs(List.of(ConnectionSpec.MODERN_TLS));

        if (metadataHttpLoggingEnabled) {
            // Add basic HTTP logging for metadata requests when enabled (useful for debugging)
            builder.addInterceptor(new HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BASIC));
        }

        return builder.build();
    }

    /**
     * Parses Base64-encoded certificate
     */
    private X509Certificate parseCertificate(String certData) throws Exception {
        // Remove any whitespace or newlines
        certData = certData.replaceAll("\\s+", "");
        
        byte[] certBytes = Base64.getDecoder().decode(certData);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }
    
    /**
     * Verifies XML signature using certificate
     */
    private boolean verifySignature(Document doc, List<X509Certificate> certs) throws Exception {
        if (certs == null || certs.isEmpty()) {
            logger.warn("No certificates provided for SAML signature validation");
            return false;
        }

        Exception lastError = null;
        for (X509Certificate cert : certs) {
            try {
                if (verifySignatureWithCert(doc, cert)) {
                    return true;
                }
            } catch (Exception ex) {
                lastError = ex;
                logger.debug("SAML signature verification failed for cert {}: {}", describeCert(cert), ex.getMessage());
            }
        }

        if (lastError != null) {
            logger.warn("SAML signature verification failed for all certificates. Last error: {}", lastError.getMessage());
        }
        return false;
    }

    private boolean verifySignatureWithCert(Document doc, X509Certificate cert) throws Exception {
        NodeList signatureNodes = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (signatureNodes.getLength() == 0) {
            logger.warn("No signature found in SAML assertion");
            return false;
        }
        
        Element signatureElement = (Element) signatureNodes.item(0);
        
        // Create validation context with certificate
        DOMValidateContext valContext = new DOMValidateContext(cert.getPublicKey(), signatureElement);
        
        // Validate signature
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = factory.unmarshalXMLSignature(valContext);
        
        boolean valid = signature.validate(valContext);
        
        if (valid) {
            logger.info("SAML assertion signature is VALID");
        } else {
            logger.warn("SAML assertion signature is INVALID for cert {}", describeCert(cert));
        }
        
        return valid;
    }

    private String describeCert(X509Certificate cert) {
        if (cert == null) {
            return "unknown";
        }
        PublicKey key = cert.getPublicKey();
        if (key instanceof RSAPublicKey rsaKey) {
            return "RSA-" + rsaKey.getModulus().bitLength();
        }
        if (key instanceof ECPublicKey ecKey) {
            return "EC-" + ecKey.getParams().getCurve().getField().getFieldSize();
        }
        return key.getAlgorithm();
    }
    
    /**
     * Validates metadata URL to prevent SSRF attacks
     * Only allows HTTPS URLs and blocks private/internal IP addresses
     */
    private void validateMetadataUrl(String metadataUrl) throws Exception {
        URI uri = URI.create(metadataUrl);
        
        // Only allow HTTPS for metadata URLs unless explicitly allowed
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new SecurityException("Metadata URL must specify a protocol");
        }
        if (!scheme.equalsIgnoreCase("https")) {
            if (!(allowHttpMetadata && scheme.equalsIgnoreCase("http"))) {
                throw new SecurityException("Metadata URL must use HTTPS");
            }
        }
        
        // Get the host from the URL
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new SecurityException("Invalid metadata URL: no host specified");
        }
        
        // Resolve the host to IP address to check for private/internal IPs
        try {
            InetAddress addr = InetAddress.getByName(host);
            
            // Block private IP addresses (RFC 1918)
            if (addr.isSiteLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()) {
                throw new SecurityException("Metadata URL points to private/internal IP address");
            }
            
            // Block localhost variations
            if (host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1") || host.equals("::1")) {
                throw new SecurityException("Metadata URL cannot point to localhost");
            }
            
            // Block cloud metadata endpoints (AWS, GCP, Azure)
            if (host.equals("169.254.169.254") || host.equals("metadata.google.internal")) {
                throw new SecurityException("Metadata URL blocked for security reasons");
            }
            
            logger.debug("Metadata URL validation passed for: {} (resolved to {})", metadataUrl, addr.getHostAddress());
        } catch (java.net.UnknownHostException e) {
            throw new SecurityException("Cannot resolve metadata URL host: " + host, e);
        }
    }
    
    /**
     * Parses XML string to Document
     */
    private Document parseXML(String xml) throws Exception {
        return parseXML(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }
    
    /**
     * Parses XML from InputStream to Document
     * Security: Disables XXE (XML External Entity) attacks
     */
    private Document parseXML(InputStream is) throws Exception {
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
        return builder.parse(is);
    }

    private void markIdAttributes(Document doc) {
        NodeList elements = doc.getElementsByTagName("*");
        for (int i = 0; i < elements.getLength(); i++) {
            Element element = (Element) elements.item(i);
            if (element.hasAttribute("ID")) {
                element.setIdAttribute("ID", true);
            }
            if (element.hasAttribute("AssertionID")) {
                element.setIdAttribute("AssertionID", true);
            }
        }
    }
    




    private void putAttribute(Map<String, List<String>> attributes, String key, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        attributes.put(key, List.of(value));
    }



    private String extractSamlAttributeValueByAliases(Document doc, String... aliases) {
        List<String> values = extractSamlAttributeValuesByAliases(doc, aliases);
        if (values.isEmpty()) {
            return null;
        }
        return values.get(0);
    }

    private List<String> extractSamlAttributeValuesByAliases(Document doc, String... aliases) {
        if (aliases == null || aliases.length == 0) {
            return Collections.emptyList();
        }
        List<String> values = new ArrayList<>();
        List<String> normalizedAliases = new ArrayList<>();
        for (String alias : aliases) {
            String normalized = normalizeAttributeName(alias);
            if (!normalized.isEmpty()) {
                normalizedAliases.add(normalized);
            }
        }
        NodeList attributes = doc.getElementsByTagNameNS("*", "Attribute");
        for (int i = 0; i < attributes.getLength(); i++) {
            Element attribute = (Element) attributes.item(i);
            String name = normalizeAttributeName(attribute.getAttribute("Name"));
            String friendly = normalizeAttributeName(attribute.getAttribute("FriendlyName"));
            if (!matchesAlias(name, friendly, normalizedAliases)) {
                continue;
            }
            NodeList items = attribute.getElementsByTagNameNS("*", "AttributeValue");
            for (int j = 0; j < items.getLength(); j++) {
                String value = items.item(j).getTextContent();
                if (value != null && !value.isBlank()) {
                    values.add(value.trim());
                }
            }
        }
        return values;
    }

    private boolean matchesAlias(String name, String friendly, List<String> aliases) {
        String nameTail = extractAttributeTail(name);
        String friendlyTail = extractAttributeTail(friendly);
        for (String alias : aliases) {
            if (alias.equals(name) || alias.equals(friendly) || alias.equals(nameTail) || alias.equals(friendlyTail)) {
                return true;
            }
        }
        return false;
    }

    private String extractAttributeTail(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        int colon = value.lastIndexOf(':');
        int slash = value.lastIndexOf('/');
        int split = Math.max(colon, slash);
        if (split >= 0 && split + 1 < value.length()) {
            return value.substring(split + 1);
        }
        return value;
    }

    private String normalizeAttributeName(String name) {
        if (name == null) {
            return "";
        }
        return name.trim().toLowerCase();
    }
    
    /**
     * Clears certificate cache (useful for testing or forcing refresh)
     */
    public void clearCertificateCache() {
        certificateCache.clear();
        logger.info("Certificate cache cleared");
    }

    public boolean isConfigured() {
        if ("any".equalsIgnoreCase(trustMode)) {
            return true;
        }
        return trustedIdps != null && !trustedIdps.isEmpty();
    }
}

