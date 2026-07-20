package decentralabs.blockchain.service.auth;

import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.logging.HttpLoggingInterceptor;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
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
import java.security.MessageDigest;
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

    @Value("${saml.metadata.certificate-cache-ms:300000}")
    private long metadataCertificateCacheMs = 300_000L;
    
    // Optional: only used in whitelist mode
    private Map<String, String> trustedIdps = Collections.emptyMap();
    private Map<String, String> metadataOverrides = Collections.emptyMap();
    private Map<String, String> metadataTlsProfiles = Collections.emptyMap();

    private volatile List<String> configurationErrors = List.of();
    private volatile MetadataHealthSnapshot metadataHealthSnapshot;
    private final Object metadataHealthLock = new Object();

    @FunctionalInterface
    public interface MetadataDownloader {
        List<X509Certificate> download(String metadataUrl, String tlsProfile) throws Exception;
    }

    private MetadataDownloader metadataDownloader = (metadataUrl, tlsProfile) -> {
        String metadataXml = downloadMetadataXml(metadataUrl, tlsProfile);
        return parseCertificatesFromMetadataXml(metadataXml);
    };
    
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

    @Autowired(required = false)
    public void setMetadataTlsProfiles(@Value("#{${saml.idp.metadata.tls-profile:{}}}") Map<String, String> metadataTlsProfiles) {
        if (metadataTlsProfiles != null) {
            this.metadataTlsProfiles = metadataTlsProfiles;
        }
    }
    
    // Cache for IdP certificates (issuer -> certificates)
    private static final int MAX_CERTIFICATE_CACHE_SIZE = 500;
    private final Map<String, List<X509Certificate>> certificateCache = new ConcurrentHashMap<>();
    private final Map<String, CertificateCacheEntry> certificateSnapshots = new ConcurrentHashMap<>();
    
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
        if ("whitelist".equalsIgnoreCase(trustMode) && (metadataUrl == null || metadataUrl.isBlank())) {
            throw new SecurityException("Whitelisted IdP requires an issuer-specific metadata URL: " + issuer);
        }
        List<X509Certificate> certs = getIdpCertificates(issuer, metadataUrl, false);
        if (certs.isEmpty()) {
            if (metadataUrl == null) {
                throw new SecurityException("No metadata URL found for IdP: " + issuer);
            }
            throw new SecurityException("Could not retrieve certificate for IdP: " + issuer);
        }
        
        // Verify signature
        boolean signatureValid = verifySignature(doc, certs);
        if (!signatureValid) {
            // IdPs commonly publish the replacement signing certificate before
            // they start using it.  Evict the issuer snapshot and perform one,
            // and only one, refresh for this assertion.
            evictCertificateCache(issuer);
            List<X509Certificate> refreshedCerts = getIdpCertificates(issuer, metadataUrl, true);
            if (refreshedCerts.isEmpty() || !verifySignature(doc, refreshedCerts)) {
                throw new SecurityException("SAML assertion signature is INVALID");
            }
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

        logger.info("SAML assertion validated WITH SIGNATURE for pucHash={}", PucHashUtil.hashPuc(puc));

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
        String override = findIssuerValue(metadataOverrides, issuer);
        if (override != null && !override.isBlank()) {
            logger.info("Using metadata URL override for issuer {}", issuer);
            return override.trim();
        }
        if ("whitelist".equalsIgnoreCase(trustMode)) {
            return null;
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
                .anyMatch(trustedIssuer -> normalizeIssuer(issuer).equals(normalizeIssuer(trustedIssuer)));
    }
    
    /**
     * Gets the current IdP certificate snapshot.  Authentication and the
     * metadata readiness worker both publish through this method so a health
     * check cannot be green while authentication is still pinned to K1.
     */
    private List<X509Certificate> getIdpCertificates(String issuer, String metadataUrl, boolean forceRefresh) {
        String cacheKey = normalizeIssuer(issuer);
        CertificateCacheEntry snapshot = certificateSnapshots.get(cacheKey);
        long now = System.currentTimeMillis();
        if (!forceRefresh && snapshot != null
                && sameMetadataUrl(snapshot.metadataUrl(), metadataUrl)
                && now - snapshot.fetchedAt() < Math.max(0L, metadataCertificateCacheMs)) {
            logger.debug("Using cached SAML certificate snapshot for IdP: {} fingerprints={}", cacheKey, snapshot.fingerprints());
            return snapshot.certificates();
        }

        // Keep compatibility with unit/integration fixtures that seed the
        // certificate cache directly. Production entries always have a
        // timestamped CertificateCacheEntry published alongside this map.
        if (!forceRefresh && snapshot == null && certificateCache.containsKey(cacheKey)) {
            return certificateCache.get(cacheKey);
        }

        if (metadataUrl == null || metadataUrl.isBlank()) {
            return Collections.emptyList();
        }

        try {
            List<X509Certificate> certs = retrieveCertificatesFromMetadata(metadataUrl, issuer);
            if (!certs.isEmpty()) {
                putCertificateSnapshot(cacheKey, metadataUrl, certs, now);
                logger.info("Retrieved and cached SAML certificate snapshot for IdP {} fingerprints={}",
                        cacheKey, certificateFingerprints(certs));
                return certs;
            }
        } catch (Exception e) {
            logger.warn("Could not retrieve certificate from metadata URL: {}", metadataUrl, e);
        }

        return Collections.emptyList();
    }

    private void putCertificateSnapshot(
            String issuer,
            String metadataUrl,
            List<X509Certificate> certificates,
            long fetchedAt) {
        if (certificateCache.size() >= MAX_CERTIFICATE_CACHE_SIZE && !certificateCache.containsKey(issuer)) {
            logger.warn("Certificate cache reached max size ({}), evicting oldest entries", MAX_CERTIFICATE_CACHE_SIZE);
            var iterator = certificateCache.keySet().iterator();
            int toRemove = Math.max(1, certificateCache.size() / 4);
            for (int i = 0; i < toRemove && iterator.hasNext(); i++) {
                String evictedIssuer = iterator.next();
                iterator.remove();
                certificateSnapshots.remove(evictedIssuer);
            }
        }
        List<X509Certificate> immutableCertificates = List.copyOf(certificates);
        certificateCache.put(issuer, immutableCertificates);
        certificateSnapshots.put(
                issuer,
                new CertificateCacheEntry(
                        normalizeMetadataUrl(metadataUrl),
                        immutableCertificates,
                        certificateFingerprints(immutableCertificates),
                        fetchedAt
                )
        );
    }

    private void evictCertificateCache(String issuer) {
        String cacheKey = normalizeIssuer(issuer);
        certificateCache.remove(cacheKey);
        certificateSnapshots.remove(cacheKey);
    }

    private boolean sameMetadataUrl(String left, String right) {
        return normalizeMetadataUrl(left).equals(normalizeMetadataUrl(right));
    }

    private String normalizeMetadataUrl(String url) {
        return url == null ? "" : url.trim();
    }

    private List<String> certificateFingerprints(List<X509Certificate> certificates) {
        List<String> fingerprints = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            try {
                if (certificate == null) {
                    continue;
                }
                byte[] encoded = certificate.getEncoded();
                if (encoded == null || encoded.length == 0) {
                    continue;
                }
                fingerprints.add(Base64.getUrlEncoder().withoutPadding().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(encoded)
                ));
            } catch (Exception ex) {
                logger.warn("Unable to fingerprint SAML certificate", ex);
            }
        }
        return List.copyOf(fingerprints);
    }
    
    private List<X509Certificate> retrieveCertificatesFromMetadata(String metadataUrl, String issuer) throws Exception {
        logger.debug("Retrieving certificate from metadata: {}", metadataUrl);
        
        return metadataDownloader.download(metadataUrl, resolveMetadataTlsProfile(issuer));
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

    private String downloadMetadataXml(String metadataUrl, String tlsProfile) throws Exception {
        String currentUrl = metadataUrl;
        for (int redirect = 0; redirect <= 5; redirect++) {
            ValidatedMetadataUrl validated = validateMetadataUrl(currentUrl);
            Request request = new Request.Builder()
                .url(currentUrl)
                .get()
                .header("Accept", "application/samlmetadata+xml, application/xml, text/xml;q=0.9,*/*;q=0.8")
                .header("User-Agent", "DecentraLabs-Blockchain-Services/1.0")
                .build();

            try (Response response = buildMetadataHttpClient(tlsProfile, Map.of(
                    validated.host(), validated.addresses()
            )).newCall(request).execute()) {
                if (response.isRedirect()) {
                    String location = response.header("Location");
                    if (location == null || location.isBlank()) {
                        throw new IOException("Metadata redirect did not include a Location header");
                    }
                    currentUrl = validated.uri().resolve(location).toString();
                    continue;
                }
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
        throw new IOException("Metadata request exceeded the redirect limit");
    }

    private OkHttpClient buildMetadataHttpClient(String tlsProfile, Map<String, List<InetAddress>> pinnedAddresses) {
        ConnectionSpec connectionSpec = "compatibility".equalsIgnoreCase(tlsProfile)
            ? ConnectionSpec.COMPATIBLE_TLS
            : ConnectionSpec.MODERN_TLS;
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
            .connectTimeout(metadataHttpConnectTimeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(metadataHttpReadTimeoutMs, TimeUnit.MILLISECONDS)
            .callTimeout(metadataHttpCallTimeoutMs, TimeUnit.MILLISECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .dns(host -> {
                List<InetAddress> addresses = pinnedAddresses.get(host.toLowerCase(Locale.ROOT));
                if (addresses == null || addresses.isEmpty()) {
                    throw new java.net.UnknownHostException("Metadata host was not pinned: " + host);
                }
                return addresses;
            })
            .connectionSpecs(List.of(connectionSpec));

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
        if (key == null) {
            return "unknown";
        }
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
    private ValidatedMetadataUrl validateMetadataUrl(String metadataUrl) throws Exception {
        URI uri = URI.create(metadataUrl.trim());
        
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
        if (uri.getRawUserInfo() != null || uri.getFragment() != null) {
            throw new SecurityException("Metadata URL must not contain credentials or a fragment");
        }

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if (normalizedHost.equals("localhost")
                || normalizedHost.endsWith(".local")
                || normalizedHost.endsWith(".internal")
                || normalizedHost.equals("127.0.0.1")
                || normalizedHost.equals("::1")
                || normalizedHost.equals("[::1]")
                || normalizedHost.equals("169.254.169.254")
                || normalizedHost.equals("metadata.google.internal")) {
            throw new SecurityException("Metadata URL points to a private/internal host");
        }
        
        try {
            List<InetAddress> addresses = List.of(InetAddress.getAllByName(host));
            if (addresses.isEmpty()) {
                throw new SecurityException("Metadata URL host did not resolve to an address");
            }
            for (InetAddress address : addresses) {
                if (isNonPublicAddress(address)) {
                    throw new SecurityException("Metadata URL points to a private/internal IP address");
                }
            }

            logger.debug("Metadata URL validation passed for: {} (resolved to {})", metadataUrl, addresses);
            return new ValidatedMetadataUrl(uri, normalizedHost, addresses);
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

    @PostConstruct
    void validateConfigurationAtStartup() {
        List<String> errors = collectConfigurationErrors();
        configurationErrors = List.copyOf(errors);
        if (!errors.isEmpty()) {
            throw new IllegalStateException("Invalid SAML configuration: " + String.join("; ", errors));
        }
        logger.info("SAML validation configuration is valid (trust-mode={})", trustMode);
    }

    public List<String> configurationErrors() {
        List<String> errors = collectConfigurationErrors();
        configurationErrors = List.copyOf(errors);
        return configurationErrors;
    }

    private List<String> collectConfigurationErrors() {
        List<String> errors = new ArrayList<>();
        String normalizedTrustMode = trustMode == null ? "" : trustMode.trim().toLowerCase(Locale.ROOT);
        if (!"any".equals(normalizedTrustMode) && !"whitelist".equals(normalizedTrustMode)) {
            errors.add("saml.idp.trust-mode must be 'any' or 'whitelist'");
        }

        if (metadataUrlOverride != null && !metadataUrlOverride.isBlank()) {
            addMetadataUrlSyntaxError(errors, "global metadata override", metadataUrlOverride);
        }

        if (metadataOverrides != null) {
            metadataOverrides.forEach((issuer, url) -> {
                if (issuer == null || issuer.isBlank()) {
                    errors.add("metadata override issuer must not be blank");
                }
                if (url == null || url.isBlank()) {
                    errors.add("metadata override for issuer " + issuer + " must not be blank");
                } else {
                    addMetadataUrlSyntaxError(errors, "metadata override for issuer " + issuer, url);
                }
            });
        }

        if (metadataTlsProfiles != null) {
            metadataTlsProfiles.forEach((issuer, profile) -> {
                String normalizedProfile = profile == null ? "" : profile.trim().toLowerCase(Locale.ROOT);
                if (!"modern".equals(normalizedProfile) && !"compatibility".equals(normalizedProfile)) {
                    errors.add("unsupported TLS profile '" + profile + "' for issuer " + issuer
                        + "; use 'modern' or 'compatibility'");
                }
            });
        }

        if ("whitelist".equals(normalizedTrustMode)) {
            if (trustedIdps == null || trustedIdps.isEmpty()) {
                errors.add("whitelist mode requires at least one trusted IdP issuer");
            } else {
                trustedIdps.values().forEach(issuer -> {
                    if (issuer == null || issuer.isBlank()) {
                        errors.add("trusted IdP issuer must not be blank");
                        return;
                    }
                    String metadataUrl = findIssuerValue(metadataOverrides, issuer);
                    if (metadataUrl == null || metadataUrl.isBlank()) {
                        errors.add("whitelisted issuer " + issuer + " requires an issuer-specific metadata override");
                    }
                });
            }
        }

        return errors;
    }

    private void addMetadataUrlSyntaxError(List<String> errors, String label, String rawUrl) {
        try {
            URI uri = URI.create(rawUrl.trim());
            String scheme = uri.getScheme();
            if (scheme == null || uri.getHost() == null || uri.getHost().isBlank()) {
                errors.add(label + " must be an absolute URL with a host");
                return;
            }
            if (!"https".equalsIgnoreCase(scheme)
                && !(allowHttpMetadata && "http".equalsIgnoreCase(scheme))) {
                errors.add(label + " must use HTTPS");
            }
        } catch (IllegalArgumentException ex) {
            errors.add(label + " is not a valid URL");
        }
    }

    private String findIssuerValue(Map<String, String> values, String issuer) {
        if (values == null || issuer == null) {
            return null;
        }
        String exact = values.get(issuer);
        if (exact != null) {
            return exact;
        }
        String normalizedIssuer = normalizeIssuer(issuer);
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (normalizedIssuer.equals(normalizeIssuer(entry.getKey()))) {
                return entry.getValue();
            }
        }
        return null;
    }

    private String normalizeIssuer(String issuer) {
        if (issuer == null) {
            return "";
        }
        return issuer.trim().replaceAll("/+$", "");
    }

    private String resolveMetadataTlsProfile(String issuer) {
        String configured = findIssuerValue(metadataTlsProfiles, issuer);
        if (configured == null || configured.isBlank()) {
            return "modern";
        }
        return configured.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Refreshes every configured IdP in the background. Readiness only reads
     * the resulting snapshot; it never performs a network call on the health
     * request path.
     */
    @Scheduled(
        fixedDelayString = "${saml.metadata.refresh.interval-ms:30000}",
        initialDelayString = "${saml.metadata.refresh.initial-delay-ms:0}"
    )
    public void refreshMetadataSnapshotsNow() {
        List<String> errors = configurationErrors();
        if (!errors.isEmpty()) {
            metadataHealthSnapshot = new MetadataHealthSnapshot(
                    System.currentTimeMillis(),
                    metadataHealthDetails("DOWN", errors, List.of(), List.of())
            );
            return;
        }

        if (!"whitelist".equalsIgnoreCase(trustMode)) {
            metadataHealthSnapshot = new MetadataHealthSnapshot(
                    System.currentTimeMillis(),
                    metadataHealthDetails("UP", List.of(), List.of(), List.of())
            );
            return;
        }

        synchronized (metadataHealthLock) {
            long now = System.currentTimeMillis();
            List<String> checkedIssuers = new ArrayList<>();
            List<String> failedIssuers = new ArrayList<>();
            Map<String, List<String>> fingerprints = new LinkedHashMap<>();
            for (String issuer : new LinkedHashSet<>(trustedIdps.values())) {
                checkedIssuers.add(issuer);
                String metadataUrl = findIssuerValue(metadataOverrides, issuer);
                try {
                    List<X509Certificate> certificates = retrieveCertificatesFromMetadata(metadataUrl, issuer);
                    if (certificates == null || certificates.isEmpty()) {
                        failedIssuers.add(issuer);
                    } else {
                        putCertificateSnapshot(normalizeIssuer(issuer), metadataUrl, certificates, now);
                        fingerprints.put(issuer, certificateFingerprints(certificates));
                    }
                } catch (Exception ex) {
                    failedIssuers.add(issuer);
                    logger.warn("SAML metadata refresh failed for issuer {}: {}", issuer, ex.getMessage());
                }
            }

            String status;
            if (failedIssuers.isEmpty()) {
                status = "UP";
            } else if (failedIssuers.size() == checkedIssuers.size()) {
                status = "DOWN";
            } else {
                status = "DEGRADED";
            }
            Map<String, Object> details = metadataHealthDetails(status, List.of(), checkedIssuers, failedIssuers);
            details = new LinkedHashMap<>(details);
            details.put("certificateFingerprints", Map.copyOf(fingerprints));
            metadataHealthSnapshot = new MetadataHealthSnapshot(now, Map.copyOf(details));
        }
    }

    private boolean isNonPublicAddress(InetAddress address) {
        if (address == null || address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            return isNonPublicIpv4(bytes);
        }
        if (bytes.length != 16 || isIpv4Mapped(bytes)) {
            return true;
        }
        int first = unsignedByte(bytes[0]);
        if ((first & 0xe0) != 0x20) {
            return true;
        }
        return hasPrefix(bytes, new int[] {0x20, 0x01, 0x0d, 0xb8}, 32)
                || hasPrefix(bytes, new int[] {0xfc}, 7);
    }

    private boolean isNonPublicIpv4(byte[] bytes) {
        int a = unsignedByte(bytes[0]);
        int b = unsignedByte(bytes[1]);
        int c = unsignedByte(bytes[2]);
        return a == 0 || a == 10 || a == 127 || a >= 224
                || (a == 100 && b >= 64 && b <= 127)
                || (a == 169 && b == 254)
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 31 && c == 196)
                || (a == 192 && b == 52 && c == 193)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 175 && c == 48)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113);
    }

    private boolean isIpv4Mapped(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) return false;
        }
        return unsignedByte(bytes[10]) == 0xff && unsignedByte(bytes[11]) == 0xff;
    }

    private boolean hasPrefix(byte[] address, int[] prefix, int bits) {
        int fullBytes = bits / 8;
        int remainingBits = bits % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (unsignedByte(address[i]) != prefix[i]) return false;
        }
        if (remainingBits == 0) return true;
        int mask = 0xff << (8 - remainingBits);
        return (unsignedByte(address[fullBytes]) & mask) == (prefix[fullBytes] & mask);
    }

    private int unsignedByte(byte value) {
        return value & 0xff;
    }

    public Map<String, Object> metadataHealth() {
        List<String> errors = configurationErrors();
        if (!errors.isEmpty()) {
            return metadataHealthDetails("DOWN", errors, List.of(), List.of());
        }

        if (!"whitelist".equalsIgnoreCase(trustMode)) {
            return metadataHealthDetails("UP", List.of(), List.of(), List.of());
        }

        MetadataHealthSnapshot snapshot = metadataHealthSnapshot;
        if (snapshot == null) {
            return metadataHealthDetails("DOWN", List.of("SAML metadata snapshot is not ready"), List.of(), List.of());
        }
        return snapshot.details();
    }

    private Map<String, Object> metadataHealthDetails(
        String status,
        List<String> errors,
        List<String> checkedIssuers,
        List<String> failedIssuers
    ) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("status", status);
        details.put("trustMode", trustMode == null ? "" : trustMode);
        details.put("checkedIssuers", List.copyOf(checkedIssuers));
        details.put("failedIssuers", List.copyOf(failedIssuers));
        if (!errors.isEmpty()) {
            details.put("configurationErrors", List.copyOf(errors));
        }
        return Map.copyOf(details);
    }

    private record MetadataHealthSnapshot(long checkedAt, Map<String, Object> details) {}

    private record CertificateCacheEntry(
            String metadataUrl,
            List<X509Certificate> certificates,
            List<String> fingerprints,
            long fetchedAt
    ) {}

    private record ValidatedMetadataUrl(
            URI uri,
            String host,
            List<InetAddress> addresses
    ) {}
    
    /**
     * Clears certificate cache (useful for testing or forcing refresh)
     */
    public void clearCertificateCache() {
        certificateCache.clear();
        certificateSnapshots.clear();
        logger.info("Certificate cache cleared");
    }

    public boolean isConfigured() {
        return configurationErrors().isEmpty();
    }
}

