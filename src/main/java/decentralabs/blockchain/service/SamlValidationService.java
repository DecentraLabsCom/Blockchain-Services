package decentralabs.blockchain.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
    
    @Value("${saml.idp.metadata.url:}")
    private String idpMetadataUrl;
    
    @Value("${saml.idp.cert.path:}")
    private String idpCertPath;
    
    @Value("${saml.idp.trust-mode:whitelist}")
    private String trustMode;
    
    @Value("#{${saml.trusted.idp}}")
    private Map<String, String> trustedIdps;
    
    // Cache for IdP certificates (issuer -> certificate)
    private final Map<String, X509Certificate> certificateCache = new ConcurrentHashMap<>();
    
    /**
     * Validates SAML assertion with signature verification and extracts attributes
     * Automatically discovers IdP metadata and retrieves certificate
     * 
     * @param samlAssertion Base64-encoded SAML assertion XML
     * @return Map of SAML attributes (userid, affiliation, etc.)
     * @throws Exception if validation fails or signature is invalid
     */
    public Map<String, String> validateSamlAssertionWithSignature(String samlAssertion) throws Exception {
        // Decode Base64
        byte[] decodedBytes = Base64.getDecoder().decode(samlAssertion);
        String xmlContent = new String(decodedBytes);
        
        // Parse XML
        Document doc = parseXML(xmlContent);
        
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
        
        // Try to get metadata URL from assertion (SAML2 extension)
        String metadataUrl = extractMetadataUrl(doc);
        if (metadataUrl == null) {
            // Fallback: construct standard metadata URL from issuer
            metadataUrl = issuer + (issuer.endsWith("/") ? "" : "/") + "metadata";
            logger.debug("No metadata URL in assertion, using constructed URL: {}", metadataUrl);
        }
        
        // Get or retrieve certificate
        X509Certificate cert = getIdpCertificate(issuer, metadataUrl);
        if (cert == null) {
            throw new SecurityException("Could not retrieve certificate for IdP: " + issuer);
        }
        
        // Verify signature
        boolean signatureValid = verifySignature(doc, cert);
        if (!signatureValid) {
            throw new SecurityException("SAML assertion signature is INVALID");
        }
        
        // Extract attributes after signature validation
        String userid = extractSAMLAttribute(doc, "userid");
        String affiliation = extractSAMLAttribute(doc, "affiliation");
        
        if (userid == null || userid.isEmpty()) {
            throw new SecurityException("SAML assertion missing 'userid' attribute");
        }
        if (affiliation == null || affiliation.isEmpty()) {
            throw new SecurityException("SAML assertion missing 'affiliation' attribute");
        }
        
        logger.info("✅ SAML assertion validated WITH SIGNATURE for user: {}", userid);
        
        return Map.of(
            "userid", userid,
            "affiliation", affiliation
        );
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
    private X509Certificate getIdpCertificate(String issuer, String metadataUrl) {
        // Check cache first
        if (certificateCache.containsKey(issuer)) {
            logger.debug("Using cached certificate for IdP: {}", issuer);
            return certificateCache.get(issuer);
        }
        
        // Try to load from configured path (if specified)
        if (idpCertPath != null && !idpCertPath.isEmpty()) {
            try {
                X509Certificate cert = loadCertificateFromFile(idpCertPath);
                certificateCache.put(issuer, cert);
                logger.info("Loaded certificate from configured path for IdP: {}", issuer);
                return cert;
            } catch (Exception e) {
                logger.warn("Could not load certificate from path: {}", idpCertPath, e);
            }
        }
        
        // Try to retrieve from metadata URL
        try {
            X509Certificate cert = retrieveCertificateFromMetadata(metadataUrl);
            if (cert != null) {
                certificateCache.put(issuer, cert);
                logger.info("Retrieved and cached certificate from metadata for IdP: {}", issuer);
                return cert;
            }
        } catch (Exception e) {
            logger.warn("Could not retrieve certificate from metadata URL: {}", metadataUrl, e);
        }
        
        return null;
    }
    
    /**
     * Retrieves certificate from IdP metadata endpoint
     */
    private X509Certificate retrieveCertificateFromMetadata(String metadataUrl) throws Exception {
        logger.debug("Retrieving certificate from metadata: {}", metadataUrl);
        
        URL url = new URL(metadataUrl);
        Document metadataDoc = parseXML(url.openStream());
        
        // Find X509Certificate element in metadata
        NodeList certNodes = metadataDoc.getElementsByTagNameNS("*", "X509Certificate");
        if (certNodes.getLength() == 0) {
            logger.warn("No X509Certificate found in metadata");
            return null;
        }
        
        // Get first signing certificate
        for (int i = 0; i < certNodes.getLength(); i++) {
            Node certNode = certNodes.item(i);
            
            // Check if this is a signing certificate
            Node keyDescriptor = certNode.getParentNode().getParentNode();
            if (keyDescriptor.getNodeName().contains("KeyDescriptor")) {
                Element keyDesc = (Element) keyDescriptor;
                String use = keyDesc.getAttribute("use");
                if (use.isEmpty() || "signing".equals(use)) {
                    String certData = certNode.getTextContent().trim();
                    return parseCertificate(certData);
                }
            }
        }
        
        // If no signing cert found, use first cert
        String certData = certNodes.item(0).getTextContent().trim();
        return parseCertificate(certData);
    }
    
    /**
     * Loads certificate from file
     */
    private X509Certificate loadCertificateFromFile(String path) throws Exception {
        try (InputStream is = new java.io.FileInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);
        }
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
    private boolean verifySignature(Document doc, X509Certificate cert) throws Exception {
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
            logger.warn("SAML assertion signature is INVALID");
        }
        
        return valid;
    }
    
    /**
     * Parses XML string to Document
     */
    private Document parseXML(String xml) throws Exception {
        return parseXML(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }
    
    /**
     * Parses XML from InputStream to Document
     */
    private Document parseXML(InputStream is) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(is);
    }
    
    /**
     * Extracts a SAML attribute value from the XML document
     */
    private String extractSAMLAttribute(Document doc, String attributeName) {
        try {
            NodeList attributes = doc.getElementsByTagNameNS("*", "Attribute");
            for (int i = 0; i < attributes.getLength(); i++) {
                Element attribute = (Element) attributes.item(i);
                String name = attribute.getAttribute("Name");
                
                if (name != null && name.equals(attributeName)) {
                    NodeList values = attribute.getElementsByTagNameNS("*", "AttributeValue");
                    if (values.getLength() > 0) {
                        return values.item(0).getTextContent();
                    }
                }
            }
            return null;
        } catch (Exception e) {
            logger.error("Error extracting SAML attribute '" + attributeName + "'", e);
            return null;
        }
    }
    
    /**
     * Clears certificate cache (useful for testing or forcing refresh)
     */
    public void clearCertificateCache() {
        certificateCache.clear();
        logger.info("Certificate cache cleared");
    }
}
