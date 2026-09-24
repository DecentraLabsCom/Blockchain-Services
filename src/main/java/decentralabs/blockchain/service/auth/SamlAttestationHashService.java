package decentralabs.blockchain.service.auth;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.springframework.stereotype.Component;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Computes the versioned hash of the bytes produced by a validated SAML
 * XMLDSig reference. The complete assertion and canonical bytes never leave
 * this in-memory boundary.
 */
@Component
public class SamlAttestationHashService {

    public static final String HASH_VERSION = "saml-assertion-c14n-keccak-v2";
    private static final String HASH_DOMAIN_VALUE = "DecentraLabs/SAML-Assertion/v2";
    private static final byte[] HASH_DOMAIN = HASH_DOMAIN_VALUE.getBytes(StandardCharsets.UTF_8);
    private static final String XML_SIGNATURE_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

    static {
        Init.init();
    }

    /**
     * Replays the safe SAML Reference transform profile over the already
     * validated Assertion and binds the result to XMLDSig's calculated digest.
     */
    public String hashValidatedReference(Reference reference, Element assertion) {
        if (reference == null) {
            throw new IllegalArgumentException("Validated SAML reference is required");
        }
        if (assertion == null) {
            throw new IllegalArgumentException("Validated SAML assertion is required");
        }

        byte[] canonicalBytes = canonicalizeValidatedReference(reference, assertion);
        verifyReferenceDigest(reference, canonicalBytes);
        return hashCanonicalSignedAssertion(canonicalBytes);
    }

    public String hashCanonicalSignedAssertion(byte[] canonicalSignedAssertionBytes) {
        if (canonicalSignedAssertionBytes == null || canonicalSignedAssertionBytes.length == 0) {
            throw new IllegalArgumentException("Canonical signed assertion bytes are required");
        }

        byte[] input = new byte[HASH_DOMAIN.length + 1 + canonicalSignedAssertionBytes.length];
        System.arraycopy(HASH_DOMAIN, 0, input, 0, HASH_DOMAIN.length);
        input[HASH_DOMAIN.length] = 0;
        System.arraycopy(canonicalSignedAssertionBytes, 0, input, HASH_DOMAIN.length + 1,
            canonicalSignedAssertionBytes.length);
        return Numeric.toHexString(Hash.sha3(input));
    }

    private byte[] canonicalizeValidatedReference(Reference reference, Element assertion) {
        String canonicalizationAlgorithm = null;
        String inclusiveNamespaces = null;
        boolean envelopedSignature = false;
        boolean canonicalizationSeen = false;

        List<Transform> transforms = reference.getTransforms();
        for (Transform transform : transforms) {
            String algorithm = transform.getAlgorithm();
            if (Transform.ENVELOPED.equals(algorithm)) {
                if (canonicalizationSeen) {
                    throw new IllegalArgumentException("Enveloped XMLDSig transform must precede canonicalization");
                }
                envelopedSignature = true;
                continue;
            }
            if (!isSupportedCanonicalization(algorithm)) {
                throw new IllegalArgumentException("Unsupported SAML Reference transform: " + algorithm);
            }
            if (canonicalizationAlgorithm != null) {
                throw new IllegalArgumentException("SAML Reference contains multiple canonicalization transforms");
            }
            canonicalizationAlgorithm = algorithm;
            canonicalizationSeen = true;
            inclusiveNamespaces = inclusiveNamespaces(transform);
        }

        if (canonicalizationAlgorithm == null) {
            canonicalizationAlgorithm = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
        }

        Element assertionCopy = cloneWithAncestorContext(assertion);
        if (envelopedSignature) {
            removeDirectSignature(assertionCopy);
        }

        try {
            Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationAlgorithm);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            if (inclusiveNamespaces == null || inclusiveNamespaces.isBlank()) {
                canonicalizer.canonicalizeSubtree(assertionCopy, output);
            } else {
                canonicalizer.canonicalizeSubtree(assertionCopy, inclusiveNamespaces, output);
            }
            return output.toByteArray();
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to canonicalize validated SAML Reference", ex);
        }
    }

    private Element cloneWithAncestorContext(Element assertion) {
        Document documentCopy = (Document) assertion.getOwnerDocument().cloneNode(true);
        List<Integer> childIndexes = new ArrayList<>();
        Node current = assertion;
        while (current.getParentNode() != null) {
            Node parent = current.getParentNode();
            int childIndex = 0;
            for (Node child = parent.getFirstChild(); child != current; child = child.getNextSibling()) {
                childIndex++;
            }
            childIndexes.add(0, childIndex);
            current = parent;
        }

        Node copy = documentCopy;
        for (int childIndex : childIndexes) {
            copy = copy.getChildNodes().item(childIndex);
        }
        return (Element) copy;
    }

    private void removeDirectSignature(Element assertion) {
        for (Node child = assertion.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (XML_SIGNATURE_NAMESPACE.equals(child.getNamespaceURI())
                    && "Signature".equals(child.getLocalName())) {
                assertion.removeChild(child);
                return;
            }
        }
        throw new IllegalArgumentException("Enveloped SAML Reference has no direct XML Signature");
    }

    private boolean isSupportedCanonicalization(String algorithm) {
        return Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS.equals(algorithm)
                || Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS.equals(algorithm)
                || Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS.equals(algorithm)
                || Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS.equals(algorithm)
                || Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS.equals(algorithm)
                || Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS.equals(algorithm);
    }

    private String inclusiveNamespaces(Transform transform) {
        if (transform.getParameterSpec() instanceof ExcC14NParameterSpec parameters) {
            return String.join(" ", parameters.getPrefixList());
        }
        return null;
    }

    private void verifyReferenceDigest(Reference reference, byte[] canonicalBytes) {
        String digestAlgorithm = resolveDigestAlgorithm(reference);
        byte[] calculatedDigest = reference.getCalculatedDigestValue();
        if (calculatedDigest == null) {
            throw new IllegalArgumentException("Validated SAML Reference has no calculated digest");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
            byte[] reconstructedDigest = digest.digest(canonicalBytes);
            if (!MessageDigest.isEqual(calculatedDigest, reconstructedDigest)) {
                throw new IllegalArgumentException("SAML Reference canonicalization does not match XMLDSig digest");
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("Unsupported SAML Reference digest algorithm", ex);
        }
    }

    private String resolveDigestAlgorithm(Reference reference) {
        return switch (reference.getDigestMethod().getAlgorithm()) {
            case DigestMethod.SHA256 -> "SHA-256";
            case DigestMethod.SHA384 -> "SHA-384";
            case DigestMethod.SHA512 -> "SHA-512";
            default -> throw new IllegalArgumentException(
                "Unsupported SAML Reference digest algorithm: " + reference.getDigestMethod().getAlgorithm()
            );
        };
    }
}
