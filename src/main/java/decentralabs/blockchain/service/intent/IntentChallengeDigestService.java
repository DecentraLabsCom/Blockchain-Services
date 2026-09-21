package decentralabs.blockchain.service.intent;

import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.util.PucHashUtil;
import decentralabs.blockchain.util.PucNormalizer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

/**
 * Builds the byte challenge consumed by the WebAuthn assertion ceremony.
 *
 * <p>The challenge is an EIP-712 digest, not an Ethereum signature. The
 * digest gives WebAuthn a fixed-size, domain-separated and unambiguous value
 * to sign while the normal intent signature remains responsible for the
 * on-chain authorization.</p>
 */
@Component
public class IntentChallengeDigestService {

    public static final String SCHEME = "eip712-webauthn-consent-v2";
    public static final String DOMAIN_NAME = "DecentraLabsWebAuthnConsent";
    public static final String DOMAIN_VERSION = "1";

    private static final String EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String CONSENT_TYPE =
        "WebAuthnIntentConsent(bytes32 requestId,address signer,address executor,uint8 action,"
            + "bytes32 payloadHash,uint256 nonce,uint64 requestedAt,uint64 expiresAt,"
            + "bytes32 pucHash,bytes32 institutionHash)";
    private static final byte[] EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE);
    private static final byte[] CONSENT_TYPEHASH = keccak256(CONSENT_TYPE);
    private static final Pattern BYTES32_PATTERN = Pattern.compile("(?i)^0x[0-9a-f]{64}$");
    private static final Pattern ADDRESS_PATTERN = Pattern.compile("(?i)^0x[0-9a-f]{40}$");
    private static final Pattern BASE64URL_PATTERN = Pattern.compile("^[A-Za-z0-9_-]+$");

    private final long chainId;
    private final String verifyingContract;

    public IntentChallengeDigestService(
        @Value("${intent.domain.chain-id:11155111}") long chainId,
        @Value("${intent.domain.verifying-contract}") String verifyingContract
    ) {
        if (chainId < 0) {
            throw new IllegalArgumentException("Invalid intent domain chainId");
        }
        this.chainId = chainId;
        this.verifyingContract = requireAddress(verifyingContract, "verifyingContract");
    }

    public Challenge build(IntentMeta meta, String puc, String institutionId) {
        if (meta == null) {
            throw new IllegalArgumentException("Missing intent meta");
        }

        byte[] requestId = bytes32(meta.getRequestId(), "requestId");
        String signer = address(meta.getSigner(), "signer");
        String executor = address(meta.getExecutor(), "executor");
        int action = requireAction(meta.getAction());
        byte[] payloadHash = bytes32(meta.getPayloadHash(), "payloadHash");
        long nonce = nonNegative(meta.getNonce(), "nonce");
        long requestedAt = nonNegative(meta.getRequestedAt(), "requestedAt");
        long expiresAt = nonNegative(meta.getExpiresAt(), "expiresAt");

        String normalizedPuc = requireText(PucNormalizer.normalize(puc), "puc");
        String normalizedInstitution = requireText(institutionId, "institutionId")
            .toLowerCase(Locale.ROOT);

        byte[] pucHash = bytes32(PucHashUtil.hashPuc(normalizedPuc), "pucHash");
        byte[] institutionHash = keccak256(normalizedInstitution);

        byte[] domainSeparator = hashEncoded(
            new Bytes32(EIP712_DOMAIN_TYPEHASH),
            new Bytes32(keccak256(DOMAIN_NAME)),
            new Bytes32(keccak256(DOMAIN_VERSION)),
            new Uint256(BigInteger.valueOf(chainId)),
            new Address(verifyingContract)
        );
        byte[] structHash = hashEncoded(
            new Bytes32(CONSENT_TYPEHASH),
            new Bytes32(requestId),
            new Address(signer),
            new Address(executor),
            new Uint8(action),
            new Bytes32(payloadHash),
            new Uint256(BigInteger.valueOf(nonce)),
            new Uint64(requestedAt),
            new Uint64(expiresAt),
            new Bytes32(pucHash),
            new Bytes32(institutionHash)
        );

        byte[] digestInput = new byte[2 + domainSeparator.length + structHash.length];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, domainSeparator.length);
        System.arraycopy(structHash, 0, digestInput, 2 + domainSeparator.length, structHash.length);
        byte[] digest = Hash.sha3(digestInput);
        String digestHex = Numeric.toHexString(digest);
        String challengeBase64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        return new Challenge(digest, digestHex, challengeBase64Url, SCHEME);
    }

    /**
     * Compares a persisted/client challenge with the expected digest. The
     * value must be the canonical unpadded Base64URL encoding of 32 bytes.
     */
    public boolean matches(Challenge expected, String candidateBase64Url) {
        if (expected == null || !isCanonicalBase64Url(candidateBase64Url)) {
            return false;
        }
        try {
            byte[] candidate = Base64.getUrlDecoder().decode(candidateBase64Url);
            return candidate.length == 32
                && candidateBase64Url.equals(Base64.getUrlEncoder().withoutPadding().encodeToString(candidate))
                && MessageDigest.isEqual(expected.digest(), candidate);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static boolean isCanonicalBase64Url(String value) {
        return value != null
            && !value.isBlank()
            && value.indexOf('=') < 0
            && value.length() % 4 != 1
            && BASE64URL_PATTERN.matcher(value).matches();
    }

    private static byte[] hashEncoded(Type<?>... types) {
        StringBuilder encoded = new StringBuilder();
        for (Type<?> type : types) {
            encoded.append(TypeEncoder.encode(type));
        }
        return Hash.sha3(Numeric.hexStringToByteArray(encoded.toString()));
    }

    private static byte[] bytes32(String value, String name) {
        if (value == null || !BYTES32_PATTERN.matcher(value.trim()).matches()) {
            throw new IllegalArgumentException("Invalid " + name);
        }
        return Numeric.hexStringToByteArray(value.trim());
    }

    private static String address(String value, String name) {
        return requireAddress(value, name);
    }

    private static String requireAddress(String value, String name) {
        if (value == null || !ADDRESS_PATTERN.matcher(value.trim()).matches()) {
            throw new IllegalArgumentException("Invalid " + name);
        }
        return "0x" + Numeric.cleanHexPrefix(value.trim()).toLowerCase(Locale.ROOT);
    }

    private static int requireAction(Integer action) {
        if (action == null || action < 0 || action > 255) {
            throw new IllegalArgumentException("Invalid action");
        }
        return action;
    }

    private static long nonNegative(Long value, String name) {
        if (value == null || value < 0) {
            throw new IllegalArgumentException("Invalid " + name);
        }
        return value;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing " + name);
        }
        return value.trim();
    }

    private static byte[] keccak256(String value) {
        return Hash.sha3(value.getBytes(StandardCharsets.UTF_8));
    }

    public record Challenge(
        byte[] digest,
        String digestHex,
        String challengeBase64Url,
        String scheme
    ) {
        public Challenge {
            digest = digest == null ? null : Arrays.copyOf(digest, digest.length);
        }

        @Override
        public byte[] digest() {
            return digest == null ? null : Arrays.copyOf(digest, digest.length);
        }
    }
}
