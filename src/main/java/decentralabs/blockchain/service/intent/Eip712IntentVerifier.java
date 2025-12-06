package decentralabs.blockchain.service.intent;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.intent.ActionIntentPayload;
import decentralabs.blockchain.dto.intent.IntentAction;
import decentralabs.blockchain.dto.intent.IntentMeta;
import decentralabs.blockchain.dto.intent.ReservationIntentPayload;
import decentralabs.blockchain.util.LogSanitizer;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class Eip712IntentVerifier {

    private static final String EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String INTENT_META_TYPE =
        "IntentMeta(bytes32 requestId,address signer,address executor,uint8 action,bytes32 payloadHash,uint256 nonce,uint64 requestedAt,uint64 expiresAt)";
    private static final String RESERVATION_PAYLOAD_TYPE =
        "ReservationIntentPayload(address executor,string schacHomeOrganization,string puc,bytes32 assertionHash,uint256 labId,uint32 start,uint32 end,uint96 price,bytes32 reservationKey)";
    private static final String ACTION_PAYLOAD_TYPE =
        "ActionIntentPayload(address executor,string schacHomeOrganization,string puc,bytes32 assertionHash,uint256 labId,bytes32 reservationKey,string uri,uint96 price,uint96 maxBatch,string auth,string accessURI,string accessKey,string tokenURI)";

    private static final byte[] EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE);
    private static final byte[] INTENT_META_TYPEHASH = keccak256(INTENT_META_TYPE);
    private static final byte[] RESERVATION_PAYLOAD_TYPEHASH = keccak256(RESERVATION_PAYLOAD_TYPE);
    private static final byte[] ACTION_PAYLOAD_TYPEHASH = keccak256(ACTION_PAYLOAD_TYPE);

    private final String trustedSigner;
    private final String domainName;
    private final String domainVersion;
    private final long domainChainId;
    private final String verifyingContract;

    public Eip712IntentVerifier(
        @Value("${intent.trusted-signer:}") String trustedSigner,
        @Value("${intent.domain.name:DecentraLabsIntent}") String domainName,
        @Value("${intent.domain.version:1}") String domainVersion,
        @Value("${intent.domain.chain-id:11155111}") long domainChainId,
        @Value("${intent.domain.verifying-contract:${contract.address:0x0000000000000000000000000000000000000000}}") String verifyingContract
    ) {
        this.trustedSigner = trustedSigner == null ? "" : trustedSigner.toLowerCase(Locale.ROOT);
        this.domainName = domainName;
        this.domainVersion = domainVersion;
        this.domainChainId = domainChainId;
        this.verifyingContract = verifyingContract;
    }

    public VerificationResult verify(
        IntentAction action,
        IntentMeta meta,
        ActionIntentPayload actionPayload,
        ReservationIntentPayload reservationPayload,
        String signature
    ) {
        if (meta == null || signature == null || signature.isBlank()) {
            return new VerificationResult(false, null, null, "missing_meta_or_signature");
        }
        if (action == null) {
            return new VerificationResult(false, null, null, "unknown_action");
        }

        try {
            String computedPayloadHash = action.usesReservationPayload()
                ? computeReservationPayloadHash(reservationPayload)
                : computeActionPayloadHash(actionPayload);

            if (computedPayloadHash == null) {
                return new VerificationResult(false, null, null, "missing_payload");
            }

            String normalizedPayloadHash = normalizeBytes32(meta.getPayloadHash());
            if (normalizedPayloadHash == null || !normalizedPayloadHash.equalsIgnoreCase(computedPayloadHash)) {
                return new VerificationResult(false, null, computedPayloadHash, "payload_hash_mismatch");
            }

            byte[] digest = buildIntentDigest(meta);
            Sign.SignatureData sigData = signatureToData(signature);
            BigInteger publicKey = Sign.signedMessageHashToKey(digest, sigData);
            String recoveredAddress = "0x" + Keys.getAddress(publicKey);
            String checksum = Keys.toChecksumAddress(recoveredAddress);
            boolean signerMatches = checksum.equalsIgnoreCase(meta.getSigner());

            if (!signerMatches) {
                return new VerificationResult(false, checksum, computedPayloadHash, "signature_mismatch");
            }
            if (!trustedSigner.isBlank() && !checksum.equalsIgnoreCase(trustedSigner)) {
                return new VerificationResult(false, checksum, computedPayloadHash, "not_trusted_signer");
            }
            return new VerificationResult(true, checksum, computedPayloadHash, null);
        } catch (Exception ex) {
            log.warn("Failed to verify EIP-712 intent {}: {}", LogSanitizer.sanitize(meta.getRequestId()), LogSanitizer.sanitize(ex.getMessage()));
            return new VerificationResult(false, null, null, ex.getMessage());
        }
    }

    public String computeActionPayloadHash(ActionIntentPayload payload) {
        if (payload == null || payload.getExecutor() == null) {
            return null;
        }
        String encodedHex = encodeTypes(
            new Bytes32(ACTION_PAYLOAD_TYPEHASH),
            new Address(normalizeAddress(payload.getExecutor())),
            new Bytes32(keccakString(payload.getSchacHomeOrganization())),
            new Bytes32(keccakString(payload.getPuc())),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(nullSafe(payload.getLabId())),
            new Bytes32(toBytes32(payload.getReservationKey())),
            new Bytes32(keccakString(payload.getUri())),
            new Uint256(nullSafe(payload.getPrice())),
            new Uint256(nullSafe(payload.getMaxBatch())),
            new Bytes32(keccakString(payload.getAuth())),
            new Bytes32(keccakString(payload.getAccessURI())),
            new Bytes32(keccakString(payload.getAccessKey())),
            new Bytes32(keccakString(payload.getTokenURI()))
        );
        return Numeric.toHexString(Hash.sha3(Numeric.hexStringToByteArray(encodedHex)));
    }

    public String computeReservationPayloadHash(ReservationIntentPayload payload) {
        if (payload == null || payload.getExecutor() == null) {
            return null;
        }
        String encodedHex = encodeTypes(
            new Bytes32(RESERVATION_PAYLOAD_TYPEHASH),
            new Address(normalizeAddress(payload.getExecutor())),
            new Bytes32(keccakString(payload.getSchacHomeOrganization())),
            new Bytes32(keccakString(payload.getPuc())),
            new Bytes32(toBytes32(payload.getAssertionHash())),
            new Uint256(nullSafe(payload.getLabId())),
            new Uint256(nullSafe(payload.getStart())),
            new Uint256(nullSafe(payload.getEnd())),
            new Uint256(nullSafe(payload.getPrice())),
            new Bytes32(toBytes32(payload.getReservationKey()))
        );
        return Numeric.toHexString(Hash.sha3(Numeric.hexStringToByteArray(encodedHex)));
    }

    public byte[] buildIntentDigest(IntentMeta meta) {
        byte[] structHash = hashIntentMeta(meta);
        byte[] domainSeparator = buildDomainSeparator();

        byte[] digestInput = new byte[2 + domainSeparator.length + structHash.length];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, domainSeparator.length);
        System.arraycopy(structHash, 0, digestInput, 2 + domainSeparator.length, structHash.length);
        return Hash.sha3(digestInput);
    }

    private byte[] hashIntentMeta(IntentMeta meta) {
        String encodedHex = encodeTypes(
            new Bytes32(INTENT_META_TYPEHASH),
            new Bytes32(toBytes32(meta.getRequestId())),
            new Address(normalizeAddress(meta.getSigner())),
            new Address(normalizeAddress(meta.getExecutor())),
            new Uint8(meta.getAction().longValue()),
            new Bytes32(toBytes32(meta.getPayloadHash())),
            new Uint256(BigInteger.valueOf(meta.getNonce())),
            new Uint256(BigInteger.valueOf(meta.getRequestedAt())),
            new Uint256(BigInteger.valueOf(meta.getExpiresAt()))
        );
        return Hash.sha3(Numeric.hexStringToByteArray(encodedHex));
    }

    private byte[] buildDomainSeparator() {
        String encodedHex = encodeTypes(
            new Bytes32(EIP712_DOMAIN_TYPEHASH),
            new Bytes32(keccak256(domainName)),
            new Bytes32(keccak256(domainVersion)),
            new Uint256(BigInteger.valueOf(domainChainId)),
            new Address(normalizeAddress(verifyingContract))
        );
        return Hash.sha3(Numeric.hexStringToByteArray(encodedHex));
    }

    @SuppressWarnings("rawtypes")
    private String encodeTypes(Type... types) {
        StringBuilder sb = new StringBuilder();
        for (Type type : types) {
            sb.append(TypeEncoder.encode(type));
        }
        return sb.toString();
    }

    private Sign.SignatureData signatureToData(String signatureHex) {
        byte[] signatureBytes = Numeric.hexStringToByteArray(signatureHex);
        if (signatureBytes.length != 65) {
            throw new IllegalArgumentException("Invalid signature length: " + signatureBytes.length);
        }
        byte v = signatureBytes[64];
        // Explicit cast to avoid implicit narrowing conversion warning
        // The v value in Ethereum signatures is expected to be 27 or 28
        if (v < 27) {
            v = (byte) (v + 27);
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signatureBytes, 0, r, 0, 32);
        System.arraycopy(signatureBytes, 32, s, 0, 32);
        return new Sign.SignatureData(v, r, s);
    }

    private static byte[] keccak256(String value) {
        return Hash.sha3(value.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] keccakString(String value) {
        String safe = value == null ? "" : value;
        return Hash.sha3(safe.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] toBytes32(String hex) {
        if (hex == null || hex.isBlank()) {
            return new byte[32];
        }
        byte[] raw = Numeric.hexStringToByteArray(hex);
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        int start = 32 - raw.length;
        if (start < 0) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, start, raw.length);
        }
        return out;
    }

    private String normalizeBytes32(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String clean = Numeric.cleanHexPrefix(value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }

    private String normalizeAddress(String address) {
        String safe = (address == null || address.isBlank()) ? "0x0" : address;
        String clean = Numeric.cleanHexPrefix(safe);
        return "0x" + clean;
    }

    private BigInteger nullSafe(BigInteger value) {
        return value == null ? BigInteger.ZERO : value;
    }

    private BigInteger nullSafe(Long value) {
        return value == null ? BigInteger.ZERO : BigInteger.valueOf(value);
    }

    public record VerificationResult(boolean valid, String recoveredAddress, String computedPayloadHash, String error) { }
}
