package decentralabs.blockchain.service.auth;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@Component
public class SessionStartedAttestationSigner {
    private static final String EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String SESSION_STARTED_TYPE =
        "SessionStarted(address signer,bytes32 reservationKey,bytes32 labIdHash,bytes32 pucHash,bytes32 gatewayIdHash,bytes32 sessionIdHash,bytes32 accessTypeHash,uint64 startedAt,bytes32 nonce,bytes32 credentialHash,bytes32 clientProofHash)";

    private static final byte[] EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE);
    private static final byte[] SESSION_STARTED_TYPEHASH = keccak256(SESSION_STARTED_TYPE);

    private final String domainName;
    private final String domainVersion;
    private final long domainChainId;
    private final String verifyingContract;

    public SessionStartedAttestationSigner(
        @Value("${session.attestation.domain.name:DecentraLabsSession}") String domainName,
        @Value("${session.attestation.domain.version:1}") String domainVersion,
        @Value("${session.attestation.domain.chain-id:${intent.domain.chain-id:11155111}}") long domainChainId,
        @Value("${session.attestation.domain.verifying-contract:${contract.address:0x0000000000000000000000000000000000000000}}") String verifyingContract
    ) {
        this.domainName = domainName;
        this.domainVersion = domainVersion;
        this.domainChainId = domainChainId;
        this.verifyingContract = verifyingContract;
    }

    public SignedSessionStartedAttestation sign(SessionStartedAttestationPayload payload, Credentials credentials) {
        if (payload == null) {
            throw new IllegalArgumentException("payload is required");
        }
        if (credentials == null) {
            throw new IllegalArgumentException("credentials are required");
        }
        byte[] digest = buildDigest(payload);
        Sign.SignatureData signatureData = Sign.signMessage(digest, credentials.getEcKeyPair(), false);
        return new SignedSessionStartedAttestation(
            Numeric.toHexString(digest),
            signatureToHex(signatureData)
        );
    }

    public byte[] buildDigest(SessionStartedAttestationPayload payload) {
        byte[] structHash = hashSessionStarted(payload);
        byte[] domainSeparator = buildDomainSeparator();

        byte[] digestInput = new byte[2 + domainSeparator.length + structHash.length];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, domainSeparator.length);
        System.arraycopy(structHash, 0, digestInput, 2 + domainSeparator.length, structHash.length);
        return Hash.sha3(digestInput);
    }

    public long getDomainChainId() {
        return domainChainId;
    }

    private byte[] hashSessionStarted(SessionStartedAttestationPayload payload) {
        String encodedHex = encodeTypes(
            new Bytes32(SESSION_STARTED_TYPEHASH),
            new Address(normalizeAddress(payload.signer())),
            new Bytes32(toBytes32(payload.reservationKey())),
            new Bytes32(keccakString(payload.labId())),
            new Bytes32(toBytes32(payload.pucHash())),
            new Bytes32(keccakString(payload.gatewayId())),
            new Bytes32(keccakString(payload.sessionId())),
            new Bytes32(keccakString(payload.accessType())),
            new Uint64(BigInteger.valueOf(payload.startedAt())),
            new Bytes32(toBytes32(payload.nonce())),
            new Bytes32(toBytes32(payload.credentialHash())),
            new Bytes32(toBytes32(payload.clientProofHash()))
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

    private static String signatureToHex(Sign.SignatureData signatureData) {
        byte[] sigBytes = new byte[65];
        System.arraycopy(signatureData.getR(), 0, sigBytes, 0, 32);
        System.arraycopy(signatureData.getS(), 0, sigBytes, 32, 32);
        sigBytes[64] = signatureData.getV()[0];
        return Numeric.toHexString(sigBytes);
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

    private String normalizeAddress(String address) {
        String safe = (address == null || address.isBlank()) ? "0x0" : address;
        String clean = Numeric.cleanHexPrefix(safe);
        return "0x" + clean.toLowerCase(Locale.ROOT);
    }

    public record SessionStartedAttestationPayload(
        String signer,
        String reservationKey,
        String labId,
        String pucHash,
        String gatewayId,
        String sessionId,
        String accessType,
        long startedAt,
        String nonce,
        String credentialHash,
        String clientProofHash
    ) { }

    public record SignedSessionStartedAttestation(String digest, String signature) { }
}
