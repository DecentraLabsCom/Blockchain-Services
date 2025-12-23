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
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@Component
public class Eip712CheckInVerifier {
    private static final String EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String CHECKIN_TYPE =
        "CheckIn(address signer,bytes32 reservationKey,bytes32 pucHash,uint64 timestamp)";

    private static final byte[] EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE);
    private static final byte[] CHECKIN_TYPEHASH = keccak256(CHECKIN_TYPE);

    private final String domainName;
    private final String domainVersion;
    private final long domainChainId;
    private final String verifyingContract;

    public Eip712CheckInVerifier(
        @Value("${intent.domain.name:DecentraLabsIntent}") String domainName,
        @Value("${intent.domain.version:1}") String domainVersion,
        @Value("${intent.domain.chain-id:11155111}") long domainChainId,
        @Value("${intent.domain.verifying-contract:${contract.address:0x0000000000000000000000000000000000000000}}") String verifyingContract
    ) {
        this.domainName = domainName;
        this.domainVersion = domainVersion;
        this.domainChainId = domainChainId;
        this.verifyingContract = verifyingContract;
    }

    public VerificationResult verify(
        String signer,
        String reservationKey,
        String pucHash,
        long timestamp,
        String signature
    ) {
        if (signature == null || signature.isBlank()) {
            return new VerificationResult(false, null, "missing_signature");
        }

        try {
            byte[] digest = buildDigest(signer, reservationKey, pucHash, timestamp);
            Sign.SignatureData sigData = signatureToData(signature);
            BigInteger publicKey = Sign.signedMessageHashToKey(digest, sigData);
            String recoveredAddress = "0x" + Keys.getAddress(publicKey);
            String checksum = Keys.toChecksumAddress(recoveredAddress);
            boolean signerMatches = checksum.equalsIgnoreCase(signer);
            if (!signerMatches) {
                return new VerificationResult(false, checksum, "signature_mismatch");
            }
            return new VerificationResult(true, checksum, null);
        } catch (Exception ex) {
            return new VerificationResult(false, null, ex.getMessage());
        }
    }

    public byte[] buildDigest(String signer, String reservationKey, String pucHash, long timestamp) {
        byte[] structHash = hashCheckIn(signer, reservationKey, pucHash, timestamp);
        byte[] domainSeparator = buildDomainSeparator();

        byte[] digestInput = new byte[2 + domainSeparator.length + structHash.length];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, domainSeparator.length);
        System.arraycopy(structHash, 0, digestInput, 2 + domainSeparator.length, structHash.length);
        return Hash.sha3(digestInput);
    }

    private byte[] hashCheckIn(String signer, String reservationKey, String pucHash, long timestamp) {
        String encodedHex = encodeTypes(
            new Bytes32(CHECKIN_TYPEHASH),
            new Address(normalizeAddress(signer)),
            new Bytes32(toBytes32(reservationKey)),
            new Bytes32(toBytes32(pucHash)),
            new Uint64(BigInteger.valueOf(timestamp))
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

    public record VerificationResult(boolean valid, String recoveredAddress, String error) { }
}
