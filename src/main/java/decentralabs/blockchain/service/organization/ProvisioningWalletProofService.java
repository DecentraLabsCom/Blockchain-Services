package decentralabs.blockchain.service.organization;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.springframework.stereotype.Component;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

/**
 * Signs the exact Marketplace provisioning claims using the custodied
 * institutional wallet and supports independent signer recovery.
 */
@Component
public class ProvisioningWalletProofService {

    private static final String EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String PROVISIONING_TYPE =
        "InstitutionProvisioning(string institutionId,address walletAddress,string canonicalBackendOrigin,string registrationType,uint256 chainId,address registryContract,string jti,bytes32 nonce,uint256 issuedAt,uint256 expiresAt)";
    private static final String PAIRING_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String PAIRING_TYPE =
        "InstitutionProvisioningPairing(string institutionId,address walletAddress,string canonicalBackendOrigin,string registrationType,uint256 chainId,address registryContract,bytes32 challenge,uint256 issuedAt,uint256 expiresAt)";
    private static final String DOMAIN_NAME = "DecentraLabsInstitutionProvisioning";
    private static final String DOMAIN_VERSION = "1";
    private static final String PAIRING_DOMAIN_NAME = "DecentraLabsInstitutionPairing";

    private static final byte[] EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE);
    private static final byte[] PROVISIONING_TYPEHASH = keccak256(PROVISIONING_TYPE);
    private static final byte[] PAIRING_DOMAIN_TYPEHASH = keccak256(PAIRING_DOMAIN_TYPE);
    private static final byte[] PAIRING_TYPEHASH = keccak256(PAIRING_TYPE);

    public String sign(ProvisioningSecurityClaims claims, Credentials credentials) {
        validate(claims);
        if (credentials == null) {
            throw new IllegalArgumentException("Institutional wallet credentials are required");
        }
        if (!credentials.getAddress().equalsIgnoreCase(claims.walletAddress())) {
            throw new IllegalArgumentException(
                "Provisioning wallet does not match the custodied institutional wallet"
            );
        }

        Sign.SignatureData signature = Sign.signMessage(
            buildDigest(claims),
            credentials.getEcKeyPair(),
            false
        );
        return signatureToHex(signature);
    }

    public String recoverSigner(ProvisioningSecurityClaims claims, String signatureHex) {
        validate(claims);
        if (signatureHex == null || signatureHex.isBlank()) {
            throw new IllegalArgumentException("Provisioning wallet signature is required");
        }
        try {
            BigInteger publicKey = Sign.signedMessageHashToKey(
                buildDigest(claims),
                signatureToData(signatureHex)
            );
            return Keys.toChecksumAddress("0x" + Keys.getAddress(publicKey));
        } catch (Exception error) {
            throw new IllegalArgumentException("Invalid provisioning wallet signature", error);
        }
    }

    public String signPairing(ProvisioningPairingSecurityClaims claims, Credentials credentials) {
        validatePairing(claims);
        if (credentials == null) {
            throw new IllegalArgumentException("Institutional wallet credentials are required");
        }
        if (!credentials.getAddress().equalsIgnoreCase(claims.walletAddress())) {
            throw new IllegalArgumentException(
                "Pairing wallet does not match the custodied institutional wallet"
            );
        }
        Sign.SignatureData signature = Sign.signMessage(
            buildPairingDigest(claims),
            credentials.getEcKeyPair(),
            false
        );
        return signatureToHex(signature);
    }

    public String recoverPairingSigner(ProvisioningPairingSecurityClaims claims, String signatureHex) {
        validatePairing(claims);
        if (signatureHex == null || signatureHex.isBlank()) {
            throw new IllegalArgumentException("Pairing wallet signature is required");
        }
        try {
            BigInteger publicKey = Sign.signedMessageHashToKey(
                buildPairingDigest(claims),
                signatureToData(signatureHex)
            );
            return Keys.toChecksumAddress("0x" + Keys.getAddress(publicKey));
        } catch (Exception error) {
            throw new IllegalArgumentException("Invalid pairing wallet signature", error);
        }
    }

    public byte[] buildPairingDigest(ProvisioningPairingSecurityClaims claims) {
        validatePairing(claims);
        byte[] domainSeparator = buildPairingDomainSeparator(claims);
        byte[] structHash = buildPairingStructHash(claims);
        byte[] digestInput = new byte[66];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, 32);
        System.arraycopy(structHash, 0, digestInput, 34, 32);
        return Hash.sha3(digestInput);
    }

    public byte[] buildDigest(ProvisioningSecurityClaims claims) {
        validate(claims);
        byte[] domainSeparator = buildDomainSeparator(claims);
        byte[] structHash = buildStructHash(claims);
        byte[] digestInput = new byte[66];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, 32);
        System.arraycopy(structHash, 0, digestInput, 34, 32);
        return Hash.sha3(digestInput);
    }

    private byte[] buildDomainSeparator(ProvisioningSecurityClaims claims) {
        String encoded = encodeTypes(
            new Bytes32(EIP712_DOMAIN_TYPEHASH),
            new Bytes32(keccak256(DOMAIN_NAME)),
            new Bytes32(keccak256(DOMAIN_VERSION)),
            new Uint256(claims.chainId()),
            new Address(normalizeAddress(claims.registryContract()))
        );
        return Hash.sha3(Numeric.hexStringToByteArray(encoded));
    }

    private byte[] buildStructHash(ProvisioningSecurityClaims claims) {
        String encoded = encodeTypes(
            new Bytes32(PROVISIONING_TYPEHASH),
            new Bytes32(keccak256(claims.institutionId())),
            new Address(normalizeAddress(claims.walletAddress())),
            new Bytes32(keccak256(claims.canonicalBackendOrigin())),
            new Bytes32(keccak256(claims.registrationType())),
            new Uint256(claims.chainId()),
            new Address(normalizeAddress(claims.registryContract())),
            new Bytes32(keccak256(claims.jti())),
            new Bytes32(bytes32(claims.nonce())),
            new Uint256(BigInteger.valueOf(claims.issuedAt())),
            new Uint256(BigInteger.valueOf(claims.expiresAt()))
        );
        return Hash.sha3(Numeric.hexStringToByteArray(encoded));
    }

    private byte[] buildPairingDomainSeparator(ProvisioningPairingSecurityClaims claims) {
        String encoded = encodeTypes(
            new Bytes32(PAIRING_DOMAIN_TYPEHASH),
            new Bytes32(keccak256(PAIRING_DOMAIN_NAME)),
            new Bytes32(keccak256(DOMAIN_VERSION)),
            new Uint256(claims.chainId()),
            new Address(normalizeAddress(claims.registryContract()))
        );
        return Hash.sha3(Numeric.hexStringToByteArray(encoded));
    }

    private byte[] buildPairingStructHash(ProvisioningPairingSecurityClaims claims) {
        String encoded = encodeTypes(
            new Bytes32(PAIRING_TYPEHASH),
            new Bytes32(keccak256(claims.institutionId())),
            new Address(normalizeAddress(claims.walletAddress())),
            new Bytes32(keccak256(claims.canonicalBackendOrigin())),
            new Bytes32(keccak256(claims.registrationType())),
            new Uint256(claims.chainId()),
            new Address(normalizeAddress(claims.registryContract())),
            new Bytes32(bytes32(claims.challenge())),
            new Uint256(BigInteger.valueOf(claims.issuedAt())),
            new Uint256(BigInteger.valueOf(claims.expiresAt()))
        );
        return Hash.sha3(Numeric.hexStringToByteArray(encoded));
    }

    private void validate(ProvisioningSecurityClaims claims) {
        if (claims == null) {
            throw new IllegalArgumentException("Provisioning security claims are required");
        }
        requireNonBlank(claims.institutionId(), "institutionId");
        requireAddress(claims.walletAddress(), "walletAddress");
        requireNonBlank(claims.canonicalBackendOrigin(), "canonicalBackendOrigin");
        requireNonBlank(claims.registrationType(), "registrationType");
        if (claims.chainId() == null || claims.chainId().signum() <= 0) {
            throw new IllegalArgumentException("chainId must be positive");
        }
        requireAddress(claims.registryContract(), "registryContract");
        requireNonBlank(claims.jti(), "jti");
        byte[] nonce = bytes32(claims.nonce());
        if (nonce.length != 32) {
            throw new IllegalArgumentException("nonce must be 32 bytes");
        }
        if (claims.issuedAt() <= 0 || claims.expiresAt() <= claims.issuedAt()) {
            throw new IllegalArgumentException("Invalid provisioning timestamps");
        }
    }

    private void validatePairing(ProvisioningPairingSecurityClaims claims) {
        if (claims == null) {
            throw new IllegalArgumentException("Provisioning pairing claims are required");
        }
        requireNonBlank(claims.institutionId(), "institutionId");
        requireAddress(claims.walletAddress(), "walletAddress");
        requireNonBlank(claims.canonicalBackendOrigin(), "canonicalBackendOrigin");
        requireNonBlank(claims.registrationType(), "registrationType");
        if (claims.chainId() == null || claims.chainId().signum() <= 0) {
            throw new IllegalArgumentException("chainId must be positive");
        }
        requireAddress(claims.registryContract(), "registryContract");
        if (bytes32(claims.challenge()).length != 32) {
            throw new IllegalArgumentException("challenge must be 32 bytes");
        }
        if (claims.issuedAt() <= 0 || claims.expiresAt() <= claims.issuedAt()) {
            throw new IllegalArgumentException("Invalid pairing timestamps");
        }
    }

    private void requireAddress(String address, String label) {
        String value = requireNonBlank(address, label);
        if (!value.matches("^0x[0-9a-fA-F]{40}$")) {
            throw new IllegalArgumentException(label + " must be a valid Ethereum address");
        }
    }

    private String requireNonBlank(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
        return value.trim();
    }

    @SuppressWarnings("rawtypes")
    private String encodeTypes(Type... types) {
        StringBuilder encoded = new StringBuilder();
        for (Type type : types) {
            encoded.append(TypeEncoder.encode(type));
        }
        return encoded.toString();
    }

    private static byte[] keccak256(String value) {
        return Hash.sha3(value.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] bytes32(String value) {
        byte[] raw = Numeric.hexStringToByteArray(requireNonBlank(value, "nonce"));
        if (raw.length != 32) {
            throw new IllegalArgumentException("nonce must be 32 bytes");
        }
        return raw;
    }

    private String normalizeAddress(String address) {
        return "0x" + Numeric.cleanHexPrefix(address).toLowerCase(Locale.ROOT);
    }

    private String signatureToHex(Sign.SignatureData signature) {
        byte[] bytes = new byte[65];
        System.arraycopy(signature.getR(), 0, bytes, 0, 32);
        System.arraycopy(signature.getS(), 0, bytes, 32, 32);
        bytes[64] = signature.getV()[0];
        return Numeric.toHexString(bytes);
    }

    private Sign.SignatureData signatureToData(String signatureHex) {
        byte[] signature = Numeric.hexStringToByteArray(signatureHex);
        if (signature.length != 65) {
            throw new IllegalArgumentException("Invalid signature length");
        }
        byte v = signature[64];
        if (v < 27) {
            v = (byte) (v + 27);
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        return new Sign.SignatureData(v, r, s);
    }
}
