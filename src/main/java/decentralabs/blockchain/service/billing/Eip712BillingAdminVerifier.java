package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest;
import decentralabs.blockchain.util.LogSanitizer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Int256;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint64;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@Component
@Slf4j
public class Eip712BillingAdminVerifier {

    private static final String EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    private static final String TREASURY_ADMIN_TYPE =
        "TreasuryAdminOperation(address signer,string operation,address providerAddress,address backendAddress,uint256 spendingLimit,uint256 spendingPeriod,uint256 amount,uint256 labId,uint256 maxBatch,address creditAccount,int256 creditDelta,uint256 fromReceivableState,uint256 toReceivableState,string reference,uint64 timestamp)";

    private static final byte[] EIP712_DOMAIN_TYPEHASH = keccak256(EIP712_DOMAIN_TYPE);
    private static final byte[] TREASURY_ADMIN_TYPEHASH = keccak256(TREASURY_ADMIN_TYPE);

    private final String domainName;
    private final String domainVersion;
    private final long domainChainId;
    private final String verifyingContract;

    public Eip712BillingAdminVerifier(
        @Value("${billing.admin.domain.name:DecentraLabsTreasuryAdmin}") String domainName,
        @Value("${billing.admin.domain.version:1}") String domainVersion,
        @Value("${billing.admin.domain.chain-id:${intent.domain.chain-id:11155111}}") long domainChainId,
        @Value("${billing.admin.domain.verifying-contract:${contract.address:0x0000000000000000000000000000000000000000}}")
            String verifyingContract
    ) {
        this.domainName = domainName;
        this.domainVersion = domainVersion;
        this.domainChainId = domainChainId;
        this.verifyingContract = verifyingContract;
    }

    public VerificationResult verify(InstitutionalAdminRequest request, String expectedSigner) {
        if (request == null || request.getOperation() == null) {
            return new VerificationResult(false, null, "missing_operation");
        }
        if (request.getSignature() == null || request.getSignature().isBlank()) {
            return new VerificationResult(false, null, "missing_signature");
        }
        if (request.getTimestamp() == null) {
            return new VerificationResult(false, null, "missing_timestamp");
        }
        String signer = request.getAdminWalletAddress();
        if (signer == null || signer.isBlank()) {
            return new VerificationResult(false, null, "missing_signer");
        }
        if (expectedSigner == null || expectedSigner.isBlank()) {
            return new VerificationResult(false, null, "missing_expected_signer");
        }
        if (!signer.equalsIgnoreCase(expectedSigner)) {
            return new VerificationResult(false, null, "signer_mismatch");
        }

        try {
            byte[] digest = buildDigest(request);
            Sign.SignatureData sigData = signatureToData(request.getSignature());
            BigInteger publicKey = Sign.signedMessageHashToKey(digest, sigData);
            String recoveredAddress = "0x" + Keys.getAddress(publicKey);
            String checksum = Keys.toChecksumAddress(recoveredAddress);
            if (!checksum.equalsIgnoreCase(expectedSigner)) {
                return new VerificationResult(false, checksum, "signature_mismatch");
            }
            return new VerificationResult(true, checksum, null);
        } catch (Exception ex) {
            log.warn("Failed to verify billing admin signature: {}", LogSanitizer.sanitize(ex.getMessage()));
            return new VerificationResult(false, null, ex.getMessage());
        }
    }

    public byte[] buildDigest(InstitutionalAdminRequest request) {
        byte[] structHash = hashRequest(request);
        byte[] domainSeparator = buildDomainSeparator();

        byte[] digestInput = new byte[2 + domainSeparator.length + structHash.length];
        digestInput[0] = 0x19;
        digestInput[1] = 0x01;
        System.arraycopy(domainSeparator, 0, digestInput, 2, domainSeparator.length);
        System.arraycopy(structHash, 0, digestInput, 2 + domainSeparator.length, structHash.length);
        return Hash.sha3(digestInput);
    }

    private byte[] hashRequest(InstitutionalAdminRequest request) {
        String encodedHex = encodeTypes(
            new Bytes32(TREASURY_ADMIN_TYPEHASH),
            new Address(normalizeAddress(request.getAdminWalletAddress())),
            new Bytes32(keccakString(request.getOperation().name())),
            new Address(normalizeAddress(request.getProviderAddress())),
            new Address(normalizeAddress(request.getBackendAddress())),
            new Uint256(parseOptionalBigInteger(request.getSpendingLimit())),
            new Uint256(parseOptionalBigInteger(request.getSpendingPeriod())),
            new Uint256(parseOptionalBigInteger(request.getAmount())),
            new Uint256(parseOptionalBigInteger(request.getLabId())),
            new Uint256(parseOptionalBigInteger(request.getMaxBatch())),
            new Address(normalizeAddress(request.getCreditAccount())),
            new Int256(parseOptionalSignedBigInteger(request.getCreditDelta())),
            new Uint256(parseOptionalBigInteger(request.getFromReceivableState())),
            new Uint256(parseOptionalBigInteger(request.getToReceivableState())),
            new Bytes32(keccakString(request.getReference())),
            new Uint64(BigInteger.valueOf(request.getTimestamp()))
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

    private byte[] keccakString(String value) {
        String safe = value == null ? "" : value;
        return Hash.sha3(safe.getBytes(StandardCharsets.UTF_8));
    }

    private String normalizeAddress(String address) {
        String safe = (address == null || address.isBlank()) ? "0x0" : address;
        String clean = Numeric.cleanHexPrefix(safe);
        return "0x" + clean.toLowerCase(Locale.ROOT);
    }

    private BigInteger parseOptionalBigInteger(String value) {
        if (value == null || value.isBlank()) {
            return BigInteger.ZERO;
        }
        return new BigInteger(value);
    }

    private BigInteger parseOptionalSignedBigInteger(String value) {
        if (value == null || value.isBlank()) {
            return BigInteger.ZERO;
        }
        return new BigInteger(value.trim());
    }

    public record VerificationResult(boolean valid, String recoveredAddress, String error) { }
}
