package decentralabs.blockchain.service.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Credentials;
import org.web3j.utils.Numeric;

class ProvisioningWalletProofServiceTest {

    private static final Credentials WALLET = Credentials.create(
        "0123456789012345678901234567890123456789012345678901234567890123"
    );

    private final ProvisioningWalletProofService service = new ProvisioningWalletProofService();

    @Test
    void matchesTheCrossRuntimeEip712Digest() {
        assertThat(Numeric.toHexString(service.buildDigest(claims("https://gateway.example.edu"))))
            .isEqualTo("0xda82840f3b973137c22759c232b6871815858b08be099be0765a901d3e3e6365");
    }

    @Test
    void signsTheExactEip712ProvisioningClaims() {
        ProvisioningSecurityClaims claims = claims("https://gateway.example.edu");

        String signature = service.sign(claims, WALLET);

        assertThat(service.recoverSigner(claims, signature)).isEqualToIgnoringCase(WALLET.getAddress());
        assertThat(service.recoverSigner(
            claims("https://attacker.example"),
            signature
        )).isNotEqualToIgnoringCase(WALLET.getAddress());
    }

    @Test
    void refusesToSignForAClaimedWalletDifferentFromTheCustodiedKey() {
        ProvisioningSecurityClaims claims = new ProvisioningSecurityClaims(
            "example.edu",
            "0x9999999999999999999999999999999999999999",
            "https://gateway.example.edu",
            "provider",
            BigInteger.valueOf(11_155_111L),
            "0xe49a2f59631717691642f929E0FeF1f705866600",
            "jti-1",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            1_700_000_000L,
            1_700_000_300L
        );

        assertThatThrownBy(() -> service.sign(claims, WALLET))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("does not match");
    }

    @Test
    void signsTheExactPairingClaims() {
        ProvisioningPairingSecurityClaims claims = pairingClaims("https://gateway.example.edu");

        String signature = service.signPairing(claims, WALLET);

        assertThat(service.recoverPairingSigner(claims, signature))
            .isEqualToIgnoringCase(WALLET.getAddress());
        assertThat(service.recoverPairingSigner(
            pairingClaims("https://attacker.example"),
            signature
        )).isNotEqualToIgnoringCase(WALLET.getAddress());
    }

    private ProvisioningSecurityClaims claims(String backendOrigin) {
        return new ProvisioningSecurityClaims(
            "example.edu",
            WALLET.getAddress(),
            backendOrigin,
            "provider",
            BigInteger.valueOf(11_155_111L),
            "0xe49a2f59631717691642f929E0FeF1f705866600",
            "jti-1",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            1_700_000_000L,
            1_700_000_300L
        );
    }

    private ProvisioningPairingSecurityClaims pairingClaims(String backendOrigin) {
        return new ProvisioningPairingSecurityClaims(
            "example.edu",
            WALLET.getAddress(),
            backendOrigin,
            "provider",
            BigInteger.valueOf(11_155_111L),
            "0xe49a2f59631717691642f929E0FeF1f705866600",
            "0x2222222222222222222222222222222222222222222222222222222222222222",
            1_700_000_000L,
            1_700_000_600L
        );
    }
}
