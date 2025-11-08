package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.service.persistence.WalletPersistenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WalletServiceEncryptionTest {

    private WalletService walletService;

    @BeforeEach
    void setUp() {
        walletService = new WalletService(Mockito.mock(WalletPersistenceService.class));
        ReflectionTestUtils.setField(walletService, "baseDomain", "localhost");
        ReflectionTestUtils.setField(walletService, "defaultRpcUrl", "http://localhost");
        ReflectionTestUtils.setField(walletService, "contractAddress", "0x0");
        ReflectionTestUtils.setField(walletService, "defaultWalletAddress", "0x0");
    }

    @Test
    void encryptAndDecryptPrivateKeyRoundTrip() {
        String privateKey = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String password = "SuperSecret!";

        String encrypted = ReflectionTestUtils.invokeMethod(walletService, "encryptPrivateKey", privateKey, password);
        String decrypted = walletService.decryptPrivateKey(encrypted, password);

        assertThat(decrypted).isEqualTo(privateKey);
    }

    @Test
    void decryptPrivateKeyFailsWithWrongPassword() {
        String privateKey = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        String encrypted = ReflectionTestUtils.invokeMethod(walletService, "encryptPrivateKey", privateKey, "password1");

        assertThatThrownBy(() -> walletService.decryptPrivateKey(encrypted, "password2"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to decrypt private key");
    }
}
