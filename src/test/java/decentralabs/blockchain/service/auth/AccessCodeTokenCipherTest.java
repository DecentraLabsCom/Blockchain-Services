package decentralabs.blockchain.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class AccessCodeTokenCipherTest {

    @Test
    void encryptsAndAuthenticatesStoredBearerMaterial() {
        String key = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        AccessCodeTokenCipher cipher = new AccessCodeTokenCipher(key);

        String encrypted = cipher.encrypt("signed-jwt");

        assertThat(encrypted).startsWith("v1.").doesNotContain("signed-jwt");
        assertThat(cipher.decrypt(encrypted)).isEqualTo("signed-jwt");
        String tampered = encrypted.substring(0, 4)
            + (encrypted.charAt(4) == 'A' ? 'B' : 'A')
            + encrypted.substring(5);
        assertThatThrownBy(() -> cipher.decrypt(tampered))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void failsClosedWithoutAFullGatewayEncryptionKey() {
        AccessCodeTokenCipher cipher = new AccessCodeTokenCipher("");
        assertThatThrownBy(() -> cipher.encrypt("signed-jwt"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("ACCESS_CODE_ENCRYPTION_KEY");
    }
}
