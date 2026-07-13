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
        assertThatThrownBy(() -> cipher.decrypt(encrypted.substring(0, encrypted.length() - 1) + "A"))
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
