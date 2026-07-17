package decentralabs.blockchain.service.auth;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Encrypts short-lived access credentials before durable hand-off storage. */
@Component
public class AccessCodeTokenCipher {
    private static final String PREFIX = "v1.";
    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MAX_PLAINTEXT_BYTES = 64 * 1024;
    private static final int MAX_ENCRYPTED_VALUE_BYTES = IV_LENGTH + MAX_PLAINTEXT_BYTES + (GCM_TAG_BITS / 8);

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public AccessCodeTokenCipher(@Value("${auth.access-code.encryption-key:}") String configuredKey) {
        this.key = decodeKey(configuredKey);
    }

    public String encrypt(String plaintext) {
        requireConfigured();
        if (plaintext == null) {
            throw new IllegalArgumentException("Access credential must not be null");
        }
        try {
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            if (plaintextBytes.length > MAX_PLAINTEXT_BYTES) {
                throw new IllegalArgumentException("Access credential is too large");
            }
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plaintextBytes);
            ByteArrayOutputStream combined = new ByteArrayOutputStream();
            combined.writeBytes(iv);
            combined.writeBytes(encrypted);
            return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(
                combined.toByteArray()
            );
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Unable to encrypt access credential", ex);
        }
    }

    public String decrypt(String ciphertext) {
        requireConfigured();
        if (ciphertext == null || !ciphertext.startsWith(PREFIX)) {
            throw new IllegalStateException("Unsupported encrypted access credential format");
        }
        try {
            byte[] value = Base64.getUrlDecoder().decode(ciphertext.substring(PREFIX.length()));
            if (value.length <= IV_LENGTH || value.length > MAX_ENCRYPTED_VALUE_BYTES) {
                throw new IllegalStateException("Invalid encrypted access credential");
            }
            byte[] iv = Arrays.copyOf(value, IV_LENGTH);
            byte[] encrypted = Arrays.copyOfRange(value, IV_LENGTH, value.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Unable to decrypt access credential", ex);
        }
    }

    private void requireConfigured() {
        if (key == null) {
            throw new IllegalStateException("ACCESS_CODE_ENCRYPTION_KEY must contain exactly 32 bytes");
        }
    }

    private SecretKeySpec decodeKey(String configuredKey) {
        if (configuredKey == null || configuredKey.isBlank() || "CHANGE_ME".equalsIgnoreCase(configuredKey.trim())) {
            return null;
        }
        String value = configuredKey.trim();
        String padded = value + "=".repeat((4 - value.length() % 4) % 4);
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(padded);
        } catch (IllegalArgumentException ignored) {
            try {
                decoded = Base64.getDecoder().decode(padded);
            } catch (IllegalArgumentException ex) {
                return null;
            }
        }
        return decoded.length == 32 ? new SecretKeySpec(decoded, "AES") : null;
    }
}
