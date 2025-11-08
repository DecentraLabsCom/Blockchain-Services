package decentralabs.blockchain.service.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyServiceTest {

    private KeyService keyService;

    @TempDir
    Path tempDir;

    private Path publicKeyFile;
    private Path privateKeyFile;

    @BeforeEach
    void setUp() throws Exception {
        keyService = new KeyService();

        // Generate test RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create public key file
        publicKeyFile = tempDir.resolve("public_key.pem");
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPublic().getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        Files.writeString(publicKeyFile, publicKeyPEM);

        // Create private key file
        privateKeyFile = tempDir.resolve("private_key.pem");
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        Files.writeString(privateKeyFile, privateKeyPEM);

        // Configure KeyService with test paths
        ReflectionTestUtils.setField(keyService, "publicKeyPath", publicKeyFile.toString());
        ReflectionTestUtils.setField(keyService, "privateKeyPath", privateKeyFile.toString());
    }

    @Test
    void shouldLoadPublicKeySuccessfully() throws Exception {
        RSAPublicKey publicKey = keyService.getPublicKey();

        assertThat(publicKey).isNotNull();
        assertThat(publicKey.getAlgorithm()).isEqualTo("RSA");
        assertThat(publicKey.getModulus().bitLength()).isEqualTo(2048);
    }

    @Test
    void shouldCachePublicKeyAfterFirstLoad() throws Exception {
        RSAPublicKey firstLoad = keyService.getPublicKey();
        RSAPublicKey secondLoad = keyService.getPublicKey();

        assertThat(firstLoad).isSameAs(secondLoad);
    }

    @Test
    void shouldLoadPrivateKeySuccessfully() throws Exception {
        PrivateKey privateKey = keyService.loadPrivateKey();

        assertThat(privateKey).isNotNull();
        assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
        assertThat(privateKey.getFormat()).isEqualTo("PKCS#8");
    }

    @Test
    void shouldFailWhenPublicKeyFileDoesNotExist() {
        ReflectionTestUtils.setField(keyService, "publicKeyPath", "/nonexistent/public_key.pem");

        assertThatThrownBy(() -> keyService.getPublicKey())
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldFailWhenPrivateKeyFileDoesNotExist() {
        ReflectionTestUtils.setField(keyService, "privateKeyPath", "/nonexistent/private_key.pem");

        assertThatThrownBy(() -> keyService.loadPrivateKey())
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldHandleInvalidPublicKeyFormat() throws Exception {
        Path invalidKeyFile = tempDir.resolve("invalid_public.pem");
        Files.writeString(invalidKeyFile, "-----BEGIN PUBLIC KEY-----\nINVALID_BASE64_DATA\n-----END PUBLIC KEY-----");

        ReflectionTestUtils.setField(keyService, "publicKeyPath", invalidKeyFile.toString());

        assertThatThrownBy(() -> keyService.getPublicKey())
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldHandleInvalidPrivateKeyFormat() throws Exception {
        Path invalidKeyFile = tempDir.resolve("invalid_private.pem");
        Files.writeString(invalidKeyFile, "-----BEGIN PRIVATE KEY-----\nINVALID_BASE64_DATA\n-----END PRIVATE KEY-----");

        ReflectionTestUtils.setField(keyService, "privateKeyPath", invalidKeyFile.toString());

        assertThatThrownBy(() -> keyService.loadPrivateKey())
                .isInstanceOf(Exception.class);
    }

    @Test
    void shouldValidateKeyFileSecurityOnPostConstruct() throws Exception {
        // Set restrictive permissions on POSIX systems
        try {
            Files.setPosixFilePermissions(privateKeyFile, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));

            // This should complete without throwing
            keyService.validateKeyFileSecurity();
        } catch (UnsupportedOperationException e) {
            // Skip test on Windows (POSIX not supported)
            assertThat(e).isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Test
    void shouldWarnAboutOverlyPermissiveKeyFiles() throws Exception {
        try {
            // Set overly permissive permissions
            Files.setPosixFilePermissions(privateKeyFile, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ
            ));

            // Should log warning but not throw
            keyService.validateKeyFileSecurity();
        } catch (UnsupportedOperationException e) {
            // Skip test on Windows (POSIX not supported)
            assertThat(e).isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Test
    void shouldStripPEMHeadersAndWhitespaceWhenLoadingKeys() throws Exception {
        // Test that keys with various whitespace formats are handled
        String publicKeyWithExtraWhitespace = "-----BEGIN PUBLIC KEY-----\n\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(
                        keyService.getPublicKey().getEncoded()
                ) +
                "\n\n-----END PUBLIC KEY-----\n\n";

        Path keyWithWhitespace = tempDir.resolve("key_with_whitespace.pem");
        Files.writeString(keyWithWhitespace, publicKeyWithExtraWhitespace);

        ReflectionTestUtils.setField(keyService, "publicKeyPath", keyWithWhitespace.toString());
        ReflectionTestUtils.setField(keyService, "publicKey", null); // Reset cache

        RSAPublicKey loadedKey = keyService.getPublicKey();
        assertThat(loadedKey).isNotNull();
    }
}
