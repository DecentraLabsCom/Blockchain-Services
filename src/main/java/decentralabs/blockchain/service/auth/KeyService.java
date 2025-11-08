package decentralabs.blockchain.service.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.charset.StandardCharsets;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Base64;
import java.util.Set;


@Service
@Slf4j
public class KeyService {

    private RSAPublicKey publicKey;

    @Value("${public.key.path}")
    private String publicKeyPath;
    @Value("${private.key.path}")
    private String privateKeyPath;

    /**
     * Validates file permissions on startup to ensure keys are properly secured
     * This prevents common security misconfigurations in production
     */
    @PostConstruct
    public void validateKeyFileSecurity() {
        try {
            validateKeyFile(privateKeyPath, "Private Key");
            validateKeyFile(publicKeyPath, "Public Key");
            log.info("✅ Key file security validation passed");
        } catch (Exception e) {
            log.error("❌ SECURITY WARNING: Key file validation failed: {}", e.getMessage());
            log.error("Please ensure key files exist and have proper permissions (recommended: 400 or 600)");
            // Continue startup but log warning - allows development mode to work
        }
    }

    /**
     * Validates a key file's existence and permissions (on POSIX systems)
     */
    private void validateKeyFile(String keyPath, String keyType) throws IOException {
        Path path = Paths.get(keyPath);
        
        // Check file exists
        if (!Files.exists(path)) {
            throw new IOException(keyType + " file not found at: " + keyPath);
        }

        // Check if file is readable
        if (!Files.isReadable(path)) {
            throw new IOException(keyType + " file is not readable: " + keyPath);
        }

        // On POSIX systems (Linux, Unix, macOS), validate permissions
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            
            // Check for overly permissive permissions
            if (permissions.contains(PosixFilePermission.GROUP_READ) ||
                permissions.contains(PosixFilePermission.GROUP_WRITE) ||
                permissions.contains(PosixFilePermission.OTHERS_READ) ||
                permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                
                String permString = PosixFilePermissions.toString(permissions);
                log.warn("⚠️  SECURITY WARNING: {} has overly permissive permissions: {} ({})", 
                    keyType, permString, keyPath);
                log.warn("Recommended: chmod 400 {} (read-only for owner)", keyPath);
            } else {
                String permString = PosixFilePermissions.toString(permissions);
                log.info("✅ {} permissions are secure: {} ({})", keyType, permString, keyPath);
            }
        } catch (UnsupportedOperationException e) {
            // Windows or other non-POSIX system - skip permission check
            log.debug("Permission validation skipped (non-POSIX file system)");
        }
    }

    public RSAPublicKey getPublicKey() throws Exception {
        if (publicKey == null) {
            this.loadPublicKey();
        }
        return publicKey;
    }

    private void loadPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
        String keyPEM = new String(keyBytes)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(keyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.publicKey = (RSAPublicKey) keyFactory
                .generatePublic(new java.security.spec.X509EncodedKeySpec(decodedKey));
    }

    public PrivateKey loadPrivateKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
        String key = new String(keyBytes, StandardCharsets.UTF_8);
        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] cleanedKeyBytes = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(cleanedKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

}
