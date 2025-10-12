package decentralabs.auth.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Base64;


@Service
public class KeyService {

    private RSAPublicKey publicKey;

    @Value("${public.key.path}")
    private String publicKeyPath;
    @Value("${private.key.path}")
    private String privateKeyPath;

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