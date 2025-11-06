package decentralabs.blockchain.service;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Map;
import java.util.UUID;

/**
 * Service for JWT token generation
 */
@Service
public class JwtService {

    @Value("${base.domain}")
    private String baseDomain;
    
    @Value("${auth.base-path}")
    private String authPath;
    
    @Autowired
    private KeyService keyService;
    
    /**
     * Helper method to construct the issuer URL from base domain and context path
     */
    private String getIssuerUrl() {
        return baseDomain + authPath;
    }

    /**
     * Generates a JWT token with optional booking information
     * 
     * @param claims User claims to include in the token
     * @param bookingInfo Optional booking information (includes aud, sub, nbf, exp, lab details)
     * @return JWT token string
     * @throws Exception if key operations fail
     */
    public String generateToken(Map<String, Object> claims, Map<String, Object> bookingInfo) throws Exception {
        String aud = null;
        BigInteger labId = null;
        String sub = null;
        BigInteger nbf = null;
        BigInteger exp = null;
    
        if (bookingInfo != null) {
            labId = (BigInteger) bookingInfo.get("lab");
            aud = (String) bookingInfo.get("aud");
            sub = (String) bookingInfo.get("sub");
            nbf = (BigInteger) bookingInfo.get("nbf");
            exp = (BigInteger) bookingInfo.get("exp");
        }
    
        String kid = generateKid(keyService.getPublicKey().getModulus());
        BigInteger iat = BigInteger.valueOf(System.currentTimeMillis() / 1000); // To seconds
        String jti = UUID.randomUUID().toString();
    
        JwtBuilder jwtBuilder = Jwts.builder()
                .header()
                .add("typ", "JWT")
                .add("kid", kid)
                .and()
                .claim("iss", getIssuerUrl())
                .claim("iat", iat)
                .claim("jti", jti); // Prevent replayability
    
        if (bookingInfo != null) {
            jwtBuilder.claim("aud", aud);
            jwtBuilder.claim("sub", sub);
            jwtBuilder.claim("nbf", nbf);
            jwtBuilder.claim("exp", exp);
        } else if (claims != null) {
            claims.forEach(jwtBuilder::claim);
        }
        if (labId != null) {
            jwtBuilder.claim("labId", labId.intValue());
        }
    
        PrivateKey privateKey = keyService.loadPrivateKey();
        return jwtBuilder.signWith(privateKey).compact();
    }

    /**
     * Generates a Key ID (kid) from the RSA modulus
     */
    public static String generateKid(BigInteger modulus) {
        byte[] modulusBytes = modulus.toByteArray();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(modulusBytes);

            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    
    /**
     * Encodes a BigInteger value to Base64URL format (for JWKS)
     */
    public static String base64UrlEncode(BigInteger value) {
        byte[] bytes = value.toByteArray();

        // If the first byte is 0x00, delete it (to make it compatible with OpenSSL)
        if (bytes.length > 1 && bytes[0] == 0x00) {
            bytes = java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
