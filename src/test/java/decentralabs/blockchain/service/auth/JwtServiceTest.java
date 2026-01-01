package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.service.BackendUrlResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private KeyService keyService;

    @Mock
    private BackendUrlResolver backendUrlResolver;

    @InjectMocks
    private JwtService jwtService;

    private PrivateKey mockPrivateKey;
    private RSAPublicKey mockPublicKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate REAL RSA keys for JJWT library (mocks don't work with crypto libraries)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        mockPrivateKey = keyPair.getPrivate();
        mockPublicKey = (RSAPublicKey) keyPair.getPublic();
        
        // Use lenient() to prevent UnnecessaryStubbing errors
        lenient().when(keyService.loadPrivateKey()).thenReturn(mockPrivateKey);
        lenient().when(keyService.getPublicKey()).thenReturn(mockPublicKey);
        lenient().when(backendUrlResolver.resolveIssuer(anyString())).thenReturn("http://localhost:8080/auth");
    }

    @Test
    void testGenerateToken_WithoutBooking_CreatesToken() throws Exception {
        // Given
        Map<String, Object> claims = new HashMap<>();
        claims.put("wallet", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");

        // When
        String token = jwtService.generateToken(claims, null);

        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        verify(keyService).loadPrivateKey();
        verify(keyService).getPublicKey();
    }

    @Test
    void testGenerateToken_WithBooking_CreatesTokenWithBookingInfo() throws Exception {
        // Given
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", BigInteger.valueOf(42));
        bookingInfo.put("aud", "https://lab.example.com");
        bookingInfo.put("sub", "lab-credential");
        bookingInfo.put("nbf", BigInteger.valueOf(System.currentTimeMillis() / 1000));
        bookingInfo.put("exp", BigInteger.valueOf((System.currentTimeMillis() / 1000) + 3600));

        // When
        String token = jwtService.generateToken(null, bookingInfo);

        // Then
        assertNotNull(token);
        assertFalse(token.isEmpty());
        verify(keyService).loadPrivateKey();
        verify(keyService).getPublicKey();
    }

    @Test
    void testGenerateKid_GeneratesConsistentHash() {
        // Given
        BigInteger modulus = BigInteger.valueOf(12345);

        // When
        String kid1 = JwtService.generateKid(modulus);
        String kid2 = JwtService.generateKid(modulus);

        // Then
        assertNotNull(kid1);
        assertEquals(kid1, kid2); // Should be deterministic
        assertEquals(64, kid1.length()); // SHA-256 produces 64 hex characters
    }

    @Test
    void testBase64UrlEncode_EncodesCorrectly() {
        // Given
        BigInteger value = BigInteger.valueOf(12345);

        // When
        String encoded = JwtService.base64UrlEncode(value);

        // Then
        assertNotNull(encoded);
        assertFalse(encoded.isEmpty());
        assertFalse(encoded.contains("+")); // Base64URL shouldn't have +
        assertFalse(encoded.contains("/")); // Base64URL shouldn't have /
        assertFalse(encoded.contains("=")); // Should be without padding
    }
}
