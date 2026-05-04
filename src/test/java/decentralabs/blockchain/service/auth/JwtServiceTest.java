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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

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

    @Test
    void testGenerateToken_FmuBooking_IncludesResourceTypeAndAccessKey() throws Exception {
        // Given — booking where accessKey ends in .fmu → resourceType should be "fmu"
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", BigInteger.valueOf(99));
        bookingInfo.put("aud", "https://lab.example.com");
        bookingInfo.put("sub", "spring-damper.fmu");
        bookingInfo.put("nbf", BigInteger.valueOf(System.currentTimeMillis() / 1000));
        bookingInfo.put("exp", BigInteger.valueOf((System.currentTimeMillis() / 1000) + 3600));
        bookingInfo.put("accessKey", "spring-damper.fmu");
        bookingInfo.put("resourceType", "fmu");

        // When
        String token = jwtService.generateToken(null, bookingInfo);

        // Then — decode and verify custom claims
        assertNotNull(token);
        Claims claims = Jwts.parser()
                .verifyWith(mockPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        assertEquals("fmu", claims.get("resourceType", String.class));
        assertEquals("spring-damper.fmu", claims.get("accessKey", String.class));
        assertEquals(99, claims.get("labId", Integer.class));
    }

    @Test
    void testGenerateToken_FmuBooking_IncludesReservationKey() throws Exception {
        // Given — FMU booking with a reservationKey (the missing claim that blocked proxy.fmu download)
        String expectedReservationKey = "0x" + "ab".repeat(32);
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", BigInteger.valueOf(2));
        bookingInfo.put("aud", "https://sarlab.dia.uned.es");
        bookingInfo.put("sub", "BouncingBall.fmu");
        bookingInfo.put("nbf", BigInteger.valueOf(System.currentTimeMillis() / 1000));
        bookingInfo.put("exp", BigInteger.valueOf((System.currentTimeMillis() / 1000) + 900));
        bookingInfo.put("accessKey", "BouncingBall.fmu");
        bookingInfo.put("resourceType", "fmu");
        bookingInfo.put("reservationKey", expectedReservationKey);

        // When
        String token = jwtService.generateToken(null, bookingInfo);

        // Then — reservationKey must be present so the gateway can issue a proxy.fmu
        assertNotNull(token);
        Claims claims = Jwts.parser()
                .verifyWith(mockPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        assertEquals(expectedReservationKey, claims.get("reservationKey", String.class));
        assertEquals("fmu", claims.get("resourceType", String.class));
        assertEquals("BouncingBall.fmu", claims.get("accessKey", String.class));
    }

    @Test
    void testGenerateToken_NullReservationKey_OmitsClaimGracefully() throws Exception {
        // Given — booking without reservationKey (physical lab or missing field)
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", BigInteger.valueOf(1));
        bookingInfo.put("aud", "https://lab.example.com");
        bookingInfo.put("sub", "guacamole-user");
        bookingInfo.put("nbf", BigInteger.valueOf(System.currentTimeMillis() / 1000));
        bookingInfo.put("exp", BigInteger.valueOf((System.currentTimeMillis() / 1000) + 3600));
        bookingInfo.put("resourceType", "lab");
        // reservationKey intentionally absent

        // When
        String token = jwtService.generateToken(null, bookingInfo);

        // Then — reservationKey claim must not appear
        Claims claims = Jwts.parser()
                .verifyWith(mockPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        assertNull(claims.get("reservationKey"));
    }

    @Test
    void testGenerateToken_LabBooking_IncludesResourceTypeLab() throws Exception {
        // Given — regular lab booking (accessKey without .fmu)
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", BigInteger.valueOf(42));
        bookingInfo.put("aud", "https://lab.example.com");
        bookingInfo.put("sub", "guacamole-user");
        bookingInfo.put("nbf", BigInteger.valueOf(System.currentTimeMillis() / 1000));
        bookingInfo.put("exp", BigInteger.valueOf((System.currentTimeMillis() / 1000) + 3600));
        bookingInfo.put("accessKey", "guacamole-user");
        bookingInfo.put("resourceType", "lab");

        // When
        String token = jwtService.generateToken(null, bookingInfo);

        // Then
        Claims claims = Jwts.parser()
                .verifyWith(mockPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        assertEquals("lab", claims.get("resourceType", String.class));
        assertEquals("guacamole-user", claims.get("accessKey", String.class));
    }

    @Test
    void testGenerateToken_NoBooking_OmitsResourceType() throws Exception {
        // Given — wallet-only auth (no booking)
        Map<String, Object> claims = new HashMap<>();
        claims.put("wallet", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");

        // When
        String token = jwtService.generateToken(claims, null);

        // Then — resourceType should NOT be present
        Claims parsed = Jwts.parser()
                .verifyWith(mockPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        assertNull(parsed.get("resourceType"));
        assertNull(parsed.get("accessKey"));
    }
}
