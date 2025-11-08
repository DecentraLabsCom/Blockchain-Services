package decentralabs.blockchain.service.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.WalletAuthRequest;
import decentralabs.blockchain.service.persistence.AntiReplayService;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WalletAuthServiceTest {

    @Mock
    private BlockchainBookingService blockchainService;

    @Mock
    private JwtService jwtService;
    
    @Mock
    private AntiReplayService antiReplayService;

    @InjectMocks
    private WalletAuthService walletAuthService;

    private WalletAuthRequest validRequest;
    private String validWallet;
    private String validSignature;
    private Credentials testCredentials;

    @BeforeEach
    void setUp() throws Exception {
        // Generate real ECDSA credentials for testing
        testCredentials = Credentials.create(Keys.createEcKeyPair());
        validWallet = testCredentials.getAddress();
        
        // Create a valid signature with current timestamp
        long timestamp = System.currentTimeMillis();
        String message = "Login request: " + timestamp;
        validSignature = createValidSignature(message, timestamp);
        
        validRequest = new WalletAuthRequest();
        validRequest.setWallet(validWallet);
        validRequest.setSignature(validSignature);
        
        // Mock antiReplayService to allow all timestamps (not testing replay here)
        lenient().when(antiReplayService.isTimestampUsed(anyString(), anyLong())).thenReturn(false);
    }
    
    /**
     * Creates a valid ECDSA signature for testing
     */
    private String createValidSignature(String message, long timestamp) {
        try {
            // Prepare Ethereum signed message
            String prefix = "\u0019Ethereum Signed Message:\n";
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            String prefixedMessage = prefix + messageBytes.length + message;
            byte[] prefixedMessageBytes = prefixedMessage.getBytes(StandardCharsets.UTF_8);
            
            // Hash the message
            byte[] messageHash = org.web3j.crypto.Hash.sha3(prefixedMessageBytes);
            
            // Sign the hash - use needToHash=false since we already hashed
            Sign.SignatureData signature = Sign.signMessage(messageHash, testCredentials.getEcKeyPair(), false);
            
            // Extract r, s, v - ensuring they are padded to correct lengths
            byte[] r = signature.getR();
            byte[] s = signature.getS();
            byte v = signature.getV()[0];
            
            // Pad r to 32 bytes if needed
            byte[] rPadded = new byte[32];
            int rOffset = 32 - r.length;
            System.arraycopy(r, 0, rPadded, rOffset, r.length);
            
            // Pad s to 32 bytes if needed
            byte[] sPadded = new byte[32];
            int sOffset = 32 - s.length;
            System.arraycopy(s, 0, sPadded, sOffset, s.length);
            
            // Ensure v is in the correct range (27 or 28)
            if (v < 27) {
                v += 27;
            }
            
            // Combine r, s, v into single byte array (65 bytes total)
            byte[] signatureBytes = new byte[65];
            System.arraycopy(rPadded, 0, signatureBytes, 0, 32);
            System.arraycopy(sPadded, 0, signatureBytes, 32, 32);
            signatureBytes[64] = v;
            
            // Convert to hex manually to preserve all leading zeros
            StringBuilder signatureHex = new StringBuilder();
            for (byte b : signatureBytes) {
                signatureHex.append(String.format("%02x", b));
            }
            
            String timestampHex = Long.toHexString(timestamp);
            
            // Pad timestamp to exactly 13 characters (service expects fixed length)
            while (timestampHex.length() < 13) {
                timestampHex = "0" + timestampHex;
            }
            
            return "0x" + signatureHex.toString() + timestampHex;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create signature: " + e.getMessage(), e);
        }
    }

    @Test
    void testHandleAuthentication_MissingWallet_ThrowsException() {
        // Given
        WalletAuthRequest request = new WalletAuthRequest();
        request.setSignature(validSignature);

        // When & Then
        assertThrows(IllegalArgumentException.class, () -> 
            walletAuthService.handleAuthentication(request, false)
        );
    }

    @Test
    void testHandleAuthentication_MissingSignature_ThrowsException() {
        // Given
        WalletAuthRequest request = new WalletAuthRequest();
        request.setWallet(validWallet);

        // When & Then
        assertThrows(IllegalArgumentException.class, () -> 
            walletAuthService.handleAuthentication(request, false)
        );
    }

    @Test
    void testHandleAuthentication_ExpiredTimestamp_ThrowsException() {
        // Given - create signature with expired timestamp (10 minutes ago)
        long expiredTimestamp = System.currentTimeMillis() - (10 * 60 * 1000);
        String expiredMessage = "Login request: " + expiredTimestamp;
        String expiredSignature = createValidSignature(expiredMessage, expiredTimestamp);
        
        validRequest.setSignature(expiredSignature);

        // When & Then - service throws IllegalArgumentException for expired timestamp (before signature validation)
        assertThrows(IllegalArgumentException.class, () -> 
            walletAuthService.handleAuthentication(validRequest, false)
        );
    }

    @Test
    void testHandleAuthentication_WithoutBooking_ReturnsToken() throws Exception {
        // Given
        when(jwtService.generateToken(anyMap(), isNull())).thenReturn("mock-jwt-token");

        // When
        AuthResponse response = walletAuthService.handleAuthentication(validRequest, false);

        // Then
        assertNotNull(response);
        assertEquals("mock-jwt-token", response.getToken());
        verify(jwtService).generateToken(anyMap(), isNull());
        verify(blockchainService, never()).getBookingInfo(anyString(), anyString(), anyString());
    }

    @Test
    void testHandleAuthentication_WithBooking_ReturnsTokenAndLabURL() throws Exception {
        // Given
        validRequest.setReservationKey("0x123");
        
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("labURL", "https://lab.example.com");
        bookingInfo.put("aud", "https://lab.example.com/guacamole");
        
        // Use anyString() for wallet since it's normalized to checksum format by service
        when(blockchainService.getBookingInfo(anyString(), eq("0x123"), isNull()))
            .thenReturn(bookingInfo);
        when(jwtService.generateToken(isNull(), eq(bookingInfo)))
            .thenReturn("mock-jwt-token-with-booking");

        // When
        AuthResponse response = walletAuthService.handleAuthentication(validRequest, true);

        // Then
        assertNotNull(response);
        assertEquals("mock-jwt-token-with-booking", response.getToken());
        assertEquals("https://lab.example.com", response.getLabURL());
        verify(blockchainService).getBookingInfo(anyString(), eq("0x123"), isNull());
        verify(jwtService).generateToken(isNull(), eq(bookingInfo));
    }
}
