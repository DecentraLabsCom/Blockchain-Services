package decentralabs.blockchain.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.AuthResponse;
import decentralabs.blockchain.dto.WalletAuthRequest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for wallet-based authentication
 */
@Service
public class WalletAuthService {
    
    private static final long TIMESTAMP_EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes
    
    @Autowired
    private BlockchainBookingService blockchainService;
    
    @Autowired
    private JwtService jwtService;
    
    // Track used timestamps to prevent replay attacks
    private final Map<String, Long> walletTimestamps = new ConcurrentHashMap<>();
    
    /**
     * Handles wallet authentication request
     * 
     * @param request Wallet authentication request
     * @param includeBookingInfo Whether to include booking information in the token
     * @return Authentication response with JWT token
     * @throws Exception if validation or token generation fails
     */
    public AuthResponse handleAuthentication(WalletAuthRequest request, boolean includeBookingInfo) throws Exception {
        String wallet = request.getWallet();
        String signature = request.getSignature();
        String labId = request.getLabId();
        String reservationKey = request.getReservationKey();
        
        // Validate required fields
        if (wallet == null || wallet.isEmpty() || signature == null || signature.isEmpty()) {
            throw new IllegalArgumentException("Missing wallet or signature");
        }

        // Get timestamp from signature (last 13 characters as timestamp in hex)
        String timestampHex = signature.substring(signature.length() - 13);
        long timestamp = Long.parseLong(timestampHex, 16);

        if (isTimestampExpired(timestamp)) {
            throw new IllegalArgumentException("Timestamp has expired");
        }

        // Verify the signature
        boolean signatureValid = verifySignature(wallet, signature, timestamp);
        if (!signatureValid) {
            throw new SecurityException("Invalid signature");
        }

        // Check for replay attack
        String timestampKey = wallet + "-" + timestamp;
        if (walletTimestamps.containsKey(timestampKey)) {
            throw new SecurityException("Timestamp already used (replay attack detected)");
        }
        walletTimestamps.put(timestampKey, System.currentTimeMillis());
        
        // Clean old timestamps (older than expiration time)
        cleanExpiredTimestamps();
        
        // Generate JWT token
        if (includeBookingInfo) {
            // Get booking information from blockchain
            Map<String, Object> bookingInfo = blockchainService.getBookingInfo(wallet, reservationKey, labId);
            String token = jwtService.generateToken(null, bookingInfo);
            String labURL = (String) bookingInfo.get("labURL");
            return new AuthResponse(token, labURL);
        } else {
            // Generate simple token with wallet as claim
            Map<String, Object> claims = new HashMap<>();
            claims.put("wallet", wallet);
            String token = jwtService.generateToken(claims, null);
            return new AuthResponse(token);
        }
    }

    /**
     * Verifies the wallet signature
     * 
     * @param expectedAddress Expected wallet address
     * @param fullSignature Full signature string (includes timestamp)
     * @param timestamp Timestamp value
     * @return true if signature is valid
     */
    private boolean verifySignature(String expectedAddress, String fullSignature, long timestamp) {
        try {
            // Remove the timestamp from the signature (last 13 characters)
            String signatureWithoutTimestamp = fullSignature.substring(0, fullSignature.length() - 13);
            
            // Message that was signed: "Login request: [timestamp]"
            String message = "Login request: " + timestamp;
            
            // Recover address from signature
            String recoveredAddress = recoverAddressFromSignature(message, signatureWithoutTimestamp);
            
            // Compare addresses (case insensitive)
            return expectedAddress.equalsIgnoreCase(recoveredAddress);
        } catch (Exception e) {
            System.err.println("Signature verification failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Recovers the Ethereum address from a message and signature using Web3j 5.x
     * 
     * @param message Original message that was signed
     * @param signatureHex Signature in hexadecimal format
     * @return Recovered Ethereum address
     * @throws SignatureException if recovery fails
     */
    private String recoverAddressFromSignature(String message, String signatureHex) throws SignatureException {
        // Prepare the Ethereum signed message
        String prefix = "\u0019Ethereum Signed Message:\n";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        String prefixedMessage = prefix + messageBytes.length + message;
        byte[] prefixedMessageBytes = prefixedMessage.getBytes(StandardCharsets.UTF_8);
        
        // Hash the prefixed message
        byte[] messageHash = org.web3j.crypto.Hash.sha3(prefixedMessageBytes);
        
        // Parse signature components
        byte[] signatureBytes = Numeric.hexStringToByteArray(signatureHex);
        
        if (signatureBytes.length != 65) {
            throw new SignatureException("Invalid signature length: " + signatureBytes.length);
        }
        
        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }
        
        byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
        byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);
        
        // Create SignatureData object
        Sign.SignatureData signatureData = new Sign.SignatureData(
            v,
            r,
            s
        );
        
        // Recover public key
        BigInteger publicKey = Sign.signedMessageHashToKey(messageHash, signatureData);
        
        // Derive address from public key
        return "0x" + Keys.getAddress(publicKey);
    }
    
    /**
     * Checks if a timestamp has expired
     */
    private boolean isTimestampExpired(long timestamp) {
        long currentTime = System.currentTimeMillis();
        return (currentTime - timestamp) > TIMESTAMP_EXPIRATION_MS;
    }
    
    /**
     * Removes expired timestamps from the tracking map
     */
    private void cleanExpiredTimestamps() {
        long currentTime = System.currentTimeMillis();
        walletTimestamps.entrySet().removeIf(entry -> 
            (currentTime - entry.getValue()) > TIMESTAMP_EXPIRATION_MS
        );
    }
}
