package decentralabs.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtBuilder;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;
import java.util.UUID;

import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import lombok.Getter;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;

import decentralabs.auth.contract.Diamond;


@RestController
@RequestMapping("")
public class AuthController {

    @Value("${contract.address}")
    private String contractAddress;
    @Value("${rpc.url}")
    private String rpcUrl;
    @Value("${base.domain}")
    private String baseDomain;
    @Value("${server.servlet.context-path}")
    private String contextPath;
    @Value("${endpoint.auth2}")
    private String auth2Endpoint;
    @Value("${endpoint.jwks}")
    private String jwksEndpoint;
    @Value("${endpoint.guacamole}")
    private String guacamoleEndpoint;
    @Value("${marketplace.public-key-url}")
    private String marketplacePublicKeyUrl;

    @Autowired
    private final KeyService keyService;

    private Map<String, Long> walletTimestamps;
    
    // Cache for marketplace public key
    private PublicKey cachedMarketplacePublicKey;
    private long lastKeyFetchTime = 0;
    private static final long KEY_CACHE_DURATION = 86400000; // 24 hours in milliseconds

    @Autowired
    public AuthController(KeyService keyService) {
        this.walletTimestamps = new HashMap<>();
        Web3j.build(new HttpService(rpcUrl));
        this.keyService = keyService;
    }
    
    /**
     * Helper method to construct the issuer URL from base domain and context path
     */
    private String getIssuerUrl() {
        return baseDomain + contextPath;
    }
    


    /*
     * END POINTS
     */

    ///// JWK ENDPOINTS /////

    // Endpoint to expose the other endpoints for OpenID Connect
    // /auth/.well-known/openid-configuration
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, String>> openidConfig() {
        String issuerUrl = getIssuerUrl();
        Map<String, String> config = new HashMap<>();
        config.put("issuer", issuerUrl);
        config.put("authorization_endpoint", issuerUrl + auth2Endpoint);
        config.put("jwks_uri", issuerUrl + jwksEndpoint);
        return ResponseEntity.ok(config);
    }

    // Endpoint to retrieve the public key in JWKS format (OpenID Connect standard)
    // /auth/jwks
    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> getJWKS() {
        try {
            RSAPublicKey publicKey = keyService.getPublicKey();

            // Obtain modulus (n) end exponent (e) in Base64URL (NOT normal Base64)
            BigInteger modulus = publicKey.getModulus();
            String modulusBase64Url = base64UrlEncode(modulus);
            String exponentBase64Url = base64UrlEncode(publicKey.getPublicExponent());    
            
            String kid = generateKid(modulus); 

            // Build JWKS response
            Map<String, Object> key = new HashMap<>();
            key.put("kty", "RSA");
            key.put("alg", "RS256");
            key.put("use", "sig");
            key.put("n", modulusBase64Url);
            key.put("e", exponentBase64Url);
            key.put("kid", kid);

            Map<String, Object> response = new HashMap<>();
            response.put("keys", Collections.singletonList(key));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500)
                .body(Collections.singletonMap("error", 
                "Failed to process the public key"));
        }
    }

    ///// WALLET AUTHENTICATION ENDPOINTS /////

    // Endpoint to generate the message that must be signed with a wallet
    // /auth/message
    @PostMapping("/message")
    public ResponseEntity<Map<String, String>> generateMessage(@RequestBody Request request) {
        String wallet = request.getWallet();
        long timestamp = System.currentTimeMillis() / 1000;
        String message = wallet + ":" + timestamp;
        walletTimestamps.put(wallet, timestamp);

        Map<String, String> response = new HashMap<>();
        response.put("message", message);

        return ResponseEntity.ok(response);
    }

    /* Endpoint to verify the signature, check bookings on blockchain and return the JWT
       It provides authentication and authorization */
    // /auth/auth2   
    @PostMapping("/auth2")
    public String auth2(@RequestBody Request request) {
        return handleWalletAuthentication(request, true);
    }

    /* Endpoint to verify the signature and return the JWT
       It only provides authentication */
    // /auth/auth
    @PostMapping("/auth")
    public String auth(@RequestBody Request request) {
        return handleWalletAuthentication(request, false);
    }



    ///// MARKETPLACE JWT AUTHENTICATION ENDPOINTS /////

    /* Endpoint to authenticate user from marketplace with signed JWT, check bookings and return JWT
       It provides authentication and authorization for marketplace users */
    // /auth/marketplace-auth2
    @PostMapping("/marketplace-auth2")
    public String marketplaceAuth2(@RequestBody MarketplaceRequest request) {
        return handleMarketplaceJwtAuthentication(request, true);
    }

    /* Endpoint to authenticate user from marketplace with signed JWT and return JWT
       It only provides authentication for marketplace users */
    // /auth/marketplace-auth
    @PostMapping("/marketplace-auth")
    public String marketplaceAuth(@RequestBody MarketplaceRequest request) {
        return handleMarketplaceJwtAuthentication(request, false);
    }



    /*
     * METHODS
     */

    private static String base64UrlEncode(BigInteger value) {
        byte[] bytes = value.toByteArray();

        // If the first byte is 0x00, delete it (to make it compatible with OpenSSL)
        if (bytes.length > 1 && bytes[0] == 0x00) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String handleWalletAuthentication(Request request, boolean includeBookingInfo) {
        try {
            // Validate required parameters
            if (request.getWallet() == null || request.getSignature() == null) {
                return "{\"error\": \"Missing wallet or signature.\"}";
            }
            
            // For booking validation, require either reservationKey OR labId
            if (includeBookingInfo && 
                (request.getReservationKey() == null || request.getReservationKey().isEmpty()) &&
                (request.getLabId() == null || request.getLabId().isEmpty())) {
                return "{\"error\": \"Missing reservationKey or labId for booking validation.\"}";
            }

            String wallet = request.getWallet();
            String signature = request.getSignature();
            String reservationKey = request.getReservationKey();
            String labId = request.getLabId();

            // Validate timestamp
            Long storedTimestamp = walletTimestamps.get(wallet);
            if (storedTimestamp == null || isTimestampExpired(storedTimestamp)) {
                return 
                "{\"error\": \"Timestamp not found or expired. Please request a new message.\"}";
            }

            // Verify signature
            if (!verifySignature(wallet, signature, storedTimestamp)) {
                return "{\"error\": \"Invalid signature\"}";
            }

            // Gather claims and generate JWT
            Map<String, Object> bookingInfo = includeBookingInfo ? 
                getBookingInfoFromWallet(wallet, reservationKey, labId) 
                : null;
            Map<String, Object> claims = new HashMap<>();
            claims.put("wallet", wallet);
            String jwt = generateToken(claims, bookingInfo);
            
            String labUrl = bookingInfo != null ? (String) bookingInfo.get("aud") : null;
            
            // Return token and URL in JSON format
            return "{\"token\": \"" + jwt + "\"" +
                    (labUrl != null ? ", \"labURL\": \"" + labUrl + "\"" : "") +
                    "}";
        } catch (SecurityException | IllegalStateException e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        } catch (Exception e) {
            System.err.println("Authentication error: " + e.getMessage());
            e.printStackTrace();
            return "{\"error\": \"Internal server error\"}";
        }
    }

    private boolean isTimestampExpired(Long timestamp) {
        long currentTime = System.currentTimeMillis() / 1000;
        return currentTime - timestamp > 600; // 10 minutes
    }
    
    // Method to verify the signature of the message
    private boolean verifySignature(String wallet, String signature, long timestamp) {
        String ethPrefix = "\u0019Ethereum Signed Message:\n";
        try {
            String rawMessage = wallet + ":" + timestamp;
            String message = ethPrefix + rawMessage.length() + rawMessage;
            String recoveredAddress = recoverAddressFromSignature(message, signature);        
            return wallet.equalsIgnoreCase(recoveredAddress);
        } catch (Exception e) {
            return false;
        }
    }

    // Method to recover the wallet address from the signature
    private String recoverAddressFromSignature(String message, String signature) 
    throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        
        // Web3j 5.x: Manual signature parsing
        // Signature format: 0x + r(64) + s(64) + v(2) = 132 chars
        if (signature.startsWith("0x")) {
            signature = signature.substring(2);
        }
        
        byte[] r = org.web3j.utils.Numeric.hexStringToByteArray(signature.substring(0, 64));
        byte[] s = org.web3j.utils.Numeric.hexStringToByteArray(signature.substring(64, 128));
        byte v = (byte) Integer.parseInt(signature.substring(128, 130), 16);
        
        // Normalize v (27/28 → 0/1)
        if (v < 27) {
            v = (byte) (v + 27);
        }
        
        Sign.SignatureData sigData = new Sign.SignatureData(v, r, s);
        BigInteger publicKey = Sign.signedMessageToKey(messageBytes, sigData);
        String recoveredAddress = "0x" + org.web3j.crypto.Keys.getAddress(publicKey);
    
        return recoveredAddress;
    }

    // Method to generate the JWT token using the RSA key
    private String generateToken(Map<String, Object> claims, Map<String, Object> bookingInfo) throws Exception {
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
            claims.forEach(jwtBuilder::claim); // TODO: rename claims to match JWT standard
        }
        if (labId != null) {
            jwtBuilder.claim("labId", labId.intValue());
        }
    
        PrivateKey privateKey = keyService.loadPrivateKey();
        return jwtBuilder.signWith(privateKey).compact();
    }

    private static String generateKid(BigInteger modulus) {
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
     * Retrieves booking information from blockchain for a wallet
     * Supports two modes:
     * 1. Direct access with reservationKey (more efficient - O(1) lookup)
     * 2. Search by labId if reservationKey not provided (less efficient - O(n) search)
     * 
     * @param wallet The user's wallet address
     * @param reservationKey Optional - the reservation key as hex string (bytes32)
     * @param labId Optional - the lab ID to search for (required if reservationKey not provided)
     * @return Map containing booking information for JWT claims
     */
    public Map<String, Object> getBookingInfoFromWallet(String wallet, String reservationKey, String labId) {
        try {           
            // Determine which method to use based on available parameters
            if (reservationKey != null && !reservationKey.isEmpty()) {
                // OPTIMAL PATH: Use reservationKey for direct O(1) access
                return getBookingInfoByReservationKey(wallet, reservationKey);
            } else if (labId != null && !labId.isEmpty()) {
                // FALLBACK PATH: Search by labId (requires iteration)
                return getBookingInfoByLabId(wallet, labId);
            } else {
                throw new IllegalArgumentException(
                    "Must provide either 'reservationKey' (recommended) or 'labId'"
                );
            }
        } catch (SecurityException | IllegalStateException | IllegalArgumentException e) {
            // Re-throw validation errors as-is
            throw e;
        } catch (Exception e) {
            System.err.println("Error fetching booking info: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(
                "Failed to retrieve booking information from blockchain: " + e.getMessage(),
                e
            );
        }
    }
    
    /**
     * Retrieves booking info using reservationKey directly (OPTIMAL - 2 blockchain calls)
     * Call flow: getReservation(key) → getLab(tokenId)
     */
    private Map<String, Object> getBookingInfoByReservationKey(String wallet, String reservationKeyHex) 
            throws Exception {
        
        // 1. Convert reservationKey from hex to bytes32
        byte[] reservationKeyBytes = hexStringToByteArray(reservationKeyHex);
        
        // 2. Load the Diamond contract
        Web3j web3 = Web3j.build(new HttpService(rpcUrl));
        Diamond diamond = Diamond.load(
            contractAddress,
            web3,
            new ReadonlyTransactionManager(web3, wallet),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );

        // 3. Get reservation data (ONE CALL) - returns Reservation struct
        Diamond.Reservation reservation = diamond.getReservation(reservationKeyBytes).send();
        
        BigInteger labId = reservation.labId;      // NOT tokenId, it's labId!
        String renter = reservation.renter;
        BigInteger price = reservation.price;
        BigInteger start = reservation.start;
        BigInteger end = reservation.end;
        BigInteger status = reservation.status;

        // 4. Validate reservation
        validateReservation(wallet, renter, status, start, end);

        // 5. Get lab information (ONE CALL)
        Diamond.Lab lab = diamond.getLab(labId).send();
        Diamond.LabBase base = lab.base;
        
        String metadata = base.uri;
        BigInteger labPrice = base.price;
        String authURI = base.auth;
        String accessURI = base.accessURI;
        String accessKey = base.accessKey;

        // 6. Build and return booking info
        return buildBookingInfo(
            labId, reservationKeyHex, price, labPrice, 
            start, end,
            accessURI, accessKey, metadata, authURI
        );
    }

    /**
     * Retrieves booking info by labId using direct contract lookup
     * Call flow: getActiveReservationKeyForUser(tokenId, address) → getReservation(key) → getLab(tokenId)
     */
    private Map<String, Object> getBookingInfoByLabId(String wallet, String labIdStr) throws Exception {
        
        BigInteger labId = new BigInteger(labIdStr);
        Web3j web3 = Web3j.build(new HttpService(rpcUrl));
        
        // 1. Load Diamond contract
        Diamond diamond = Diamond.load(
            contractAddress, web3,
            new ReadonlyTransactionManager(web3, wallet),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );

        // 2. Get active reservation key
        byte[] reservationKeyBytes = diamond.getActiveReservationKeyForUser(labId, wallet).send();
        
        // Check if reservation exists (bytes32(0) means no active reservation)
        if (reservationKeyBytes == null || isEmptyBytes32(reservationKeyBytes)) {
            throw new IllegalStateException(
                "No active reservation found for lab " + labIdStr + " and wallet " + wallet
            );
        }

        // 3. Get reservation data
        Diamond.Reservation reservation = diamond.getReservation(reservationKeyBytes).send();
        
        String renter = reservation.renter;
        BigInteger price = reservation.price;
        BigInteger start = reservation.start;
        BigInteger end = reservation.end;
        BigInteger status = reservation.status;

        // 4. Validate reservation
        validateReservation(wallet, renter, status, start, end);

        // 5. Get lab information (ONE CALL)
        Diamond.Lab lab = diamond.getLab(labId).send();
        Diamond.LabBase base = lab.base;
        
        String metadata = base.uri;
        BigInteger labPrice = base.price;
        String authURI = base.auth;
        String accessURI = base.accessURI;
        String accessKey = base.accessKey;

        // 6. Convert reservationKey to hex for response
        String reservationKeyHex = bytesToHex(reservationKeyBytes);

        // 7. Build and return booking info
        return buildBookingInfo(
            labId, reservationKeyHex, price, labPrice,
            start, end,
            accessURI, accessKey, metadata, authURI
        );
    }
    
    /**
     * Helper method to check if bytes32 is empty (all zeros)
     */
    private boolean isEmptyBytes32(byte[] bytes) {
        if (bytes == null || bytes.length != 32) {
            return true;
        }
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validates reservation ownership, status, and time validity
     */
    private void validateReservation(String wallet, String renter, BigInteger status, 
                                     BigInteger start, BigInteger end) {
        // Validate ownership
        if (!renter.equalsIgnoreCase(wallet)) {
            throw new SecurityException(
                "Reservation does not belong to this wallet. Expected: " + wallet + ", Found: " + renter
            );
        }

        // Validate status (1 = ACTIVE)
        if (!status.equals(BigInteger.ONE)) {
            String statusStr = status.equals(BigInteger.ZERO) ? "INACTIVE" : 
                             status.equals(BigInteger.TWO) ? "CANCELLED" : "UNKNOWN";
            throw new IllegalStateException("Reservation is not active. Status: " + statusStr);
        }

        // Validate time range
        BigInteger currentTime = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        
        if (currentTime.compareTo(start) < 0) {
            throw new IllegalStateException(
                "Reservation has not started yet. Start: " + start + ", Current: " + currentTime
            );
        }
        
        if (currentTime.compareTo(end) > 0) {
            throw new IllegalStateException(
                "Reservation has expired. End: " + end + ", Current: " + currentTime
            );
        }
    }

    /**
     * Builds the bookingInfo map for JWT claims
     */
    private Map<String, Object> buildBookingInfo(
            BigInteger labId, String reservationKeyHex,
            BigInteger price, BigInteger labPrice,
            BigInteger start, BigInteger end,
            String accessURI, String accessKey, String metadata, String authURI) {
        
        Map<String, Object> bookingInfo = new HashMap<>();
        
        // JWT Standard Claims
        bookingInfo.put("aud", accessURI);       // Audience - where token is used
        bookingInfo.put("sub", accessKey);       // Subject - username for access
        bookingInfo.put("nbf", start);           // Not Before - reservation start
        bookingInfo.put("exp", end);             // Expiration - reservation end
        
        // Custom Claims
        bookingInfo.put("lab", labId);                      // Lab ID
        bookingInfo.put("reservationKey", reservationKeyHex); // For reference
        bookingInfo.put("price", price);                    // Price paid
        bookingInfo.put("labPrice", labPrice);              // Lab base price
        bookingInfo.put("metadata", metadata);              // Lab metadata URI
        bookingInfo.put("authURI", authURI);                // This auth service

        return bookingInfo;
    }

    /**
     * Helper method to convert hex string to byte array
     */
    private byte[] hexStringToByteArray(String hex) {
        // Remove "0x" prefix if present
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Helper method to convert byte array to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder("0x");
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public Map<String, Object> getBookingInfoFromSAML2(String userid, String affiliation, String labId) {
        // TODO: Load the smart contract
        /* ReservationContract contract = ReservationContract.load(
                contractAddress, web3, new ReadonlyTransactionManager(web3, wallet),
                new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );*/

        // Generate temporary test credentials
        String aud = baseDomain + guacamoleEndpoint;
        String sub = "JWTtest";
        BigInteger nbf = BigInteger.valueOf(System.currentTimeMillis() / 1000)
                        .subtract(BigInteger.valueOf(300));
        BigInteger exp = BigInteger.valueOf(System.currentTimeMillis() / 1000)
                        .add(BigInteger.valueOf(300));

        // Wrap the data received from the contract in a JSON Map
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", labId);
        bookingInfo.put("aud", aud);
        bookingInfo.put("sub", sub);
        bookingInfo.put("nbf", nbf);
        bookingInfo.put("exp", exp);

        return bookingInfo;
    }

    private String handleMarketplaceJwtAuthentication(MarketplaceRequest request, boolean includeBookingInfo) {
        try {
            // Validate required parameters
            if (request.getMarketplaceToken() == null || 
                (includeBookingInfo && request.getLabId() == null)) {
                return "{\"error\": \"Missing parameters.\"}";
            }

            // Validate timestamp to prevent replay attacks
            if (isMarketplaceTimestampExpired(request.getTimestamp())) {
                return "{\"error\": \"Request timestamp expired.\"}";
            }

            // Validate and extract claims from marketplace JWT
            Map<String, Object> claims = validateAndExtractMarketplaceJWT(request.getMarketplaceToken());
            if (claims == null || claims.isEmpty()) {
                return "{\"error\": \"Invalid marketplace token or could not extract user information.\"}";
            }

            // Gather booking info if required
            Map<String, Object> bookingInfo = includeBookingInfo ? 
                getBookingInfoFromSAML2(
                    claims.get("id") != null ? claims.get("id").toString() : "", 
                    claims.get("affiliation") != null ? claims.get("affiliation").toString() : "",
                    request.getLabId())
                : null;

            // Generate JWT
            String jwt = generateToken(claims, bookingInfo);
            String labUrl = bookingInfo != null ? (String) bookingInfo.get("aud") : null;

            // Return token and URL in JSON format
            return "{\"token\": \"" + jwt + "\"" +
                    (labUrl != null ? ", \"labURL\": \"" + labUrl + "\"" : "") +
                    "}";

        } catch (Exception e) {
            e.printStackTrace();
            return "{\"error\": \"Internal server error processing marketplace request.\"}";
        }
    }

    private boolean isMarketplaceTimestampExpired(long timestamp) {
        long currentTime = System.currentTimeMillis() / 1000;
        return currentTime - timestamp > 300; // 5 minutes for marketplace requests
    }

    /**
     * Validates the JWT token from marketplace and extracts user claims
     * This provides cryptographic guarantee that the token comes from the trusted marketplace
     */
    private Map<String, Object> validateAndExtractMarketplaceJWT(String marketplaceToken) {
        return validateAndExtractMarketplaceJWT(marketplaceToken, false);
    }
    
    /**
     * Validates JWT with retry logic for key refresh on signature failures
     */
    private Map<String, Object> validateAndExtractMarketplaceJWT(String marketplaceToken, boolean isRetry) {
        try {
            // Get marketplace public key
            PublicKey publicKey = getMarketplacePublicKey(isRetry);
            if (publicKey == null) {
                return null;
            }

            // Validate and parse JWT
            @SuppressWarnings("deprecation")
            Claims claims = Jwts.parser()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(marketplaceToken)
                .getBody();

            // Extract user information from JWT claims
            Map<String, Object> userClaims = new HashMap<>();
            
            // Standard JWT claims
            userClaims.put("username", claims.getSubject());
            if (claims.get("email") != null) {
                userClaims.put("email", claims.get("email"));
            }
            
            // Custom claims from SAML2 attributes
            if (claims.get("uid") != null) {
                userClaims.put("id", claims.get("uid"));
            }
            if (claims.get("displayName") != null) {
                userClaims.put("name", claims.get("displayName"));
            }
            if (claims.get("schacHomeOrganization") != null) {
                userClaims.put("affiliation", claims.get("schacHomeOrganization"));
            }
            if (claims.get("eduPersonAffiliation") != null) {
                userClaims.put("role", claims.get("eduPersonAffiliation"));
            }
            if (claims.get("eduPersonScopedAffiliation") != null) {
                userClaims.put("scopedRole", claims.get("eduPersonScopedAffiliation"));
            }

            return userClaims;

        } catch (io.jsonwebtoken.security.SignatureException e) {
            // Signature validation failed - try refreshing the key once
            if (!isRetry) {
                System.err.println("JWT signature validation failed, attempting key refresh: " + e.getMessage());
                return validateAndExtractMarketplaceJWT(marketplaceToken, true);
            }
            System.err.println("JWT signature validation failed even after key refresh: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("JWT validation error: " + e.getMessage());
            return null; // Invalid token
        }
    }
    
    /**
     * Fetches the marketplace public key with optional cache bypass
     * @param forceRefresh if true, bypasses cache and fetches fresh key
     */
    private PublicKey getMarketplacePublicKey(boolean forceRefresh) {
        try {
            long currentTime = System.currentTimeMillis();
            
            // Return cached key if valid and not forcing refresh
            if (!forceRefresh && 
                cachedMarketplacePublicKey != null && 
                (currentTime - lastKeyFetchTime) < KEY_CACHE_DURATION) {
                return cachedMarketplacePublicKey;
            }
            
            // Fetch key from URL
            PublicKey freshKey = fetchPublicKeyFromUrl();
            if (freshKey != null) {
                cachedMarketplacePublicKey = freshKey;
                lastKeyFetchTime = currentTime;
                return freshKey;
            }
            
            // If fetch failed and we have a cached key, use it as fallback
            if (cachedMarketplacePublicKey != null) {
                return cachedMarketplacePublicKey;
            }
            
            return null;
            
        } catch (Exception e) {
            e.printStackTrace();
            // Return cached key as fallback if available
            return cachedMarketplacePublicKey;
        }
    }
    
    /**
     * Fetches the public key from the marketplace URL
     */
    private PublicKey fetchPublicKeyFromUrl() {
        try {
            if (marketplacePublicKeyUrl == null || marketplacePublicKeyUrl.isEmpty()) {
                return null;
            }
            
            RestTemplate restTemplate = new RestTemplate();
            String publicKeyPem = restTemplate.getForObject(marketplacePublicKeyUrl, String.class);
            
            if (publicKeyPem == null || publicKeyPem.isEmpty()) {
                return null;
            }
            
            // Remove PEM headers and whitespace
            String cleanedPem = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

            // Decode and create public key
            byte[] keyBytes = Base64.getDecoder().decode(cleanedPem);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            return keyFactory.generatePublic(keySpec);
            
        } catch (RestClientException e) {
            System.err.println("Failed to fetch public key from URL: " + marketplacePublicKeyUrl + " - " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("Error processing public key from URL: " + e.getMessage());
            return null;
        }
    }

    /**
     * Public method to check if marketplace public key is available (for health checks)
     */
    public boolean isMarketplacePublicKeyAvailable() {
        try {
            PublicKey key = getMarketplacePublicKey(false);
            return key != null;
        } catch (Exception e) {
            return false;
        }
    }



    /*
     * CLASSES
     */

    // General class to represent the request body from the marketplace when using wallet authentication
    @Getter
    static class Request {
        private String wallet;
        private String signature;
        private String labId;              // Lab ID - required if reservationKey not provided
        private String reservationKey;     // Optional - more efficient if provided (bytes32 as hex string)
    }

    // Class to represent requests from marketplace with signed JWT authentication
    @Getter
    static class MarketplaceRequest {
        private String marketplaceToken;   // JWT signed by marketplace containing user info
        private String labId;              // Lab ID for booking validation
        private long timestamp;            // Timestamp to prevent replay attacks
    }

}