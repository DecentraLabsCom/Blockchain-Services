package decentralabs.auth;

//import decentralabs.auth.ReservationContract;
/*
 * web3j generate solidity -b path/to/contract.bin -a path/to/contract.abi -o /path/to/output/folder -p decentralabs.auth
 * contract.bin: The compiled bytecode of your smart contract.
 * contract.abi: The ABI (Application Binary Interface) of your contract.
 */

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
import org.web3j.tuples.generated.Tuple4;
import org.web3j.tuples.generated.Tuple6;
import org.web3j.tuples.generated.Tuple7;


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
            if (request.getWallet() == null || 
                request.getSignature() == null || 
                request.getLabId() == null) {
                    return "{\"error\": \"Missing parameters.\"}";
            }

            String wallet = request.getWallet();
            String signature = request.getSignature();
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
                getBookingInfoFromWallet(wallet, labId) 
                : null;
            Map<String, Object> claims = new HashMap<>();
            claims.put("wallet", wallet);
            String jwt = generateToken(claims, bookingInfo);
            
            String labUrl = bookingInfo != null ? (String) bookingInfo.get("aud") : null;
            
            // Return token and URL in JSON format
            return "{\"token\": \"" + jwt + "\"" +
                    (labUrl != null ? ", \"labURL\": \"" + labUrl + "\"" : "") +
                    "}";
        } catch (Exception e) {
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
        Sign.SignatureData sigData = Sign.signatureDataFromHex(signature);
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
   
    public Map<String, Object> getBookingInfoFromWallet(String wallet, String labId) {
        // TODO: Load the smart contract
        /* ReservationContract contract = ReservationContract.load(
                contractAddress, web3, new ReadonlyTransactionManager(web3, wallet),
                new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );

        // Get all reservations registered onchain
        Typle7<Bytes, BigInteger, String, BigInteger, BigInteger, BigInteger, BigInteger> reservations = 
            contract.getAllReservations(wallet).send(); */
        // TODO: loop through reservations and keep the closest one with the right labId, renter and status 1
        Tuple7<BigInteger, BigInteger, String, BigInteger, BigInteger, BigInteger, BigInteger> reservation = 
            new Tuple7<>(
                new BigInteger("1"),                                // reservationKey
                new BigInteger("1"),                                // labId
                "0x1234567890abcdef1234567890abcdef12345678",    // renter
                new BigInteger("2"),                                // price
                BigInteger.valueOf(System.currentTimeMillis() / 1000)
                            .subtract(BigInteger.valueOf(300)),     // start
                BigInteger.valueOf(System.currentTimeMillis() / 1000)
                            .add(BigInteger.valueOf(300)),          // end
                new BigInteger("1")                                 // status
            );

        /* Get other info for the JWT claims: lab access URI (aud) and username for accessing
        the lab (sub)
        Tuple6<BigInteger, String, BigInteger, String, String, String> lab = 
            contract.getLab(reservation.component2()).send(); */
        Tuple6<BigInteger, String, BigInteger, String, String, String> lab = new Tuple6<>(
            new BigInteger("1"),                                    // labId
            "https://metadata",                                  // metadata
            new BigInteger("2"),                                    // price
            getIssuerUrl() + auth2Endpoint,                      // authURI
            baseDomain + guacamoleEndpoint,                      // accessURI
            "JWTtest"                                            // accessKey
        );

        // Wrap the data received from the contract in a JSON Map
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", labId);
        bookingInfo.put("aud", lab.component5());
        bookingInfo.put("sub", lab.component6());
        bookingInfo.put("nbf", reservation.component5());
        bookingInfo.put("exp", reservation.component6());

        return bookingInfo;
    }

    public Map<String, Object> getBookingInfoFromSAML2(String userid, String affiliation, String labId) {
        // TODO: Load the smart contract
        /* ReservationContract contract = ReservationContract.load(
                contractAddress, web3, new ReadonlyTransactionManager(web3, wallet),
                new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );*/

        Tuple4<String, String, BigInteger, BigInteger> info = new Tuple4<>(
            baseDomain + guacamoleEndpoint,
            "JWTtest",
            BigInteger.valueOf(System.currentTimeMillis() / 1000)
                        .subtract(BigInteger.valueOf(300)),
            BigInteger.valueOf(System.currentTimeMillis() / 1000)
                        .add(BigInteger.valueOf(300))
        );

        // Wrap the data received from the contract in a JSON Map
        Map<String, Object> bookingInfo = new HashMap<>();
        bookingInfo.put("lab", labId);
        bookingInfo.put("aud", info.component1());
        bookingInfo.put("sub", info.component2());
        bookingInfo.put("nbf", info.component3());
        bookingInfo.put("exp", info.component4());

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



    /*
     * CLASSES
     */

    // General class to represent the request body from the marketplace when using wallet authentication
    @Getter
    static class Request {
        private String wallet;
        private String signature;
        private String labId;
    }

    // Class to represent requests from marketplace with signed JWT authentication
    @Getter
    static class MarketplaceRequest {
        private String marketplaceToken;   // JWT signed by marketplace containing user info
        private String labId;              // Lab ID for booking validation
        private long timestamp;            // Timestamp to prevent replay attacks
    }

}