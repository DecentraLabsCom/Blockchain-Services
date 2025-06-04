package decentralabs.auth;

//import decentralabs.auth.ReservationContract;
/*
 * web3j generate solidity -b path/to/contract.bin -a path/to/contract.abi -o /path/to/output/folder -p decentralabs.auth
 * contract.bin: The compiled bytecode of your smart contract.
 * contract.abi: The ABI (Application Binary Interface) of your contract.
 */

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtBuilder;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.UUID;

import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import javax.servlet.http.HttpServletResponse;
import lombok.Getter;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;

import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tuples.generated.Tuple4;
import org.web3j.tuples.generated.Tuple6;
import org.web3j.tuples.generated.Tuple7;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;


@RestController
@RequestMapping("")
public class AuthController {

    @Value("${contract.address}")
    private String contractAddress;
    @Value("${rpc.url}")
    private String rpcUrl;
    @Value("${issuer}")
    private String issuer;
    @Value("${serviceprovider.registration-id}")
    private String registrationId;

    @Autowired
    private final KeyService keyService;

    private Map<String, Long> walletTimestamps;
    private final Web3j web3;

    private final Saml2MetadataResolver metadataResolver;
    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    public AuthController(KeyService keyService,
                        Saml2MetadataResolver metadataResolver,
                        RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.walletTimestamps = new HashMap<>();
        this.web3 = Web3j.build(new HttpService(rpcUrl));
        this.keyService = keyService;
        this.metadataResolver = metadataResolver;
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }
    


    /*
     * END POINTS
     */

    ///// JWK ENDPOINTS /////

    // Endpoint to expose the other endpoints for OpenID Connect
    // /auth/.well-known/openid-configuration
    @GetMapping("/.well-known/openid-configuration")
    public ResponseEntity<Map<String, String>> openidConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("issuer", issuer);
        config.put("authorization_endpoint", issuer + "/auth2");
        config.put("jwks_uri", issuer + "/jwks");
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

    ///// SAML2 AUTHENTICATION ENDPOINTS /////

    // Endpoint to provide SAML2 metadata
    @GetMapping("/saml2-metadata")
    public void saml2Metadata(HttpServletResponse response) throws Exception {
        String metadata = metadataResolver.resolve(
            relyingPartyRegistrationRepository.findByRegistrationId(registrationId)
            );
        response.setContentType("application/xml");
        response.getWriter().write(metadata);
    }
  
    /* Endpoint to authenticate user through IdP, check bookings on blockchain and return the JWT
       It provides authentication and authorization */
    // /auth/saml2-auth2
    @PostMapping("/saml2-auth2")
    public String saml2Auth2(@RequestBody Request request) {
        return handleSamlAuthentication(request, true);
    }

    /* Endpoint to authenticate user through the IdP and return the JWT
       It only provides authentication */
    // /auth/saml2-auth
    @PostMapping("/saml2-auth")
    public String saml2Auth(@RequestBody Request request) {
        return handleSamlAuthentication(request, false);
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

    private String handleSamlAuthentication(Request request, boolean includeBookingInfo) {
        try {
            // Validate lab_url if required
            String labId = request != null ? request.getLabId() : null;
            if (!includeBookingInfo && labId == null) {
                return "{\"error\": \"Missing parameters.\"}";
            }

            // Get authentication from SecurityContext
            Authentication authentication = 
                    SecurityContextHolder.getContext().getAuthentication();
            if (!(authentication instanceof Saml2Authentication)) {
                return "{\"error\": \"Wrong authentication.\"}";
            }

            Saml2Authentication samlAuth = (Saml2Authentication) authentication;
            Saml2AuthenticatedPrincipal principal = 
                    (Saml2AuthenticatedPrincipal) samlAuth.getPrincipal();

            // Extract SAML2 attributes
            Map<String, Object> claims = extractSamlAttributes(principal);

            // Gather claims and generate JWT
            Map<String, Object> bookingInfo = includeBookingInfo ? 
                getBookingInfoFromSAML2(
                claims.get("id").toString(), 
                claims.get("affiliation").toString(),
                labId)
                : null;
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

    private Map<String, Object> extractSamlAttributes(Saml2AuthenticatedPrincipal principal) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", principal.getName());
        claims.put("id", 
            principal.getAttributes().getOrDefault("uid", List.of("")).get(0));
        claims.put("email", 
            principal.getAttributes().getOrDefault("email", List.of("")).get(0));
        claims.put("name", 
            principal.getAttributes().getOrDefault("displayName", List.of("")));
        claims.put("affiliation", 
            principal.getAttributes().getOrDefault("schacHomeOrganization", List.of("")));
        claims.put("role", 
            principal.getAttributes().getOrDefault("eduPersonAffiliation", List.of("")));
        claims.put("scopedRole", 
            principal.getAttributes().getOrDefault("eduPersonScopedAffiliation", List.of("")));
        return claims;
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
                .claim("iss", issuer)
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
            "https://sarlab.dia.uned.es/auth2",                  // authURI
            "https://sarlab.dia.uned.es/guacamole",              // accessURI
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
            "https://sarlab.dia.uned.es/guacamole",
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



    /*
     * CLASSES
     */

    // General class to represent the request body when using wallet or SSO authentication
    @Getter
    static class Request {
        private String wallet;
        private String signature;
        private String labId;
    }

}