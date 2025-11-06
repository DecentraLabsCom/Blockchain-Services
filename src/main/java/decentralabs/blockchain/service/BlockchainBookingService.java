package decentralabs.blockchain.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;

import decentralabs.blockchain.contract.Diamond;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for handling blockchain booking operations
 * Manages reservation lookups and validation from the Diamond smart contract
 */
@Service
public class BlockchainBookingService {

    @Value("${contract.address}")
    private String contractAddress;
    
    @Value("${rpc.url}")
    private String rpcUrl;
    
    @Value("${base.domain}")
    private String baseDomain;

    private static final BigInteger STATUS_PENDING = BigInteger.ZERO;
    private static final BigInteger STATUS_CONFIRMED = BigInteger.ONE;
    private static final BigInteger STATUS_IN_USE = BigInteger.valueOf(2);
    private static final BigInteger STATUS_COMPLETED = BigInteger.valueOf(3);
    private static final BigInteger STATUS_COLLECTED = BigInteger.valueOf(4);
    private static final BigInteger STATUS_CANCELLED = BigInteger.valueOf(5);

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
    public Map<String, Object> getBookingInfo(String wallet, String reservationKey, String labId) {
        return getBookingInfo(wallet, reservationKey, labId, null);
    }

    /**
     * Retrieves booking information from blockchain for a wallet, with optional institutional user filter.
     *
     * @param wallet        The wallet address (self-service user or institutional provider)
     * @param reservationKey Optional reservation key (hex). When provided, lookup is direct.
     * @param labId         The lab ID (required when reservationKey is absent)
     * @param puc           Optional schacPersonalUniqueCode to disambiguate institutional users
     * @return Map containing booking information
     */
    public Map<String, Object> getBookingInfo(String wallet, String reservationKey, String labId, String puc) {
        try {           
            // Determine which method to use based on available parameters
            if (reservationKey != null && !reservationKey.isEmpty()) {
                // OPTIMAL PATH: Use reservationKey for direct O(1) access
                return getBookingInfoByReservationKey(wallet, reservationKey);
            } else if (labId != null && !labId.isEmpty()) {
                // FALLBACK PATH: Search by labId (requires iteration)
                return getBookingInfoByLabId(wallet, labId, puc);
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
        
        BigInteger labId = reservation.labId;
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
     * Call flow: find active reservation for user by labId → getLab(tokenId)
     */
    private Map<String, Object> getBookingInfoByLabId(String wallet, String labIdStr, String puc) throws Exception {
        
        BigInteger labId = new BigInteger(labIdStr);
        Web3j web3 = Web3j.build(new HttpService(rpcUrl));
        
        // 1. Load Diamond contract
        Diamond diamond = Diamond.load(
            contractAddress, web3,
            new ReadonlyTransactionManager(web3, wallet),
            new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
        );

        // 2. Find active reservation by labId
        BigInteger totalReservations = diamond.reservationsOf(wallet).send();
        
        byte[] reservationKeyBytes = resolveActiveReservationKey(diamond, labId, wallet, puc);
        BigInteger currentTime = BigInteger.valueOf(System.currentTimeMillis() / 1000);
        
        if (!isValidReservationKey(reservationKeyBytes)) {
            // Iterate through user's reservations to find active one for this labId (fallback)
            for (int i = 0; i < totalReservations.intValue(); i++) {
                byte[] key = diamond.reservationKeyOfUserByIndex(wallet, BigInteger.valueOf(i)).send();
                Diamond.Reservation res = diamond.getReservation(key).send();
                
                // Check if this reservation matches our labId and is currently active
                if (res.labId.equals(labId) && 
                    (STATUS_CONFIRMED.equals(res.status) || STATUS_IN_USE.equals(res.status)) &&
                    (puc == null || puc.isEmpty() || (res.puc != null && res.puc.equals(puc))) &&
                    currentTime.compareTo(res.start) >= 0 &&
                    currentTime.compareTo(res.end) <= 0) {
                    
                    reservationKeyBytes = key;
                    break;
                }
            }
        }
        
        // Check if we found a valid active reservation
        if (reservationKeyBytes == null) {
            throw new IllegalStateException(
                "No active reservation found for lab " + labIdStr + " and wallet " + wallet + 
                " (searched through " + totalReservations + " reservations)"
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

        // 5. Get lab information
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

        // Validate status (CONFIRMED or IN_USE are considered active)
        if (!STATUS_CONFIRMED.equals(status) && !STATUS_IN_USE.equals(status)) {
            throw new IllegalStateException("Reservation is not active. Status: " + describeStatus(status));
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

    private String describeStatus(BigInteger status) {
        if (status == null) {
            return "UNKNOWN";
        }
        return switch (status.intValue()) {
            case 0 -> "PENDING";
            case 1 -> "CONFIRMED";
            case 2 -> "IN_USE";
            case 3 -> "COMPLETED";
            case 4 -> "COLLECTED";
            case 5 -> "CANCELLED";
            default -> "UNKNOWN(" + status + ")";
        };
    }

    /**
     * Builds the bookingInfo map for JWT claims and response
     */
    private Map<String, Object> buildBookingInfo(
            BigInteger labId, String reservationKeyHex,
            BigInteger price, BigInteger labPrice,
            BigInteger start, BigInteger end,
            String accessURI, String accessKey, String metadata, String authURI) {
        
        Map<String, Object> bookingInfo = new HashMap<>();
        
        // JWT Standard Claims
        bookingInfo.put("aud", accessURI);       // Audience - where token is used (complete URL from contract)
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
        
        // labURL for JSON response
        bookingInfo.put("labURL", accessURI);               // Complete URL to access lab

        return bookingInfo;
    }

    /**
     * Helper method to convert hex string to byte array
     */
    private byte[] hexStringToByteArray(String hex) {
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
    
    private byte[] resolveActiveReservationKey(Diamond diamond, BigInteger labId, String wallet, String puc) {
        try {
            byte[] key;
            if (puc != null && !puc.isBlank()) {
                key = diamond.getInstitutionalUserActiveReservationKey(wallet, puc, labId).send();
            } else {
                key = diamond.getActiveReservationKeyForUser(labId, wallet).send();
            }
            return isValidReservationKey(key) ? key : null;
        } catch (Exception e) {
            System.err.println("Warning: unable to fetch active reservation key from contract: " + e.getMessage());
            return null;
        }
    }

    private boolean isValidReservationKey(byte[] key) {
        return key != null && key.length == 32 && !Arrays.equals(key, new byte[32]);
    }
    
    /**
     * Retrieves booking information for a SAML-authenticated user
     * Maps SAML user ID to wallet address, then uses standard blockchain lookup
     * 
     * @param userid The SAML user identifier (NameID from IdP)
     * @param affiliation The user's institutional affiliation
     * @param labId The lab ID to search for
     * @param reservationKey Optional - the reservation key as hex string
     * @return Map containing booking information for JWT claims
     */
}

