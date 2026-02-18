package decentralabs.blockchain.controller.auth;

import decentralabs.blockchain.dto.auth.AuthResponse;
import decentralabs.blockchain.dto.auth.CheckInRequest;
import decentralabs.blockchain.dto.auth.CheckInResponse;
import decentralabs.blockchain.dto.auth.WalletAuthRequest;
import decentralabs.blockchain.service.auth.CheckInOnChainService;
import decentralabs.blockchain.service.auth.WalletAuthService;
import decentralabs.blockchain.service.wallet.BlockchainBookingService;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

/**
 * Controller for wallet-based authentication endpoints
 */
@RestController
@RequestMapping("/auth")
@ConditionalOnProperty(value = "features.providers.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class WalletAuthController {
    
    @Autowired
    private WalletAuthService walletAuthService;

    @Autowired
    private CheckInOnChainService checkInOnChainService;

    @Autowired
    private BlockchainBookingService blockchainBookingService;

    @org.springframework.beans.factory.annotation.Value("${intent.domain.name:DecentraLabsIntent}")
    private String domainName;

    @org.springframework.beans.factory.annotation.Value("${intent.domain.version:1}")
    private String domainVersion;

    @org.springframework.beans.factory.annotation.Value("${intent.domain.chain-id:11155111}")
    private long domainChainId;

    @org.springframework.beans.factory.annotation.Value("${intent.domain.verifying-contract:${contract.address:0x0000000000000000000000000000000000000000}}")
    private String verifyingContract;
    
    /**
     * Endpoint to get a message to sign (timestamp-based)
     * 
     * @return Message containing current timestamp
     */
    @GetMapping("/message")
    public ResponseEntity<Map<String, Object>> getMessage(
        @RequestParam(name = "purpose", required = false) String purpose,
        @RequestParam(name = "reservationKey", required = false) String reservationKey,
        @RequestParam(name = "labId", required = false) String labId,
        @RequestParam(name = "puc", required = false) String puc,
        @RequestParam(name = "signer", required = false) String signer
    ) {
        String resolvedPurpose = purpose == null ? "login" : purpose.trim().toLowerCase();
        if ("checkin".equals(resolvedPurpose)) {
            if (signer == null || signer.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing signer"));
            }
            String resolvedKey = reservationKey;
            if (resolvedKey == null || resolvedKey.isBlank()) {
                if (labId == null || labId.isBlank()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Missing reservationKey or labId"));
                }
                try {
                    resolvedKey = blockchainBookingService.resolveActiveReservationKeyHex(signer, labId, puc);
                } catch (IllegalArgumentException e) {
                    return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
                }
                if (resolvedKey == null || resolvedKey.isBlank()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "No active reservation found"));
                }
            }
            long timestamp = System.currentTimeMillis() / 1000;
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("purpose", "checkin");
            response.put("timestamp", timestamp);
            response.put("reservationKey", resolvedKey);
            response.put("typedData", buildCheckInTypedData(signer, resolvedKey, puc, timestamp));
            return ResponseEntity.ok(response);
        }

        long timestamp = System.currentTimeMillis();
        String message = "Login request: " + timestamp;

        Map<String, Object> response = new HashMap<>();
        response.put("purpose", "login");
        response.put("message", message);
        response.put("timestamp", String.valueOf(timestamp));
        return ResponseEntity.ok(response);
    }
    
    /**
     * Endpoint for wallet authentication without booking information
     * 
     * @param request Wallet authentication request
     * @return JWT token
     */
    @PostMapping("/wallet-auth")
    public ResponseEntity<?> walletAuth(@RequestBody WalletAuthRequest request) {
        try {
            AuthResponse response = walletAuthService.handleAuthentication(request, false);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Wallet authentication error", e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }
    
    /**
     * Endpoint for wallet authentication with booking information
     * 
     * @param request Wallet authentication request (must include labId or reservationKey)
     * @return JWT token with booking claims and lab URL
     */
    @PostMapping("/wallet-auth2")
    public ResponseEntity<?> walletAuth2(@RequestBody WalletAuthRequest request) {
        try {
            AuthResponse response = walletAuthService.handleAuthentication(request, true);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Wallet authentication error", e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    /**
     * Endpoint to verify an EIP-712 check-in signature.
     */
    @PostMapping("/checkin")
    public ResponseEntity<CheckInResponse> checkIn(@RequestBody CheckInRequest request) {
        try {
            CheckInResponse response = checkInOnChainService.verifyAndSubmit(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason(e.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (SecurityException e) {
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason(e.getMessage());
            return ResponseEntity.status(401).body(response);
        } catch (Exception e) {
            log.error("Check-in verification error", e);
            CheckInResponse response = new CheckInResponse();
            response.setValid(false);
            response.setReason("Internal server error");
            return ResponseEntity.status(500).body(response);
        }
    }

    private Map<String, Object> buildCheckInTypedData(
        String signer,
        String reservationKey,
        String puc,
        long timestamp
    ) {
        Map<String, Object> domain = new LinkedHashMap<>();
        domain.put("name", domainName);
        domain.put("version", domainVersion);
        domain.put("chainId", domainChainId);
        domain.put("verifyingContract", verifyingContract);

        List<Map<String, String>> domainFields = List.of(
            Map.of("name", "name", "type", "string"),
            Map.of("name", "version", "type", "string"),
            Map.of("name", "chainId", "type", "uint256"),
            Map.of("name", "verifyingContract", "type", "address")
        );

        List<Map<String, String>> checkInFields = List.of(
            Map.of("name", "signer", "type", "address"),
            Map.of("name", "reservationKey", "type", "bytes32"),
            Map.of("name", "pucHash", "type", "bytes32"),
            Map.of("name", "timestamp", "type", "uint64")
        );

        Map<String, Object> types = new LinkedHashMap<>();
        types.put("EIP712Domain", domainFields);
        types.put("CheckIn", checkInFields);

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("signer", signer);
        message.put("reservationKey", normalizeBytes32(reservationKey));
        message.put("pucHash", computePucHash(puc));
        message.put("timestamp", timestamp);

        Map<String, Object> typedData = new LinkedHashMap<>();
        typedData.put("types", types);
        typedData.put("domain", domain);
        typedData.put("primaryType", "CheckIn");
        typedData.put("message", message);
        return typedData;
    }

    private String computePucHash(String puc) {
        if (puc == null || puc.isBlank()) {
            return "0x" + "0".repeat(64);
        }
        byte[] hash = Hash.sha3(puc.getBytes(StandardCharsets.UTF_8));
        return normalizeBytes32(Numeric.toHexString(hash));
    }

    private String normalizeBytes32(String value) {
        String clean = Numeric.cleanHexPrefix(value == null ? "" : value);
        if (clean.length() > 64) {
            clean = clean.substring(clean.length() - 64);
        }
        if (clean.length() < 64) {
            clean = "0".repeat(64 - clean.length()) + clean;
        }
        return "0x" + clean;
    }
}
