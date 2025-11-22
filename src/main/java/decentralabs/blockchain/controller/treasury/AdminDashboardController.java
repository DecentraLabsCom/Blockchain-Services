package decentralabs.blockchain.controller.treasury;

import decentralabs.blockchain.service.treasury.InstitutionalAnalyticsService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

/**
 * REST Controller for Treasury Administration Dashboard
 * Provides read-only endpoints for monitoring and management
 * Secured by localhost-only access
 */
@RestController
@RequestMapping("/treasury/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminDashboardController {

    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final InstitutionalAnalyticsService institutionalAnalyticsService;

    private static final int LAB_TOKEN_DECIMALS = 6;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${marketplace.url:https://marketplace-decentralabs.vercel.app}")
    private String marketplaceUrl;

    /**
     * GET /treasury/admin/status
     * Overall system status for dashboard
     */
    @GetMapping("/status")
    public ResponseEntity<?> getSystemStatus(HttpServletRequest request) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            boolean walletConfigured = institutionalAddress != null && !institutionalAddress.isBlank();

            Map<String, Object> status = new LinkedHashMap<>();
            status.put("success", true);
            status.put("walletConfigured", walletConfigured);
            status.put("institutionalWalletAddress", walletConfigured ? institutionalAddress : null);
            status.put("contractAddress", contractAddress);
            status.put("marketplaceUrl", marketplaceUrl);
            status.put("timestamp", System.currentTimeMillis());
            
            var networksResponse = walletService.getAvailableNetworks();
            status.put("availableNetworks", networksResponse.getNetworks());
            status.put("activeNetwork", networksResponse.getActiveNetwork());

            return ResponseEntity.ok(status);
        } catch (Exception e) {
            log.error("Error getting system status: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve system status: " + e.getMessage()
            ));
        }
    }

    /**
     * GET /treasury/admin/balance?chainId=11155111
     * Get balance of institutional wallet on specified network
     */
    @GetMapping("/balance")
    public ResponseEntity<?> getInstitutionalBalance(
        @RequestParam(required = false) Long chainId,
        HttpServletRequest request
    ) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (institutionalAddress == null || institutionalAddress.isBlank()) {
                // Wallet not configured - return zeros
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("walletConfigured", false);
                result.put("institutionalWalletAddress", null);
                result.put("ethBalance", "0");
                result.put("ethBalanceFormatted", "0.0");
                result.put("labTokenAddress", null);
                result.put("labBalanceRaw", "0");
                result.put("labBalance", "0.0");
                result.put("note", "Institutional wallet not configured");
                return ResponseEntity.ok(result);
            }

            // If no chainId provided, get balance on all configured networks
            if (chainId == null) {
                return getBalanceAllNetworks(institutionalAddress);
            }

            // Get balance on specific network
            return getBalanceOnNetwork(institutionalAddress, chainId);

        } catch (Exception e) {
            log.error("Error getting institutional wallet balance: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve balance: " + e.getMessage()
            ));
        }
    }

    /**
     * GET /treasury/admin/transactions?limit=10
     * Get recent transactions (requires indexing service or blockchain explorer API)
     * TODO: Implement transaction history tracking
     */
    @GetMapping("/transactions")
    public ResponseEntity<?> getRecentTransactions(
        @RequestParam(defaultValue = "10") int limit,
        HttpServletRequest request
    ) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            String providerAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (providerAddress == null || providerAddress.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Institutional wallet not configured"
                ));
            }

            int safeLimit = Math.min(Math.max(limit, 1), 50);
            List<InstitutionalAnalyticsService.TransactionRecord> transactions =
                institutionalAnalyticsService.getRecentTransactions(providerAddress, safeLimit);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("transactions", transactions);
            result.put("provider", providerAddress);
            if (transactions.isEmpty()) {
                result.put("note", "No local transactions recorded yet. Execute an admin action or reservation to populate the feed.");
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error getting transactions: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve transactions: " + e.getMessage()
            ));
        }
    }

    /**
     * GET /treasury/admin/contract-info
     * Get information about the smart contract
     */
    @GetMapping("/contract-info")
    public ResponseEntity<?> getContractInfo(HttpServletRequest request) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("success", true);
            info.put("contractAddress", contractAddress);
            
            var networksResponse = walletService.getAvailableNetworks();
            info.put("networks", networksResponse.getNetworks());
            info.put("activeNetwork", networksResponse.getActiveNetwork());
            // TODO: Add contract version, deployed block, etc.

            return ResponseEntity.ok(info);
        } catch (Exception e) {
            log.error("Error getting contract info: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve contract info: " + e.getMessage()
            ));
        }
    }

    // ==================== PRIVATE HELPER METHODS ====================

    @Value("${admin.dashboard.local-only:true}")
    private boolean adminDashboardLocalOnly;

    @Value("${admin.dashboard.allow-private:true}")
    private boolean adminDashboardAllowPrivate;

    private static final Set<String> LOOPBACK_ADDRESSES = Set.of(
        "127.0.0.1",
        "0:0:0:0:0:0:0:1",
        "::1"
    );

    /**
     * Check if request comes from localhost (unless explicitly disabled)
     */
    private boolean isLocalhostRequest(HttpServletRequest request) {
        if (!adminDashboardLocalOnly) {
            return true;
        }

        String candidate = extractClientIp(request);
        log.info("Admin access check from IP={}", candidate);
        boolean allowed = candidate == null
            || LOOPBACK_ADDRESSES.contains(candidate)
            || candidate.startsWith("127.")
            || (adminDashboardAllowPrivate && isPrivateAddress(candidate));

        if (!allowed) {
            log.warn("Blocked administrative dashboard access from non-local address.");
        }

        return allowed;
    }

    private boolean isPrivateAddress(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        return address.startsWith("10.")
            || address.startsWith("192.168.")
            || (address.startsWith("172.") && isInRange(address, 16, 31))
            || address.startsWith("169.254.");
    }

    private boolean isInRange(String address, int start, int end) {
        try {
            String[] parts = address.split("\\.");
            if (parts.length < 2) {
                return false;
            }
            int second = Integer.parseInt(parts[1]);
            return second >= start && second <= end;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Get balance on all configured networks
     */
    private ResponseEntity<?> getBalanceAllNetworks(String walletAddress) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("address", walletAddress);
        
        Map<String, Object> balances = new LinkedHashMap<>();
        
        // Get available networks
        var networksResponse = walletService.getAvailableNetworks();
        if (!networksResponse.isSuccess()) {
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to get available networks"
            ));
        }
        
        // Get balance on each configured network
        for (var networkInfo : networksResponse.getNetworks()) {
            String networkId = networkInfo.getId();
            try {
                // Switch to network
                walletService.switchNetwork(networkId);
                
                // Get balance
                var balanceResponse = walletService.getBalance(walletAddress);
                
                Map<String, Object> networkBalance = new LinkedHashMap<>();
                networkBalance.put("success", balanceResponse.isSuccess());
                networkBalance.put("balanceWei", balanceResponse.getBalanceWei());
                networkBalance.put("balanceEth", balanceResponse.getBalanceEth());
                networkBalance.put("network", balanceResponse.getNetwork());
                networkBalance.put("labTokenAddress", balanceResponse.getLabTokenAddress());
                networkBalance.put("labBalanceRaw", balanceResponse.getLabBalanceRaw());
                networkBalance.put("labBalance", balanceResponse.getLabBalance());
                
                balances.put(networkId, networkBalance);
            } catch (Exception e) {
                log.warn("Failed to get network balance");
                balances.put(networkId, Map.of("error", "Failed to retrieve balance"));
            }
        }

        result.put("balances", balances);
        return ResponseEntity.ok(result);
    }

    /**
     * Get balance on specific network
     */
    private ResponseEntity<?> getBalanceOnNetwork(String walletAddress, Long chainId) {
        try {
            // Map chainId to network name
            String networkId = mapChainIdToNetworkId(chainId);
            
            // Switch to network
            walletService.switchNetwork(networkId);
            
            // Get balance
            var balanceResponse = walletService.getBalance(walletAddress);
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", balanceResponse.isSuccess());
            result.put("address", walletAddress);
            result.put("balanceWei", balanceResponse.getBalanceWei());
            result.put("balanceEth", balanceResponse.getBalanceEth());
            result.put("network", balanceResponse.getNetwork());
            result.put("chainId", chainId);
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Failed to get balance on chainId " + chainId + ": " + e.getMessage()
            ));
        }
    }

    private String formatLabTokens(BigInteger rawValue) {
        if (rawValue == null) {
            return "0";
        }
        BigDecimal decimal = new BigDecimal(rawValue).movePointLeft(LAB_TOKEN_DECIMALS);
        return decimal.stripTrailingZeros().toPlainString();
    }
    
    /**
     * Map chainId to network identifier
     */
    private String mapChainIdToNetworkId(Long chainId) {
        return switch (chainId.intValue()) {
            case 1 -> "mainnet";
            case 11155111 -> "sepolia";
            default -> throw new IllegalArgumentException("Unsupported chainId: " + chainId);
        };
    }

    /**
     * GET /treasury/admin/treasury-info
     * Get treasury configuration (limit, period, balance)
     * Returns contract default values if wallet not configured
     */
    @GetMapping("/treasury-info")
    public ResponseEntity<?> getTreasuryInfo(HttpServletRequest request) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            
            // Default contract values (if wallet not configured or contract call fails)
            final String DEFAULT_USER_LIMIT = "10000000"; // 10 LAB tokens (6 decimals)
            final long DEFAULT_PERIOD_DURATION = 10368000L; // 120 days in seconds
            
            // If wallet not configured, return contract default values
            if (institutionalAddress == null || institutionalAddress.isBlank()) {
                Map<String, Object> defaults = new LinkedHashMap<>();
                defaults.put("success", true);
                defaults.put("userLimit", DEFAULT_USER_LIMIT);
                defaults.put("periodDuration", DEFAULT_PERIOD_DURATION);
                defaults.put("periodStart", System.currentTimeMillis() / 1000); // Current timestamp
                defaults.put("periodEnd", (System.currentTimeMillis() / 1000) + DEFAULT_PERIOD_DURATION);
                defaults.put("treasuryBalance", "0"); // 0 LAB tokens
                defaults.put("walletConfigured", false);
                defaults.put("note", "Showing contract default values - wallet not configured");
                return ResponseEntity.ok(defaults);
            }

            // Wallet is configured - get actual values from contract
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("success", true);
            info.put("walletConfigured", true);
            
            // Get user spending limit from contract
            java.math.BigInteger userLimit = walletService.getInstitutionalUserLimit(institutionalAddress);
            if (userLimit != null && userLimit.compareTo(java.math.BigInteger.ZERO) > 0) {
                info.put("userLimit", userLimit.toString());
            } else {
                // If 0 or null, wallet not registered as provider - use defaults
                info.put("userLimit", DEFAULT_USER_LIMIT);
                info.put("note", "Wallet not registered as provider - showing contract default values");
            }
            
            // Get spending period from contract
            java.math.BigInteger periodDuration = walletService.getInstitutionalSpendingPeriod(institutionalAddress);
            if (periodDuration != null && periodDuration.compareTo(java.math.BigInteger.ZERO) > 0) {
                info.put("periodDuration", periodDuration.longValue());
                info.put("periodStart", System.currentTimeMillis() / 1000);
                info.put("periodEnd", (System.currentTimeMillis() / 1000) + periodDuration.longValue());
            } else {
                // If 0 or null, use defaults
                info.put("periodDuration", DEFAULT_PERIOD_DURATION);
                info.put("periodStart", System.currentTimeMillis() / 1000);
                info.put("periodEnd", (System.currentTimeMillis() / 1000) + DEFAULT_PERIOD_DURATION);
                if (!info.containsKey("note")) {
                    info.put("note", "Wallet not registered as provider - showing contract default values");
                }
            }
            
            // Get treasury balance from contract
            java.math.BigInteger treasuryBalance = walletService.getInstitutionalTreasuryBalance(institutionalAddress);
            if (treasuryBalance != null) {
                info.put("treasuryBalance", treasuryBalance.toString());
            } else {
                info.put("treasuryBalance", "0");
            }

            return ResponseEntity.ok(info);
        } catch (Exception e) {
            log.error("Error getting treasury info: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve treasury info: " + e.getMessage()
            ));
        }
    }

    /**
     * GET /treasury/admin/top-spenders?limit=10
     * Get top spenders in current period
     */
    @GetMapping("/top-spenders")
    public ResponseEntity<?> getTopSpenders(
        @RequestParam(defaultValue = "10") int limit,
        HttpServletRequest request
    ) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (institutionalAddress == null || institutionalAddress.isBlank()) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Institutional wallet not configured"
                ));
            }

            List<InstitutionalAnalyticsService.UserActivity> knownUsers =
                institutionalAnalyticsService.getKnownUsers(institutionalAddress, 50);

            List<Map<String, Object>> spenders = new ArrayList<>();
            for (InstitutionalAnalyticsService.UserActivity user : knownUsers) {
                walletService.getInstitutionalUserFinancialStats(institutionalAddress, user.getPuc())
                    .ifPresent(stats -> {
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("puc", user.getPuc());
                        entry.put("amountRaw", stats.getCurrentPeriodSpent().toString());
                        entry.put("amountLab", formatLabTokens(stats.getCurrentPeriodSpent()));
                        entry.put("remainingLab", formatLabTokens(stats.getRemainingAllowance()));
                        entry.put("limitLab", formatLabTokens(stats.getSpendingLimit()));
                        entry.put("periodStart", stats.getPeriodStart().longValue());
                        entry.put("periodEnd", stats.getPeriodEnd().longValue());
                        entry.put("lastSeen", user.getLastSeenEpochMillis());
                        spenders.add(entry);
                    });
            }

            spenders.sort((a, b) -> {
                BigInteger spentA = new BigInteger((String) a.get("amountRaw"));
                BigInteger spentB = new BigInteger((String) b.get("amountRaw"));
                return spentB.compareTo(spentA);
            });
            int safeLimit = Math.min(Math.max(limit, 1), spenders.size());
            List<Map<String, Object>> limited = spenders.stream()
                .limit(safeLimit)
                .collect(Collectors.toList());

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("spenders", limited);
            result.put("provider", institutionalAddress);
            if (limited.isEmpty()) {
                result.put("note", knownUsers.isEmpty()
                    ? "No institutional users have interacted yet from this provider."
                    : "Users recorded but no on-chain spending detected for current period.");
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error getting top spenders: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve top spenders: " + e.getMessage()
            ));
        }
    }
}
