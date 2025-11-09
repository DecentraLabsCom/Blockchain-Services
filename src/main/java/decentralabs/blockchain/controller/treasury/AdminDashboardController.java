package decentralabs.blockchain.controller.treasury;

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

import java.util.*;

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

    @Value("${contract.address}")
    private String contractAddress;

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
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Institutional wallet not configured"
                ));
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
     * GET /treasury/admin/limits
     * Get configured spending limits (from contract or configuration)
     * TODO: Implement contract call to get actual on-chain limits
     */
    @GetMapping("/limits")
    public ResponseEntity<?> getSpendingLimits(HttpServletRequest request) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            // TODO: Call smart contract to get actual limits
            // For now, return placeholder data
            Map<String, Object> limits = new LinkedHashMap<>();
            limits.put("success", true);
            limits.put("limits", Map.of(
                "dailyLimit", "100000000000000000000",  // 100 ETH in wei
                "weeklyLimit", "500000000000000000000", // 500 ETH in wei
                "monthlyLimit", "2000000000000000000000", // 2000 ETH in wei
                "dailySpent", "0",
                "weeklySpent", "0",
                "monthlySpent", "0",
                "lastResetTimestamp", System.currentTimeMillis()
            ));
            limits.put("note", "Contract integration pending - showing placeholder values");

            return ResponseEntity.ok(limits);
        } catch (Exception e) {
            log.error("Error getting spending limits: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                "success", false,
                "error", "Failed to retrieve limits: " + e.getMessage()
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
            // TODO: Implement transaction history
            // Options:
            // 1. Use Etherscan/Blockscout API
            // 2. Index events from contract
            // 3. Store transaction hashes in database
            
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("transactions", new ArrayList<>());
            result.put("note", "Transaction history tracking not yet implemented");
            result.put("suggestion", "Use Etherscan API or implement event indexing");

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

    /**
     * Check if request comes from localhost
     */
    private boolean isLocalhostRequest(HttpServletRequest request) {
        // TODO: Re-enable localhost validation for production deployment
        // DEVELOPMENT MODE: Allowing all access for testing
        log.info("Administrative dashboard access from: {}", request.getRemoteAddr());
        return true;
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
                
                balances.put(networkId, networkBalance);
            } catch (Exception e) {
                log.warn("Failed to get {} balance: {}", networkId, e.getMessage());
                balances.put(networkId, Map.of("error", e.getMessage()));
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
}
