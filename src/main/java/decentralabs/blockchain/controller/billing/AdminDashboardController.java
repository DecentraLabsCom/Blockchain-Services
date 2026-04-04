package decentralabs.blockchain.controller.billing;

import decentralabs.blockchain.dto.wallet.PayoutRequestSimulationResult;
import decentralabs.blockchain.dto.wallet.ProviderReceivableStatus;
import decentralabs.blockchain.service.billing.OnChainAdminTransactionService;
import decentralabs.blockchain.service.health.LabMetadataService;
import decentralabs.blockchain.service.billing.InstitutionalAnalyticsService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.EthereumAddressValidator;
import decentralabs.blockchain.util.LogSanitizer;
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
 * REST Controller for Billing Administration Dashboard
 * Provides read-only endpoints for monitoring and management
 * Secured by localhost-only access
 */
@RestController
@RequestMapping("/billing/admin")
@RequiredArgsConstructor
@Slf4j
public class AdminDashboardController {

    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final InstitutionalAnalyticsService institutionalAnalyticsService;
    private final OnChainAdminTransactionService onChainAdminTransactionService;
    private final LabMetadataService labMetadataService;

    private static final int LAB_TOKEN_DECIMALS = CreditUnitConverter.CREDIT_DECIMALS;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${marketplace.url:https://marketplace-decentralabs.vercel.app}")
    private String marketplaceUrl;

    @Value("${billing.admin.domain.name:DecentraLabsTreasuryAdmin}")
    private String billingAdminDomainName;

    @Value("${billing.admin.domain.version:1}")
    private String billingAdminDomainVersion;

    @Value("${billing.admin.domain.chain-id:${intent.domain.chain-id:11155111}}")
    private long billingAdminDomainChainId;

    @Value("${billing.admin.domain.verifying-contract:${contract.address:0x0000000000000000000000000000000000000000}}")
    private String billingAdminDomainVerifyingContract;

    @Value("${billing.collect.max-batch:50}")
    private int collectMaxBatch;

    /**
     * GET /billing/admin/status
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
            boolean isInstitution = walletConfigured && walletService.isInstitution(institutionalAddress);
            boolean isProvider = walletConfigured && walletService.isLabProvider(institutionalAddress);
            Optional<String> defaultAdminRole = walletService.getDefaultAdminRole();
            boolean isDefaultAdmin = walletConfigured && walletService.isDefaultAdmin(institutionalAddress);

            Map<String, Object> status = new LinkedHashMap<>();
            status.put("success", true);
            status.put("walletConfigured", walletConfigured);
            status.put("institutionalWalletAddress", walletConfigured ? institutionalAddress : null);
            status.put("isInstitution", isInstitution);
            status.put("isProvider", isProvider);
            status.put("defaultAdminRole", defaultAdminRole.orElse(null));
            status.put("isDefaultAdmin", isDefaultAdmin);
            status.put("institutionControlsEnabled", isInstitution);
            status.put("providerControlsEnabled", isProvider);
            status.put("operatorControlsEnabled", isDefaultAdmin);
            status.put("contractAddress", contractAddress);
            status.put("marketplaceUrl", marketplaceUrl);
            status.put("dashboardLocalOnly", adminDashboardLocalOnly);
            status.put("dashboardAllowPrivate", adminDashboardAllowPrivate);
            status.put("allowPrivateNetworks", allowPrivateNetworks);
            status.put("timestamp", System.currentTimeMillis());

            Map<String, Object> eip712 = new LinkedHashMap<>();
            eip712.put("name", billingAdminDomainName);
            eip712.put("version", billingAdminDomainVersion);
            eip712.put("chainId", billingAdminDomainChainId);
            String verifying = billingAdminDomainVerifyingContract;
            if (verifying == null || verifying.isBlank()) {
                verifying = contractAddress;
            }
            eip712.put("verifyingContract", verifying);
            status.put("billingAdminEip712", eip712);

            var networksResponse = walletService.getAvailableNetworks();
            status.put("availableNetworks", networksResponse.getNetworks());
            status.put("activeNetwork", networksResponse.getActiveNetwork());

            return ResponseEntity.ok(status);
        } catch (Exception e) {
            return internalServerError("Failed to retrieve system status", e);
        }
    }

    /**
     * GET /billing/admin/balance?chainId=11155111
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
            return internalServerError("Failed to retrieve balance", e);
        }
    }

    /**
     * GET /billing/admin/transactions?limit=10
     * Get recent on-chain administrative transactions for the configured institutional wallet.
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
            List<InstitutionalAnalyticsService.TransactionRecord> onChainTransactions =
                onChainAdminTransactionService.getRecentTransactions(providerAddress, Math.min(safeLimit + 5, 50));
            List<InstitutionalAnalyticsService.TransactionRecord> localTransactions =
                institutionalAnalyticsService.getRecentTransactions(providerAddress, Math.min(safeLimit + 5, 50));

            Map<String, InstitutionalAnalyticsService.TransactionRecord> merged = new LinkedHashMap<>();
            for (InstitutionalAnalyticsService.TransactionRecord tx : onChainTransactions) {
                merged.put(tx.getHash(), tx);
            }
            for (InstitutionalAnalyticsService.TransactionRecord tx : localTransactions) {
                merged.putIfAbsent(tx.getHash(), tx);
            }

            List<InstitutionalAnalyticsService.TransactionRecord> transactions = merged.values().stream()
                .sorted(Comparator.comparingLong(InstitutionalAnalyticsService.TransactionRecord::getTimestamp).reversed())
                .limit(Math.min(safeLimit + 1, 50))
                .toList();

            boolean hasMore = transactions.size() > safeLimit;
            if (hasMore) {
                transactions = transactions.subList(0, safeLimit);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("transactions", transactions);
            result.put("provider", providerAddress);
            result.put("hasMore", hasMore);
            if (transactions.isEmpty()) {
                result.put("note", "No recent on-chain administrative events found in the configured lookback window.");
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return internalServerError("Failed to retrieve transactions", e);
        }
    }

    /**
     * GET /billing/admin/contract-info
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

            return ResponseEntity.ok(info);
        } catch (Exception e) {
            return internalServerError("Failed to retrieve contract info", e);
        }
    }

    /**
     * GET /billing/admin/provider-labs
     * List labs associated with the institutional provider wallet.
     */
    @GetMapping("/provider-labs")
    public ResponseEntity<?> getProviderLabs(HttpServletRequest request) {
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

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("providerAddress", providerAddress);
            result.put("maxBatch", resolveCollectBatch(null));

            boolean isProvider = walletService.isLabProvider(providerAddress);
            boolean isDefaultAdmin = walletService.isDefaultAdmin(providerAddress);
            result.put("isProvider", isProvider);
            result.put("isDefaultAdmin", isDefaultAdmin);
            result.put("operatorControlsEnabled", isDefaultAdmin);
            List<Map<String, Object>> labs = new ArrayList<>();
            List<BigInteger> visibleLabIds = isDefaultAdmin
                ? walletService.getAllLabIds()
                : walletService.getLabsOwnedByProvider(providerAddress);
            for (BigInteger labId : visibleLabIds) {
                boolean ownedByInstitutionalProvider = walletService.isLabOwnedByProvider(providerAddress, labId);
                Map<String, Object> lab = new LinkedHashMap<>();
                lab.put("labId", labId.toString());
                String labName = resolveLabDisplayName(labId);
                lab.put("name", labName);
                lab.put("label", labName);
                lab.put("ownedByInstitutionalProvider", ownedByInstitutionalProvider);
                lab.put("providerPayoutEnabled", ownedByInstitutionalProvider);
                lab.put("operatorReviewOnly", isDefaultAdmin && !ownedByInstitutionalProvider);

                walletService.getProviderReceivableStatus(labId).ifPresent(status -> {
                    lab.put("providerReceivableRaw", status.providerReceivable().toString());
                    lab.put("providerReceivableLab", formatLabTokens(status.providerReceivable()));
                    lab.put("deferredInstitutionalReceivableRaw", status.deferredInstitutionalReceivable().toString());
                    lab.put("deferredInstitutionalReceivableLab", formatLabTokens(status.deferredInstitutionalReceivable()));
                    lab.put("totalReceivableRaw", status.totalReceivable().toString());
                    lab.put("totalReceivableLab", formatLabTokens(status.totalReceivable()));
                    lab.put("eligibleReservationCount", status.eligibleReservationCount().toString());
                    lab.put("hasReceivable", status.totalReceivable().compareTo(BigInteger.ZERO) > 0);

                });
                labs.add(lab);
            }

            result.put("labs", labs);
            if (isDefaultAdmin && !labs.isEmpty()) {
                result.put("note", "Operator view: showing all labs for settlement oversight");
            } else if (!isProvider && labs.isEmpty()) {
                result.put("note", "Institutional wallet is not registered as provider");
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return internalServerError("Failed to retrieve provider labs", e);
        }
    }

    /**
     * GET /billing/admin/provider-receivable-status?labId=3&maxBatch=50
     * Returns provider receivable and payout-request availability for a lab.
     */
    @GetMapping("/provider-receivable-status")
    public ResponseEntity<?> getProviderReceivableStatus(
        @RequestParam String labId,
        @RequestParam(required = false) Integer maxBatch,
        HttpServletRequest request
    ) {
        return buildProviderReceivableStatusResponse(labId, maxBatch, request);
    }

    private ResponseEntity<?> buildProviderReceivableStatusResponse(
        String labId,
        Integer maxBatch,
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

            BigInteger parsedLabId = EthereumAddressValidator.parseBigInteger(labId, "labId");
            if (parsedLabId.compareTo(BigInteger.ZERO) <= 0) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "labId must be greater than zero"
                ));
            }

            boolean isDefaultAdmin = walletService.isDefaultAdmin(providerAddress);
            boolean ownedByInstitutionalProvider = walletService.isLabOwnedByProvider(providerAddress, parsedLabId);
            if (!isDefaultAdmin && !ownedByInstitutionalProvider) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Selected lab is not associated with this institutional provider"
                ));
            }

            Optional<ProviderReceivableStatus> maybeReceivable = walletService.getProviderReceivableStatus(parsedLabId);
            if (maybeReceivable.isEmpty()) {
                return ResponseEntity.internalServerError().body(Map.of(
                    "success", false,
                    "error", "Failed to read provider receivable status from contract"
                ));
            }

            int effectiveBatch = resolveCollectBatch(maxBatch);
            ProviderReceivableStatus receivable = maybeReceivable.get();
            PayoutRequestSimulationResult simulation = walletService.simulateProviderPayoutRequest(
                providerAddress,
                parsedLabId,
                BigInteger.valueOf(effectiveBatch)
            );

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("providerAddress", providerAddress);
            result.put("labId", parsedLabId.toString());
            result.put("ownedByInstitutionalProvider", ownedByInstitutionalProvider);
            result.put("providerPayoutEnabled", ownedByInstitutionalProvider);
            result.put("operatorReviewOnly", isDefaultAdmin && !ownedByInstitutionalProvider);
            result.put("maxBatch", effectiveBatch);
            result.put("providerReceivableRaw", receivable.providerReceivable().toString());
            result.put("providerReceivableLab", formatLabTokens(receivable.providerReceivable()));
            result.put("deferredInstitutionalReceivableRaw", receivable.deferredInstitutionalReceivable().toString());
            result.put("deferredInstitutionalReceivableLab", formatLabTokens(receivable.deferredInstitutionalReceivable()));
            result.put("totalReceivableRaw", receivable.totalReceivable().toString());
            result.put("totalReceivableLab", formatLabTokens(receivable.totalReceivable()));
            result.put("accruedReceivableRaw", receivable.accruedReceivable().toString());
            result.put("accruedReceivableLab", formatLabTokens(receivable.accruedReceivable()));
            result.put("settlementQueuedRaw", receivable.settlementQueued().toString());
            result.put("settlementQueuedLab", formatLabTokens(receivable.settlementQueued()));
            result.put("invoicedReceivableRaw", receivable.invoicedReceivable().toString());
            result.put("invoicedReceivableLab", formatLabTokens(receivable.invoicedReceivable()));
            result.put("approvedReceivableRaw", receivable.approvedReceivable().toString());
            result.put("approvedReceivableLab", formatLabTokens(receivable.approvedReceivable()));
            result.put("paidReceivableRaw", receivable.paidReceivable().toString());
            result.put("paidReceivableLab", formatLabTokens(receivable.paidReceivable()));
            result.put("reversedReceivableRaw", receivable.reversedReceivable().toString());
            result.put("reversedReceivableLab", formatLabTokens(receivable.reversedReceivable()));
            result.put("disputedReceivableRaw", receivable.disputedReceivable().toString());
            result.put("disputedReceivableLab", formatLabTokens(receivable.disputedReceivable()));
            result.put("lastAccruedAt", receivable.lastAccruedAt().toString());
            result.put("eligibleReservationCount", receivable.eligibleReservationCount().toString());
            result.put("hasReceivable", receivable.totalReceivable().compareTo(BigInteger.ZERO) > 0);
            result.put("canRequestPayout", simulation.canRequestPayout());
            result.put("payoutRequestReason", simulation.reason());

            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", ex.getMessage()
            ));
        } catch (Exception e) {
            return internalServerError("Failed to retrieve provider receivable status", e);
        }
    }

    // ==================== PRIVATE HELPER METHODS ====================

    @Value("${admin.dashboard.local-only:true}")
    private boolean adminDashboardLocalOnly;

    @Value("${admin.dashboard.allow-private:true}")
    private boolean adminDashboardAllowPrivate;

    @Value("${security.allow-private-networks:false}")
    private boolean allowPrivateNetworks;

    @Value("${security.access-token:}")
    private String accessToken;

    @Value("${security.access-token-header:X-Access-Token}")
    private String accessTokenHeader;

    @Value("${security.access-token-cookie:access_token}")
    private String accessTokenCookie;

    @Value("${security.access-token.required:true}")
    private boolean accessTokenRequired;

    private static final Set<String> LOOPBACK_ADDRESSES = Set.of(
        "127.0.0.1",
        "0:0:0:0:0:0:0:1",
        "::1",
        "::ffff:127.0.0.1"
    );

    /**
     * Check if request comes from localhost (unless explicitly disabled)
     */
    private boolean isLocalhostRequest(HttpServletRequest request) {
        if (!adminDashboardLocalOnly) {
            return true;
        }

        String candidate = extractClientIp(request);
        log.info("Admin access check from IP={}", LogSanitizer.sanitize(candidate));
        boolean allowed = candidate == null
            || LOOPBACK_ADDRESSES.contains(candidate)
            || candidate.startsWith("127.")
            || (adminDashboardAllowPrivate
                && allowPrivateNetworks
                && isPrivateAddress(candidate)
                && (!accessTokenRequired || hasValidAccessToken(request)));

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
        return request.getRemoteAddr();
    }

    private boolean hasValidAccessToken(HttpServletRequest request) {
        if (accessToken == null || accessToken.isBlank()) {
            return false;
        }
        String headerToken = request.getHeader(accessTokenHeader);
        if (headerToken != null && !headerToken.isBlank()) {
            return accessToken.equals(headerToken.trim());
        }
        String authorization = request.getHeader("Authorization");
        if (authorization != null) {
            String lower = authorization.toLowerCase();
            if (lower.startsWith("bearer ")) {
                String bearer = authorization.substring("bearer ".length()).trim();
                return accessToken.equals(bearer);
            }
        }
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (accessTokenCookie.equals(cookie.getName())) {
                    return accessToken.equals(cookie.getValue());
                }
            }
        }
        return false;
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
            log.warn(
                "Failed to get balance on chainId {}: {}",
                chainId,
                LogSanitizer.sanitize(e.getMessage())
            );
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Failed to get balance on requested chainId"
            ));
        }
    }

    private String resolveLabDisplayName(BigInteger labId) {
        String fallback = "Lab #" + labId;
        return walletService.getLabTokenUri(labId)
            .flatMap(this::resolveLabNameFromMetadata)
            .orElse(fallback);
    }

    private Optional<String> resolveLabNameFromMetadata(String metadataUri) {
        if (metadataUri == null || metadataUri.isBlank()) {
            return Optional.empty();
        }

        try {
            var metadata = labMetadataService.getLabMetadata(metadataUri);
            if (metadata == null || metadata.getName() == null) {
                return Optional.empty();
            }
            String name = metadata.getName().trim();
            return name.isEmpty() ? Optional.empty() : Optional.of(name);
        } catch (RuntimeException ex) {
            log.debug(
                "Unable to resolve lab name from metadata {}: {}",
                LogSanitizer.sanitize(metadataUri),
                LogSanitizer.sanitize(ex.getMessage())
            );
            return Optional.empty();
        }
    }

    private String formatLabTokens(BigInteger rawValue) {
        if (rawValue == null) {
            return "0";
        }
        BigDecimal decimal = new BigDecimal(rawValue).movePointLeft(LAB_TOKEN_DECIMALS);
        return decimal.stripTrailingZeros().toPlainString();
    }

    private int resolveCollectBatch(Integer requestedBatch) {
        int candidate = requestedBatch != null ? requestedBatch : collectMaxBatch;
        if (candidate < 1) {
            return 1;
        }
        if (candidate > 100) {
            return 100;
        }
        return candidate;
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
     * GET /billing/admin/billing-info
     * Get billing configuration (limit, period, balance)
     * Returns contract default values if wallet not configured
     */
    @GetMapping("/billing-info")
    public ResponseEntity<?> getBillingInfo(HttpServletRequest request) {
        if (!isLocalhostRequest(request)) {
            return ResponseEntity.status(403).body(Map.of(
                "success", false,
                "error", "Access denied: administrative endpoints only accessible from localhost"
            ));
        }

        try {
            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            
            // Default contract values (if wallet not configured or contract call fails)
            final String DEFAULT_USER_LIMIT = CreditUnitConverter.DEFAULT_USER_LIMIT_RAW; // 10 service credits
            final long DEFAULT_PERIOD_DURATION = 10368000L; // 120 days in seconds
            
            // If wallet not configured, return contract default values
            if (institutionalAddress == null || institutionalAddress.isBlank()) {
                Map<String, Object> defaults = new LinkedHashMap<>();
                defaults.put("success", true);
                defaults.put("userLimit", DEFAULT_USER_LIMIT);
                defaults.put("periodDuration", DEFAULT_PERIOD_DURATION);
                defaults.put("periodStart", System.currentTimeMillis() / 1000); // Current timestamp
                defaults.put("periodEnd", (System.currentTimeMillis() / 1000) + DEFAULT_PERIOD_DURATION);
                defaults.put("billingBalance", "0"); // 0 credits
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
            
            // Get billing balance from contract
            java.math.BigInteger billingBalance = walletService.getInstitutionalBillingBalance(institutionalAddress);
            if (billingBalance != null) {
                info.put("billingBalance", billingBalance.toString());
                info.put("billingBalanceFormatted", formatLabTokens(billingBalance));
            } else {
                info.put("billingBalance", "0");
                info.put("billingBalanceFormatted", "0");
            }

            java.math.BigInteger serviceCreditBalance = walletService.getServiceCreditBalance(institutionalAddress);
            info.put("serviceCreditBalance", serviceCreditBalance.toString());
            info.put("serviceCreditBalanceFormatted", formatLabTokens(serviceCreditBalance));

            // Check if wallet is registered as provider
            boolean isProvider = walletService.isLabProvider(institutionalAddress);
            info.put("isProvider", isProvider);
            
            // Get stake info if provider
            if (isProvider) {
                var stakeInfo = walletService.getStakeInfo(institutionalAddress);
                Map<String, Object> stakeData = new LinkedHashMap<>();
                stakeData.put("stakedAmount", stakeInfo.getStakedAmount().toString());
                stakeData.put("stakedAmountFormatted", stakeInfo.getStakedAmountFormatted());
                stakeData.put("slashedAmount", stakeInfo.getSlashedAmount().toString());
                stakeData.put("lastReservationTimestamp", stakeInfo.getLastReservationTimestamp());
                stakeData.put("unlockTimestamp", stakeInfo.getUnlockTimestamp());
                stakeData.put("canUnstake", stakeInfo.isCanUnstake());
                info.put("stakeInfo", stakeData);
                
                // Remove the "not registered" note if we got here
                info.remove("note");
            }

            return ResponseEntity.ok(info);
        } catch (Exception e) {
            return internalServerError("Failed to retrieve billing info", e);
        }
    }

    /**
     * GET /billing/admin/top-spenders?limit=10
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
            return internalServerError("Failed to retrieve top spenders", e);
        }
    }

    private ResponseEntity<Map<String, Object>> internalServerError(String clientMessage, Exception e) {
        log.error("{}: {}", clientMessage, LogSanitizer.sanitize(e.getMessage()), e);
        return ResponseEntity.internalServerError().body(Map.of(
            "success", false,
            "error", clientMessage
        ));
    }
}
