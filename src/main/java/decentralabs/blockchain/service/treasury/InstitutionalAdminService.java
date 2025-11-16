package decentralabs.blockchain.service.treasury;

import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.treasury.InstitutionalAdminResponse;
import decentralabs.blockchain.util.EthereumAddressValidator;
import jakarta.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

/**
 * Service for institutional treasury administrative operations
 * Secured by localhost access and wallet ownership validation
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalAdminService {

    private final Web3j web3j;
    private final HttpServletRequest request;
    private final RateLimitService rateLimitService;
    private final InstitutionalWalletService institutionalWalletService;
    private final InstitutionalAnalyticsService analyticsService;

    private static final int LAB_TOKEN_DECIMALS = 6;

    @Value("${contract.address}")
    private String contractAddress;

    /**
     * Execute administrative operation with localhost and wallet ownership validation
     */
    public InstitutionalAdminResponse executeAdminOperation(InstitutionalAdminRequest request) {
        try {
            // Step 1: Validate localhost access
            if (!isLocalhostRequest()) {
                return InstitutionalAdminResponse.error("Access denied: administrative operations only allowed from localhost");
            }

            // Step 2: Validate wallet ownership
            if (!isAuthorizedWalletOwner(request.getAdminWalletAddress())) {
                return InstitutionalAdminResponse.error("Access denied: wallet address does not match configured wallet");
            }

            // Step 3: Execute the requested operation
            return executeOperation(request);

        } catch (Exception e) {
            log.error("Error executing admin operation: {}", e.getMessage(), e);
            return InstitutionalAdminResponse.error("Administrative operation failed: " + e.getMessage());
        }
    }

    /**
     * Check if the request comes from localhost
     */
    private boolean isLocalhostRequest() {
        String remoteAddr = request.getRemoteAddr();
        String forwardedFor = request.getHeader("X-Forwarded-For");

        // Check direct IP
        if ("127.0.0.1".equals(remoteAddr) || "::1".equals(remoteAddr)) {
            return true;
        }

        // Check X-Forwarded-For header (for proxies/load balancers)
        if (forwardedFor != null) {
            String[] forwardedIps = forwardedFor.split(",");
            for (String ip : forwardedIps) {
                if ("127.0.0.1".equals(ip.trim()) || "::1".equals(ip.trim())) {
                    return true;
                }
            }
        }

        log.warn("Administrative access attempt from non-localhost IP: {}", remoteAddr);
        return false;
    }

    /**
     * Check if the provided wallet address matches the institutional wallet
     */
    private boolean isAuthorizedWalletOwner(String adminWalletAddress) {
        if (adminWalletAddress == null || adminWalletAddress.trim().isEmpty()) {
            return false;
        }

        String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
        if (institutionalAddress == null) {
            log.error("Institutional wallet not configured");
            return false;
        }

        // Compare case-insensitive (Ethereum addresses are case-insensitive)
        boolean isAuthorized = institutionalAddress.equalsIgnoreCase(adminWalletAddress.trim());

        if (!isAuthorized) {
            log.warn("Administrative access attempt with unauthorized wallet: {} (expected: {})",
                adminWalletAddress, institutionalAddress);
        }

        return isAuthorized;
    }

    /**
     * Execute the specific administrative operation
     */
    private InstitutionalAdminResponse executeOperation(InstitutionalAdminRequest request) throws Exception {
        Credentials credentials = institutionalWalletService.getInstitutionalCredentials();

        switch (request.getOperation()) {
            case AUTHORIZE_BACKEND:
                return authorizeBackend(credentials, request);

            case REVOKE_BACKEND:
                return revokeBackend(credentials);

            case ADMIN_RESET_BACKEND:
                return adminResetBackend(credentials, request);

            case SET_USER_LIMIT:
                return setUserLimit(credentials, request);

            case SET_SPENDING_PERIOD:
                return setSpendingPeriod(credentials, request);

            case RESET_SPENDING_PERIOD:
                return resetSpendingPeriod(credentials);

            case DEPOSIT_TREASURY:
                return depositTreasury(credentials, request);

            case WITHDRAW_TREASURY:
                return withdrawTreasury(credentials, request);

            default:
                return InstitutionalAdminResponse.error("Unknown administrative operation");
        }
    }

    private InstitutionalAdminResponse authorizeBackend(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getBackendAddress() == null) {
            return InstitutionalAdminResponse.error("Backend address required for authorization");
        }

        Function function = new Function(
            "authorizeBackend",
            Arrays.asList(new Address(request.getBackendAddress())),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "AUTHORIZE_BACKEND",
            "Authorized backend " + request.getBackendAddress(),
            null
        );
        return InstitutionalAdminResponse.success(
            "Backend authorized successfully",
            txHash,
            "AUTHORIZE_BACKEND"
        );
    }

    private InstitutionalAdminResponse revokeBackend(Credentials credentials) throws Exception {
        Function function = new Function(
            "revokeBackend",
            Collections.emptyList(),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "REVOKE_BACKEND",
            "Revoked backend access",
            null
        );
        return InstitutionalAdminResponse.success(
            "Backend revoked successfully",
            txHash,
            "REVOKE_BACKEND"
        );
    }

    private InstitutionalAdminResponse adminResetBackend(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getProviderAddress() == null) {
            return InstitutionalAdminResponse.error("Provider address required for admin reset");
        }

        String backendAddress = request.getBackendAddress() != null ?
            request.getBackendAddress() :
            "0x0000000000000000000000000000000000000000";

        Function function = new Function(
            "adminResetBackend",
            Arrays.asList(
                new Address(request.getProviderAddress()),
                new Address(backendAddress)
            ),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "ADMIN_RESET_BACKEND",
            "Admin reset backend for " + request.getProviderAddress(),
            null
        );
        return InstitutionalAdminResponse.success(
            "Backend reset by admin successfully",
            txHash,
            "ADMIN_RESET_BACKEND"
        );
    }

    private InstitutionalAdminResponse setUserLimit(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getSpendingLimit() == null) {
            return InstitutionalAdminResponse.error("Spending limit required");
        }

        BigInteger limit = EthereumAddressValidator.parseBigInteger(request.getSpendingLimit(), "spendingLimit");
        Function function = new Function(
            "setInstitutionalUserLimit",
            Arrays.asList(new Uint256(limit)),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "SET_USER_LIMIT",
            "Updated user spending limit",
            formatLabTokens(limit)
        );
        return InstitutionalAdminResponse.success(
            "User spending limit updated successfully",
            txHash,
            "SET_USER_LIMIT"
        ).withUserLimit(request.getSpendingLimit());
    }

    private InstitutionalAdminResponse setSpendingPeriod(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getSpendingPeriod() == null) {
            return InstitutionalAdminResponse.error("Spending period required");
        }

        BigInteger period = EthereumAddressValidator.parseBigInteger(request.getSpendingPeriod(), "spendingPeriod");
        Function function = new Function(
            "setInstitutionalSpendingPeriod",
            Arrays.asList(new Uint256(period)),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "SET_SPENDING_PERIOD",
            "Updated spending period",
            formatPeriodDays(period)
        );
        return InstitutionalAdminResponse.success(
            "Spending period updated successfully",
            txHash,
            "SET_SPENDING_PERIOD"
        ).withSpendingPeriod(request.getSpendingPeriod());
    }

    private InstitutionalAdminResponse resetSpendingPeriod(Credentials credentials) throws Exception {
        Function function = new Function(
            "resetInstitutionalSpendingPeriod",
            Collections.emptyList(),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "RESET_SPENDING_PERIOD",
            "Reset spending counters for all users",
            null
        );
        return InstitutionalAdminResponse.success(
            "Spending period reset successfully - all user spending counters cleared",
            txHash,
            "RESET_SPENDING_PERIOD"
        );
    }

    private InstitutionalAdminResponse depositTreasury(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getAmount() == null) {
            return InstitutionalAdminResponse.error("Amount required for treasury deposit");
        }

        BigInteger amount = EthereumAddressValidator.parseBigInteger(request.getAmount(), "amount");
        Function function = new Function(
            "depositToInstitutionalTreasury",
            Arrays.asList(new Uint256(amount)),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "DEPOSIT_TREASURY",
            "Treasury deposit",
            formatLabTokens(amount)
        );
        return InstitutionalAdminResponse.success(
            "Treasury deposit completed successfully",
            txHash,
            "DEPOSIT_TREASURY"
        );
    }

    private InstitutionalAdminResponse withdrawTreasury(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getAmount() == null) {
            return InstitutionalAdminResponse.error("Amount required for treasury withdrawal");
        }

        BigInteger amount = EthereumAddressValidator.parseBigInteger(request.getAmount(), "amount");
        Function function = new Function(
            "withdrawFromInstitutionalTreasury",
            Arrays.asList(new Uint256(amount)),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "WITHDRAW_TREASURY",
            "Treasury withdrawal",
            formatLabTokens(amount)
        );
        return InstitutionalAdminResponse.success(
            "Treasury withdrawal completed successfully",
            txHash,
            "WITHDRAW_TREASURY"
        );
    }

    /**
     * Send a transaction to the blockchain
     */
    private String sendTransaction(Credentials credentials, Function function) throws Exception {
        // Rate limiting check
        if (!rateLimitService.allowTransaction(credentials.getAddress())) {
            throw new RuntimeException("Rate limit exceeded. Too many transactions per hour.");
        }
        
        // Encode function call
        String encodedFunction = FunctionEncoder.encode(function);

        // Get nonce
        EthGetTransactionCount ethGetTransactionCount = web3j.ethGetTransactionCount(
            credentials.getAddress(), DefaultBlockParameterName.LATEST).send();
        BigInteger nonce = ethGetTransactionCount.getTransactionCount();

        // Create transaction
        BigInteger gasLimit = BigInteger.valueOf(300000); // Reasonable gas limit for contract calls
        BigInteger gasPrice = Convert.toWei("20", Convert.Unit.GWEI).toBigInteger();

        RawTransaction rawTransaction = RawTransaction.createTransaction(
            nonce,
            gasPrice,
            gasLimit,
            contractAddress,
            encodedFunction
        );

        // Sign transaction
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        String hexValue = Numeric.toHexString(signedMessage);

        // Send transaction
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

        if (ethSendTransaction.hasError()) {
            throw new RuntimeException("Transaction failed: " + ethSendTransaction.getError().getMessage());
        }

        return ethSendTransaction.getTransactionHash();
    }

    private void recordAdminTransaction(
        String providerAddress,
        String txHash,
        String type,
        String description,
        String amountDisplay
    ) {
        if (providerAddress == null || providerAddress.isBlank()) {
            providerAddress = institutionalWalletService.getInstitutionalWalletAddress();
        }
        if (providerAddress == null || providerAddress.isBlank()) {
            return;
        }
        analyticsService.recordTransaction(
            providerAddress,
            new InstitutionalAnalyticsService.TransactionRecord(
                txHash,
                type,
                description,
                amountDisplay,
                System.currentTimeMillis(),
                "submitted"
            )
        );
    }

    private String formatLabTokens(BigInteger rawValue) {
        if (rawValue == null) {
            return null;
        }
        BigDecimal decimal = new BigDecimal(rawValue).movePointLeft(LAB_TOKEN_DECIMALS);
        return decimal.stripTrailingZeros().toPlainString() + " LAB";
    }

    private String formatPeriodDays(BigInteger seconds) {
        if (seconds == null) {
            return null;
        }
        BigDecimal days = new BigDecimal(seconds)
            .divide(BigDecimal.valueOf(86_400), 2, RoundingMode.HALF_UP);
        return days.stripTrailingZeros().toPlainString() + " days";
    }
}
