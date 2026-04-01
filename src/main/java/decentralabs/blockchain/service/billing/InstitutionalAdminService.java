package decentralabs.blockchain.service.billing;

import decentralabs.blockchain.service.RateLimitService;
import decentralabs.blockchain.service.persistence.AntiReplayService;
import decentralabs.blockchain.service.wallet.InstitutionalWalletService;
import decentralabs.blockchain.service.wallet.WalletService;
import decentralabs.blockchain.dto.billing.InstitutionalAdminRequest;
import decentralabs.blockchain.dto.billing.InstitutionalAdminResponse;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.util.EthereumAddressValidator;
import decentralabs.blockchain.util.LogSanitizer;
import jakarta.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Int256;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthChainId;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

/**
 * Service for institutional billing administrative operations
 * Secured by localhost access and wallet ownership validation
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalAdminService {
    private static final BigInteger RECEIVABLE_ACCRUED = BigInteger.ONE;
    private static final BigInteger RECEIVABLE_QUEUED = BigInteger.valueOf(2);
    private static final BigInteger RECEIVABLE_INVOICED = BigInteger.valueOf(3);
    private static final BigInteger RECEIVABLE_APPROVED = BigInteger.valueOf(4);
    private static final BigInteger RECEIVABLE_PAID = BigInteger.valueOf(5);
    private static final BigInteger RECEIVABLE_REVERSED = BigInteger.valueOf(6);
    private static final BigInteger RECEIVABLE_DISPUTED = BigInteger.valueOf(7);


    private final Web3j web3j;
    private final HttpServletRequest request;
    private final RateLimitService rateLimitService;
    private final InstitutionalWalletService institutionalWalletService;
    private final WalletService walletService;
    private final InstitutionalAnalyticsService analyticsService;
    private final Eip712BillingAdminVerifier adminVerifier;
    private final AntiReplayService antiReplayService;

    private static final int LAB_TOKEN_DECIMALS = CreditUnitConverter.CREDIT_DECIMALS;
    private static final long SIGNATURE_MAX_AGE_MS = 5 * 60 * 1000;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${admin.dashboard.allow-private:false}")
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

    @Value("${billing.collect.max-batch:50}")
    private int defaultCollectMaxBatch;

    @Value("${ethereum.gas.price.default:20}")
    private BigInteger defaultGasPriceGwei;

    @Value("${ethereum.gas.limit.contract:300000}")
    private BigInteger defaultContractGasLimit;

    /**
     * Execute administrative operation with localhost and wallet ownership validation
     */
    public InstitutionalAdminResponse executeAdminOperation(InstitutionalAdminRequest request) {
        try {
            // Step 1: Validate localhost access
            if (!isLocalhostRequest()) {
                return InstitutionalAdminResponse.error("Access denied: administrative operations only allowed from localhost");
            }

            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (institutionalAddress == null || institutionalAddress.isBlank()) {
                return InstitutionalAdminResponse.error("Institutional wallet not configured");
            }

            // Step 2: Verify EIP-712 signature and replay protection
            String signatureError = validateAdminSignature(request, institutionalAddress);
            if (signatureError != null) {
                return InstitutionalAdminResponse.error(signatureError);
            }

            // Step 2: Validate wallet ownership
            if (!isAuthorizedWalletOwner(request.getAdminWalletAddress())) {
                return InstitutionalAdminResponse.error("Access denied: wallet address does not match configured wallet");
            }

            String roleError = validateRoleForOperation(request, institutionalAddress);
            if (roleError != null) {
                return InstitutionalAdminResponse.error(roleError);
            }

            // Step 3: Execute the requested operation
            return executeOperation(request);

        } catch (Exception e) {
            log.error("Error executing admin operation: {}", LogSanitizer.sanitize(e.getMessage()), e);
            return InstitutionalAdminResponse.error("Administrative operation failed: " + e.getMessage());
        }
    }

    /**
     * Executes provider payout request using the institutional wallet configured on the server.
     */
    public InstitutionalAdminResponse requestProviderPayoutWithConfiguredWallet(String labId, String maxBatch) {
        try {
            if (!isLocalhostRequest()) {
                return InstitutionalAdminResponse.error("Access denied: administrative operations only allowed from localhost");
            }

            String institutionalAddress = institutionalWalletService.getInstitutionalWalletAddress();
            if (institutionalAddress == null || institutionalAddress.isBlank()) {
                return InstitutionalAdminResponse.error("Institutional wallet not configured");
            }
            if (!walletService.isLabProvider(institutionalAddress)) {
                return InstitutionalAdminResponse.error("Provider payout requests are only available for provider wallets");
            }

            Credentials credentials = institutionalWalletService.getInstitutionalCredentials();
            InstitutionalAdminRequest request = new InstitutionalAdminRequest();
            request.setOperation(InstitutionalAdminRequest.AdminOperation.COLLECT_LAB_PAYOUT);
            request.setLabId(labId);
            request.setMaxBatch(maxBatch);

            String roleError = validateRoleForOperation(request, institutionalAddress);
            if (roleError != null) {
                return InstitutionalAdminResponse.error(roleError);
            }

            return requestProviderPayout(credentials, request);
        } catch (Exception e) {
            log.error("Error executing server-side payout request: {}", LogSanitizer.sanitize(e.getMessage()), e);
            return InstitutionalAdminResponse.error("Payout request failed: " + e.getMessage());
        }
    }

    /**
     * Check if the request comes from localhost
     */
    private boolean isLocalhostRequest() {
        String remoteAddr = request.getRemoteAddr();

        if ("127.0.0.1".equals(remoteAddr) || remoteAddr.startsWith("127.") || "::1".equals(remoteAddr)) {
            return true;
        }

        if (adminDashboardAllowPrivate && allowPrivateNetworks && isPrivateAddress(remoteAddr)
            && (!accessTokenRequired || hasValidAccessToken())) {
            return true;
        }

        log.warn("Administrative access attempt from non-localhost IP: {}", LogSanitizer.sanitize(remoteAddr));
        return false;
    }

    private boolean hasValidAccessToken() {
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
        if (accessTokenCookie != null && request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if (accessTokenCookie.equals(cookie.getName())) {
                    return accessToken.equals(cookie.getValue());
                }
            }
        }
        return false;
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
            log.warn("Administrative access attempt with unauthorized wallet");
        }

        return isAuthorized;
    }

    private String validateAdminSignature(InstitutionalAdminRequest request, String expectedSigner) {
        if (request == null) {
            return "Missing administrative request";
        }
        Long timestamp = request.getTimestamp();
        if (timestamp == null || timestamp <= 0) {
            return "Missing or invalid signature timestamp";
        }
        long now = System.currentTimeMillis();
        long skew = Math.abs(now - timestamp);
        if (skew > SIGNATURE_MAX_AGE_MS) {
            return "Signature timestamp is expired or too far in the future";
        }

        Eip712BillingAdminVerifier.VerificationResult result = adminVerifier.verify(request, expectedSigner);
        if (!result.valid()) {
            return "Invalid admin signature: " + result.error();
        }

        if (antiReplayService.isTimestampUsed(expectedSigner, timestamp)) {
            return "Replay detected for admin signature";
        }

        return null;
    }

    private String validateRoleForOperation(InstitutionalAdminRequest request, String institutionalAddress) {
        if (request == null || request.getOperation() == null) {
            return "Missing administrative operation";
        }

        boolean isOperator = walletService.isDefaultAdmin(institutionalAddress);
        boolean isInstitution = walletService.isInstitution(institutionalAddress);
        boolean isProvider = walletService.isLabProvider(institutionalAddress);

        return switch (request.getOperation()) {
            case COLLECT_LAB_PAYOUT -> validateProviderPayoutRole(request, institutionalAddress, isProvider);
            case AUTHORIZE_BACKEND,
                 REVOKE_BACKEND,
                 SET_USER_LIMIT,
                 SET_SPENDING_PERIOD,
                 RESET_SPENDING_PERIOD -> isInstitution
                    ? null
                    : "Institution privileges required: this action is only available to wallets with INSTITUTION_ROLE";
            case ADMIN_RESET_BACKEND,
                 ISSUE_SERVICE_CREDITS,
                 ADJUST_SERVICE_CREDITS,
                 TRANSITION_PROVIDER_RECEIVABLE_STATE -> isOperator
                    ? null
                    : "Operator privileges required: this action is only available to wallets with DEFAULT_ADMIN_ROLE";
        };
    }

    private String validateProviderPayoutRole(
        InstitutionalAdminRequest request,
        String institutionalAddress,
        boolean isProvider
    ) {
        if (!isProvider) {
            return "Provider privileges required: payout requests are only available to provider wallets";
        }
        if (request == null || request.getLabId() == null || request.getLabId().isBlank()) {
            return null;
        }

        try {
            BigInteger labId = EthereumAddressValidator.parseBigInteger(request.getLabId(), "labId");
            if (!walletService.isLabOwnedByProvider(institutionalAddress, labId)) {
                return "Provider payout requests are limited to labs associated with this institutional provider wallet";
            }
            return null;
        } catch (IllegalArgumentException ex) {
            return ex.getMessage();
        }
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

            case ISSUE_SERVICE_CREDITS:
                return issueServiceCredits(credentials, request);

            case ADJUST_SERVICE_CREDITS:
                return adjustServiceCredits(credentials, request);

            case TRANSITION_PROVIDER_RECEIVABLE_STATE:
                return transitionProviderReceivableState(credentials, request);

            case COLLECT_LAB_PAYOUT:
                return requestProviderPayout(credentials, request);

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
        log.info("Revoking backend access request received.");
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
        log.info("Resetting spending period request received.");
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

    private InstitutionalAdminResponse issueServiceCredits(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getCreditAccount() == null || request.getCreditAccount().isBlank()) {
            return InstitutionalAdminResponse.error("Credit account required for service credit issuance");
        }
        if (request.getAmount() == null || request.getAmount().isBlank()) {
            return InstitutionalAdminResponse.error("Amount required for service credit issuance");
        }

        String creditAccount = normalizeAddress(request.getCreditAccount(), "creditAccount");
        BigInteger amount = EthereumAddressValidator.parseBigInteger(request.getAmount(), "amount");
        if (amount.compareTo(BigInteger.ZERO) <= 0) {
            return InstitutionalAdminResponse.error("Amount must be greater than zero");
        }

        Function function = new Function(
            "issueServiceCredits",
            Arrays.asList(
                new Address(creditAccount),
                new Uint256(amount),
                new Bytes32(referenceToBytes32(request.getReference()))
            ),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "ISSUE_SERVICE_CREDITS",
            "Issued service credits to " + creditAccount,
            formatServiceCredits(amount)
        );
        return InstitutionalAdminResponse.success(
            "Service credit issuance submitted successfully",
            txHash,
            "ISSUE_SERVICE_CREDITS"
        );
    }

    private InstitutionalAdminResponse adjustServiceCredits(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getCreditAccount() == null || request.getCreditAccount().isBlank()) {
            return InstitutionalAdminResponse.error("Credit account required for service credit adjustment");
        }
        if (request.getCreditDelta() == null || request.getCreditDelta().isBlank()) {
            return InstitutionalAdminResponse.error("creditDelta required for service credit adjustment");
        }

        String creditAccount = normalizeAddress(request.getCreditAccount(), "creditAccount");
        BigInteger delta = parseSignedBigInteger(request.getCreditDelta(), "creditDelta");
        if (delta.equals(BigInteger.ZERO)) {
            return InstitutionalAdminResponse.error("creditDelta must not be zero");
        }

        Function function = new Function(
            "adjustServiceCredits",
            Arrays.asList(
                new Address(creditAccount),
                new Int256(delta),
                new Bytes32(referenceToBytes32(request.getReference()))
            ),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "ADJUST_SERVICE_CREDITS",
            "Adjusted service credits for " + creditAccount + " by " + delta,
            formatServiceCredits(delta.abs())
        );
        return InstitutionalAdminResponse.success(
            "Service credit adjustment submitted successfully",
            txHash,
            "ADJUST_SERVICE_CREDITS"
        );
    }

    private InstitutionalAdminResponse requestProviderPayout(Credentials credentials, InstitutionalAdminRequest request) throws Exception {
        if (request.getLabId() == null || request.getLabId().isBlank()) {
            return InstitutionalAdminResponse.error("Lab ID required for payout request");
        }

        BigInteger labId = EthereumAddressValidator.parseBigInteger(request.getLabId(), "labId");
        if (labId.compareTo(BigInteger.ZERO) <= 0) {
            return InstitutionalAdminResponse.error("Lab ID must be greater than zero");
        }

        BigInteger maxBatch;
        if (request.getMaxBatch() == null || request.getMaxBatch().isBlank()) {
            maxBatch = BigInteger.valueOf(sanitizeBatch(defaultCollectMaxBatch));
        } else {
            maxBatch = EthereumAddressValidator.parseBigInteger(request.getMaxBatch(), "maxBatch");
        }

        if (maxBatch.compareTo(BigInteger.ONE) < 0 || maxBatch.compareTo(BigInteger.valueOf(100)) > 0) {
            return InstitutionalAdminResponse.error("maxBatch must be between 1 and 100");
        }

        Function function = new Function(
            "requestProviderPayout",
            Arrays.asList(new Uint256(labId), new Uint256(maxBatch)),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "COLLECT_LAB_PAYOUT",
            "Request provider payout for lab #" + labId + " (maxBatch=" + maxBatch + ")",
            null
        );
        return InstitutionalAdminResponse.success(
            "Provider payout request submitted successfully",
            txHash,
            "COLLECT_LAB_PAYOUT"
        );
    }

    private InstitutionalAdminResponse transitionProviderReceivableState(
        Credentials credentials,
        InstitutionalAdminRequest request
    ) throws Exception {
        if (request.getLabId() == null || request.getLabId().isBlank()) {
            return InstitutionalAdminResponse.error("Lab ID required for provider receivable transition");
        }
        if (request.getAmount() == null || request.getAmount().isBlank()) {
            return InstitutionalAdminResponse.error("Amount required for provider receivable transition");
        }
        if (request.getFromReceivableState() == null || request.getFromReceivableState().isBlank()) {
            return InstitutionalAdminResponse.error("fromReceivableState required for provider receivable transition");
        }
        if (request.getToReceivableState() == null || request.getToReceivableState().isBlank()) {
            return InstitutionalAdminResponse.error("toReceivableState required for provider receivable transition");
        }

        BigInteger labId = EthereumAddressValidator.parseBigInteger(request.getLabId(), "labId");
        if (labId.compareTo(BigInteger.ZERO) <= 0) {
            return InstitutionalAdminResponse.error("Lab ID must be greater than zero");
        }

        BigInteger amount = EthereumAddressValidator.parseBigInteger(request.getAmount(), "amount");
        if (amount.compareTo(BigInteger.ZERO) <= 0) {
            return InstitutionalAdminResponse.error("Amount must be greater than zero");
        }

        BigInteger fromState = EthereumAddressValidator.parseBigInteger(
            request.getFromReceivableState(),
            "fromReceivableState"
        );
        BigInteger toState = EthereumAddressValidator.parseBigInteger(request.getToReceivableState(), "toReceivableState");

        if (!isSupportedReceivableState(fromState) || !isSupportedReceivableState(toState)) {
            return InstitutionalAdminResponse.error("Invalid provider receivable lifecycle state");
        }
        if (!isValidReceivableTransition(fromState, toState)) {
            return InstitutionalAdminResponse.error("Invalid provider receivable lifecycle transition");
        }

        Function function = new Function(
            "transitionProviderReceivableState",
            Arrays.asList(
                new Uint256(labId),
                new Uint256(fromState),
                new Uint256(toState),
                new Uint256(amount),
                new Bytes32(referenceToBytes32(request.getReference()))
            ),
            Collections.emptyList()
        );

        String txHash = sendTransaction(credentials, function);
        recordAdminTransaction(
            credentials.getAddress(),
            txHash,
            "TRANSITION_PROVIDER_RECEIVABLE_STATE",
            "Transition provider receivable for lab #" + labId + " from " + receivableStateLabel(fromState)
                + " to " + receivableStateLabel(toState),
            formatLabTokens(amount)
        );
        return InstitutionalAdminResponse.success(
            "Provider receivable transition submitted successfully",
            txHash,
            "TRANSITION_PROVIDER_RECEIVABLE_STATE"
        );
    }

    private boolean isSupportedReceivableState(BigInteger state) {
        return state != null && state.compareTo(RECEIVABLE_ACCRUED) >= 0 && state.compareTo(RECEIVABLE_DISPUTED) <= 0;
    }

    private boolean isValidReceivableTransition(BigInteger fromState, BigInteger toState) {
        if (fromState == null || toState == null || fromState.equals(toState)) {
            return false;
        }
        if (fromState.equals(RECEIVABLE_PAID) || fromState.equals(RECEIVABLE_REVERSED)) {
            return false;
        }
        if (fromState.equals(RECEIVABLE_ACCRUED)) {
            return toState.equals(RECEIVABLE_QUEUED)
                || toState.equals(RECEIVABLE_DISPUTED)
                || toState.equals(RECEIVABLE_REVERSED);
        }
        if (fromState.equals(RECEIVABLE_QUEUED)) {
            return toState.equals(RECEIVABLE_INVOICED)
                || toState.equals(RECEIVABLE_APPROVED)
                || toState.equals(RECEIVABLE_DISPUTED)
                || toState.equals(RECEIVABLE_REVERSED);
        }
        if (fromState.equals(RECEIVABLE_INVOICED)) {
            return toState.equals(RECEIVABLE_APPROVED)
                || toState.equals(RECEIVABLE_DISPUTED)
                || toState.equals(RECEIVABLE_REVERSED);
        }
        if (fromState.equals(RECEIVABLE_APPROVED)) {
            return toState.equals(RECEIVABLE_PAID)
                || toState.equals(RECEIVABLE_DISPUTED)
                || toState.equals(RECEIVABLE_REVERSED);
        }
        if (fromState.equals(RECEIVABLE_DISPUTED)) {
            return toState.equals(RECEIVABLE_INVOICED)
                || toState.equals(RECEIVABLE_APPROVED)
                || toState.equals(RECEIVABLE_REVERSED);
        }
        return false;
    }

    private String receivableStateLabel(BigInteger state) {
        if (RECEIVABLE_ACCRUED.equals(state)) return "ACCRUED";
        if (RECEIVABLE_QUEUED.equals(state)) return "QUEUED";
        if (RECEIVABLE_INVOICED.equals(state)) return "INVOICED";
        if (RECEIVABLE_APPROVED.equals(state)) return "APPROVED";
        if (RECEIVABLE_PAID.equals(state)) return "PAID";
        if (RECEIVABLE_REVERSED.equals(state)) return "REVERSED";
        if (RECEIVABLE_DISPUTED.equals(state)) return "DISPUTED";
        return "UNKNOWN";
    }

    /**
     * Send a transaction to the blockchain
     */
    private synchronized String sendTransaction(Credentials credentials, Function function) throws Exception {
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

        BigInteger gasPrice = resolveGasPriceWei();
        BigInteger gasLimit = resolveContractGasLimit(credentials.getAddress(), nonce, encodedFunction);

        RawTransaction rawTransaction = RawTransaction.createTransaction(
            nonce,
            gasPrice,
            gasLimit,
            contractAddress,
            encodedFunction
        );

        EthChainId ethChainId = web3j.ethChainId().send();
        BigInteger chainId = ethChainId != null ? ethChainId.getChainId() : null;
        if (chainId == null || chainId.compareTo(BigInteger.ZERO) <= 0) {
            throw new RuntimeException("Unable to resolve blockchain chainId for EIP-155 signing.");
        }

        // Sign EIP-155 transaction with chainId (required by many RPC providers)
        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, chainId.longValueExact(), credentials);
        String hexValue = Numeric.toHexString(signedMessage);

        // Send transaction
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

        if (ethSendTransaction.hasError()) {
            throw new RuntimeException("Transaction failed: " + ethSendTransaction.getError().getMessage());
        }

        return ethSendTransaction.getTransactionHash();
    }

    private BigInteger resolveGasPriceWei() {
        BigInteger fallback = Convert.toWei(defaultGasPriceGwei.toString(), Convert.Unit.GWEI).toBigInteger();
        try {
            var response = web3j.ethGasPrice().send();
            if (response != null && response.getGasPrice() != null && response.getGasPrice().compareTo(BigInteger.ZERO) > 0) {
                return response.getGasPrice();
            }
        } catch (Exception ex) {
            log.warn("Unable to resolve gas price from node, using default {} gwei: {}", defaultGasPriceGwei, ex.getMessage());
        }
        return fallback;
    }

    private BigInteger resolveContractGasLimit(String from, BigInteger nonce, String encodedFunction) {
        BigInteger fallback = sanitizeContractGasLimit(defaultContractGasLimit);
        try {
            EthEstimateGas estimate = web3j.ethEstimateGas(
                org.web3j.protocol.core.methods.request.Transaction.createFunctionCallTransaction(
                    from,
                    nonce,
                    null,
                    null,
                    contractAddress,
                    encodedFunction
                )
            ).send();

            if (estimate != null && !estimate.hasError() && estimate.getAmountUsed() != null
                && estimate.getAmountUsed().compareTo(BigInteger.ZERO) > 0) {
                // Add 20% safety margin to reduce OOG failures on state-changing calls.
                BigInteger withMargin = estimate.getAmountUsed().multiply(BigInteger.valueOf(120)).divide(BigInteger.valueOf(100));
                return withMargin.max(fallback);
            }

            if (estimate != null && estimate.hasError()) {
                log.warn("Gas estimation failed for admin tx: {}", estimate.getError().getMessage());
            }
        } catch (Exception ex) {
            log.warn("Unable to estimate gas for admin tx, using fallback {}: {}", fallback, ex.getMessage());
        }
        return fallback;
    }

    private BigInteger sanitizeContractGasLimit(BigInteger configuredLimit) {
        if (configuredLimit == null) {
            return BigInteger.valueOf(300000);
        }
        if (configuredLimit.compareTo(BigInteger.valueOf(21000)) < 0) {
            return BigInteger.valueOf(300000);
        }
        return configuredLimit;
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

    private String formatServiceCredits(BigInteger rawValue) {
        if (rawValue == null) {
            return null;
        }
        BigDecimal decimal = new BigDecimal(rawValue).movePointLeft(LAB_TOKEN_DECIMALS);
        return decimal.stripTrailingZeros().toPlainString() + " credits";
    }

    private String formatPeriodDays(BigInteger seconds) {
        if (seconds == null) {
            return null;
        }
        BigDecimal days = new BigDecimal(seconds)
            .divide(BigDecimal.valueOf(86_400), 2, RoundingMode.HALF_UP);
        return days.stripTrailingZeros().toPlainString() + " days";
    }

    private int sanitizeBatch(int configuredBatch) {
        if (configuredBatch < 1) {
            return 1;
        }
        if (configuredBatch > 100) {
            return 100;
        }
        return configuredBatch;
    }

    private BigInteger parseSignedBigInteger(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        try {
            return new BigInteger(value.trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid " + fieldName + ": " + value);
        }
    }

    private String normalizeAddress(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        String normalized = value.trim();
        if (!EthereumAddressValidator.isValidAddress(normalized)) {
            throw new IllegalArgumentException("Invalid " + fieldName + ": " + value);
        }
        return "0x" + Numeric.cleanHexPrefix(normalized).toLowerCase(Locale.ROOT);
    }

    private byte[] referenceToBytes32(String reference) {
        String safeReference = reference == null ? "" : reference;
        byte[] hashed = org.web3j.crypto.Hash.sha3(safeReference.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return hashed;
    }
}
