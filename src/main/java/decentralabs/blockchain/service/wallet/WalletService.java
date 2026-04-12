package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.contract.Diamond;
import decentralabs.blockchain.event.NetworkSwitchEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.ReadonlyTransactionManager;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.billing.InstitutionalUserFinancialStats;
import decentralabs.blockchain.dto.wallet.*;
import decentralabs.blockchain.util.CreditUnitConverter;
import decentralabs.blockchain.service.persistence.WalletPersistenceService;
import decentralabs.blockchain.util.LogSanitizer;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Service for managing Ethereum wallets with secure encryption
 * 
 * SECURITY:
 * - Wallets are encrypted using AES-256-GCM (military-grade encryption)
 * - Key derivation via PBKDF2-HMAC-SHA256 with 65,536 iterations
 * - Random salt (16 bytes) and IV (12 bytes) per encryption
 * - NOT the legacy Base64(password:privateKey) format
 * - Encrypted format: Base64(salt + iv + ciphertext + auth_tag)
 * 
 * WARNING:
 * - Wallets stored in-memory (ConcurrentHashMap) - lost on restart
 * - Use Redis/Database for production persistence
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WalletService {

    private final WalletPersistenceService walletPersistenceService;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${wallet.address}")
    private String defaultWalletAddress;

    // Network-specific RPC configurations (comma-separated for fallback)
    @Value("${ethereum.mainnet.rpc.url:https://eth.public-rpc.com}")
    private String mainnetRpcUrl;

    @Value("${ethereum.sepolia.rpc.url:https://rpc.sepolia.org}")
    private String sepoliaRpcUrl;
    
    @Value("${blockchain.network.active:sepolia}")
    private String defaultNetwork;

    // AES-GCM parameters
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 128 bits
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int AES_KEY_SIZE = 256;
    private static final int MAX_PROVIDER_LABS_QUERY = 100;
    private static final String DEFAULT_ADMIN_ROLE_HEX =
        "0x0000000000000000000000000000000000000000000000000000000000000000";
    private static final String INSTITUTION_ROLE_HEX = Hash.sha3String("INSTITUTION_ROLE");

    // Cache of Web3j connections per network (with fallback URLs)
    private final Map<String, Web3j> web3jInstances = new ConcurrentHashMap<>();
    private final Map<String, List<String>> networkRpcUrls = new ConcurrentHashMap<>();
    private final Map<String, Integer> currentRpcIndex = new ConcurrentHashMap<>();
    private String activeNetwork;
    
    // Shared OkHttpClient with connection pooling for all Web3j instances
    private OkHttpClient httpClient;

    @PostConstruct
    public void init() {
        // Initialize OkHttpClient with connection pooling
        this.httpClient = new OkHttpClient.Builder()
            .connectionPool(new okhttp3.ConnectionPool(10, 5, TimeUnit.MINUTES))
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
        
        // Parse RPC URLs (comma-separated list for fallback)
        networkRpcUrls.put("mainnet", parseRpcUrls(mainnetRpcUrl));
        networkRpcUrls.put("sepolia", parseRpcUrls(sepoliaRpcUrl));
        
        // Initialize RPC index to 0 for each network
        currentRpcIndex.put("mainnet", 0);
        currentRpcIndex.put("sepolia", 0);
            
        // Use configured default network
        this.activeNetwork = resolveNetworkId(defaultNetwork);
        List<String> activeUrls = networkRpcUrls.getOrDefault(activeNetwork, List.of());
        log.info("WalletService initialized with active network: {} using RPC endpoints: {}", 
                 activeNetwork, String.join(", ", activeUrls));
    }
    
    /**
     * Parse comma-separated RPC URLs into a list
     */
    private List<String> parseRpcUrls(String rpcUrlConfig) {
        return Arrays.stream(rpcUrlConfig.split(","))
                     .map(String::trim)
                     .filter(url -> !url.isEmpty())
                     .toList();
    }

    private String resolveNetworkId(String requestedNetwork) {
        if (requestedNetwork != null && networkRpcUrls.containsKey(requestedNetwork)) {
            return requestedNetwork;
        }
        if (defaultNetwork != null && networkRpcUrls.containsKey(defaultNetwork)) {
            return defaultNetwork;
        }
        return networkRpcUrls.keySet().stream().findFirst().orElse("sepolia");
    }

    /**
     * Creates a new Ethereum wallet
     */
    public WalletResponse createWallet(String password) {
        try {
            // Check if a wallet already exists
            String existingWallet = walletPersistenceService.getCurrentWalletAddress();
            boolean replacingExisting = existingWallet != null;
            
            // Generate random private key
            ECKeyPair keyPair = Keys.createEcKeyPair();
            String privateKey = Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
            String address = "0x" + Keys.getAddress(keyPair.getPublicKey());

            // Encrypt the private key
            String encryptedPrivateKey = encryptPrivateKey(privateKey, password);

            // Save using persistence service (replaces any existing wallet)
            walletPersistenceService.saveWallet(address, encryptedPrivateKey);

            String message = replacingExisting 
                ? String.format("New institutional wallet created (replaced previous wallet %s)", existingWallet)
                : "Institutional wallet created successfully";
            
            log.info("Created new institutional wallet: {} (replaced: {})", address, replacingExisting);

            return WalletResponse.builder()
                .success(true)
                .address(address)
                .privateKey(privateKey)
                .encryptedPrivateKey(encryptedPrivateKey)
                .message(message)
                .build();

        } catch (Exception e) {
            log.error("Error creating wallet", e);
            return WalletResponse.error("Failed to create wallet: " + e.getMessage());
        }
    }

    /**
     * Imports a wallet from private key or mnemonic.
     * Note: This replaces any existing institutional wallet.
     */
    public WalletResponse importWallet(WalletImportRequest request) {
        try {
            // Check if a wallet already exists
            String existingWallet = walletPersistenceService.getCurrentWalletAddress();
            boolean replacingExisting = existingWallet != null;

            String address;
            String encryptedPrivateKey;

            String privateKey = request.getPrivateKey();
            String mnemonic = request.getMnemonic();

            if (privateKey != null && !privateKey.trim().isEmpty()) {
                String normalizedPrivateKey = privateKey.trim().startsWith("0x")
                    ? privateKey.trim()
                    : "0x" + privateKey.trim();

                // Import from private key
                ECKeyPair keyPair = ECKeyPair.create(Numeric.toBigInt(normalizedPrivateKey));
                address = "0x" + Keys.getAddress(keyPair.getPublicKey());
                encryptedPrivateKey = encryptPrivateKey(normalizedPrivateKey, request.getPassword());
            } else if (mnemonic != null && !mnemonic.trim().isEmpty()) {
                // Import from mnemonic (BIP39)
                Credentials credentials = WalletUtils.loadBip39Credentials(
                    request.getPassword(), mnemonic.trim());
                address = credentials.getAddress();
                encryptedPrivateKey = encryptPrivateKey(
                    Numeric.toHexStringWithPrefix(credentials.getEcKeyPair().getPrivateKey()),
                    request.getPassword());
            } else {
                return WalletResponse.error("Either privateKey or mnemonic must be provided");
            }

            // Persist imported wallet so it becomes the active institutional wallet
            walletPersistenceService.saveWallet(address, encryptedPrivateKey);

            String message = replacingExisting 
                ? String.format("Institutional wallet imported (replaced previous wallet %s)", existingWallet)
                : "Institutional wallet imported successfully";

            log.info("Imported wallet: {} {}", address, 
                replacingExisting ? "(replaced " + existingWallet + ")" : "");

            return WalletResponse.builder()
                .success(true)
                .address(address)
                .encryptedPrivateKey(encryptedPrivateKey)
                .message(message)
                .build();

        } catch (Exception e) {
            log.error("Error importing wallet", e);
            return WalletResponse.error("Failed to import wallet: " + e.getMessage());
        }
    }

    /**
     * Reveals the institutional wallet private key after validating the password.
     * Only intended for localhost administrative access.
     */
    public WalletResponse revealInstitutionalPrivateKey(String password) {
        String walletAddress = walletPersistenceService.getCurrentWalletAddress();
        if (walletAddress == null || walletAddress.isBlank()) {
            return WalletResponse.error("Institutional wallet is not configured");
        }

        String encryptedWallet = walletPersistenceService.getWallet(walletAddress);
        if (encryptedWallet == null || encryptedWallet.isBlank()) {
            return WalletResponse.error("Encrypted wallet data not found");
        }

        try {
            String privateKey = decryptPrivateKey(encryptedWallet, password);
            return WalletResponse.builder()
                .success(true)
                .address(walletAddress)
                .privateKey(privateKey)
                .message("Private key revealed successfully")
                .build();
        } catch (RuntimeException ex) {
            log.warn("Failed to reveal private key: {}", ex.getMessage());
            return WalletResponse.error("Invalid password for institutional wallet");
        }
    }

    /**
     * Gets the balance of an address
     */
    public BalanceResponse getBalance(String address) {
        return getBalance(address, activeNetwork);
    }

    public BalanceResponse getBalance(String address, String networkId) {
        try {
            String resolvedNetwork = resolveNetworkId(networkId);
            Web3j web3j = getWeb3jInstanceForNetwork(resolvedNetwork);
            EthGetBalance balance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send();

            BigDecimal ethBalance = Convert.fromWei(balance.getBalance().toString(), Convert.Unit.ETHER);

            BigInteger serviceCreditBalance = getServiceCreditBalance(address, resolvedNetwork);
            String labBalance = CreditUnitConverter.formatRawCredits(serviceCreditBalance);
            String labCreditAddress = getLabCreditAddress(resolvedNetwork);

            return BalanceResponse.builder()
                .success(true)
                .address(address)
                .balanceWei(balance.getBalance().toString())
                .balanceEth(ethBalance.toString())
                .labCreditAddress(labCreditAddress)
                .labBalanceRaw(serviceCreditBalance.toString())
                .labBalance(labBalance)
                .network(resolvedNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting balance");
            log.debug("Error getting balance (context omitted for safety)", e);
            return BalanceResponse.error("Failed to get balance: " + e.getMessage());
        }
    }

    /**
     * Returns the address used by clients for service-credit contract interactions.
     *
     * The current architecture exposes service-credit functions directly in the Diamond,
     * so this resolves to the configured Diamond address.
     */
    private String getLabCreditAddress() {
        return getLabCreditAddress(activeNetwork);
    }

    private String getLabCreditAddress(String networkId) {
        resolveNetworkId(networkId);
        return contractAddress;
    }
    
    /**
     * Gets the institutional user spending limit from the Diamond contract
     * @return User spending limit in credit base units (5 decimals), or null if error
     */
    public BigInteger getInstitutionalUserLimit(String providerAddress) {
        if (providerAddress == null || providerAddress.isBlank()) {
            return null;
        }
        try {
            Web3j web3j = getWeb3jInstance();
            
            // Call getInstitutionalUserLimit() function on Diamond contract
            // function getInstitutionalUserLimit(address provider) public view returns (uint256)
            Function function = new Function(
                "getInstitutionalUserLimit",
                Collections.singletonList(new Address(providerAddress)),
                Collections.singletonList(new TypeReference<Uint256>() {})
            );
            
            String encodedFunction = FunctionEncoder.encode(function);
            
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();
            
            if (response.hasError()) {
                log.warn("Error calling getInstitutionalUserLimit() for {}: {}", LogSanitizer.maskIdentifier(providerAddress), LogSanitizer.sanitize(response.getError().getMessage()));
                return null;
            }
            
            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                BigInteger limit = (BigInteger) decoded.get(0).getValue();
                log.info("Institutional user limit for {}: {}", LogSanitizer.maskIdentifier(providerAddress), limit);
                return limit;
            }
            
            return null;
        } catch (Exception e) {
            log.error("Error getting institutional user limit from Diamond contract", e);
            return null;
        }
    }
    
    /**
     * Gets the institutional spending period duration from the Diamond contract
     * @return Period duration in seconds, or null if error
     */
    public BigInteger getInstitutionalSpendingPeriod(String providerAddress) {
        if (providerAddress == null || providerAddress.isBlank()) {
            return null;
        }
        try {
            Web3j web3j = getWeb3jInstance();
            
            // Call getInstitutionalSpendingPeriod() function on Diamond contract
            // function getInstitutionalSpendingPeriod(address provider) public view returns (uint256)
            Function function = new Function(
                "getInstitutionalSpendingPeriod",
                Collections.singletonList(new Address(providerAddress)),
                Collections.singletonList(new TypeReference<Uint256>() {})
            );
            
            String encodedFunction = FunctionEncoder.encode(function);
            
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();
            
            if (response.hasError()) {
                log.warn("Error calling getInstitutionalSpendingPeriod()");
                log.debug("getInstitutionalSpendingPeriod() RPC error (details omitted)");
                return null;
            }
            
            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                BigInteger period = (BigInteger) decoded.get(0).getValue();
                log.debug("Institutional spending period retrieved");
                return period;
            }
            
            return null;
        } catch (Exception e) {
            log.error("Error getting institutional spending period from Diamond contract", e);
            return null;
        }
    }
    
    /**
     * Gets the institutional billing balance from the Diamond contract
     * @return Billing balance in base units (5 decimals), or null if error
     */
    public BigInteger getInstitutionalBillingBalance(String providerAddress) {
        if (providerAddress == null || providerAddress.isBlank()) {
            return null;
        }
        try {
            Web3j web3j = getWeb3jInstance();
            
            // Call getInstitutionalTreasuryBalance() function on Diamond contract
            // function getInstitutionalTreasuryBalance(address provider) public view returns (uint256)
            Function function = new Function(
                "getInstitutionalTreasuryBalance",
                Collections.singletonList(new Address(providerAddress)),
                Collections.singletonList(new TypeReference<Uint256>() {})
            );
            
            String encodedFunction = FunctionEncoder.encode(function);
            
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();
            
            if (response.hasError()) {
                log.warn("Error calling getInstitutionalTreasuryBalance()");
                log.debug("getInstitutionalTreasuryBalance() RPC error (details omitted)");
                return null;
            }
            
            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                BigInteger balance = (BigInteger) decoded.get(0).getValue();
                log.debug("Institutional billing balance retrieved");
                return balance;
            }
            
            return null;
        } catch (Exception e) {
            log.error("Error getting institutional billing balance from Diamond contract", e);
            return null;
        }
    }

    /**
     * Checks if an address is registered as a lab provider
     * @param address The address to check
     * @return true if the address is a lab provider, false otherwise
     */
    public boolean isLabProvider(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        try {
            Web3j web3j = getWeb3jInstance();
            
            // Call isLabProvider(address) function on Diamond contract
            Function function = new Function(
                "isLabProvider",
                Collections.singletonList(new Address(address)),
                Collections.singletonList(new TypeReference<org.web3j.abi.datatypes.Bool>() {})
            );
            
            String encodedFunction = FunctionEncoder.encode(function);
            
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();
            
            if (response.hasError()) {
                log.warn("Error calling isLabProvider()");
                return false;
            }
            
            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                return (Boolean) decoded.get(0).getValue();
            }
            
            return false;
        } catch (Exception e) {
            log.error("Error checking isLabProvider from Diamond contract", e);
            return false;
        }
    }

    /**
     * Lists lab IDs owned by a provider wallet.
     *
     * <p>Ownership is resolved strictly via ERC-721 ownerOf semantics so the
     * backend matches the authorization enforced on-chain for payout requests.
     */
    public List<BigInteger> getLabsOwnedByProvider(String providerAddress) {
        if (providerAddress == null || providerAddress.isBlank()) {
            return List.of();
        }
        try {
            Web3j web3j = getWeb3jInstance();
            return getDirectlyOwnedLabs(providerAddress, web3j);
        } catch (Exception e) {
            log.error("Error getting provider labs from Diamond contract", e);
            return List.of();
        }
    }

    /**
     * Checks whether a given lab ID is owned by a provider wallet.
     */
    public boolean isLabOwnedByProvider(String providerAddress, BigInteger labId) {
        if (providerAddress == null || providerAddress.isBlank() || labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
            return false;
        }
        try {
            Web3j web3j = getWeb3jInstance();
            Optional<String> owner = getLabOwner(labId, web3j);
            return owner.isPresent() && owner.get().equalsIgnoreCase(providerAddress);
        } catch (Exception e) {
            log.warn("Failed to resolve provider association for lab {}", labId, e);
            return false;
        }
    }

    /**
     * Returns a metadata URI for a lab token.
     * Tries ERC-721 tokenURI first and falls back to Lab.base.uri from getLab().
     */
    public Optional<String> getLabTokenUri(BigInteger labId) {
        if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
            return Optional.empty();
        }
        try {
            Web3j web3j = getWeb3jInstance();
            Function function = new Function(
                "tokenURI",
                Collections.singletonList(new Uint256(labId)),
                Collections.singletonList(new TypeReference<Utf8String>() {})
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                log.debug(
                    "Error calling tokenURI() for lab {}: {}",
                    labId,
                    LogSanitizer.sanitize(response.getError().getMessage())
                );
                return getLabBaseUri(labId);
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return getLabBaseUri(labId);
            }

            String uri = Objects.toString(decoded.get(0).getValue(), "").trim();
            if (!uri.isEmpty()) {
                return Optional.of(uri);
            }
            return getLabBaseUri(labId);
        } catch (Exception e) {
            log.debug("Failed to resolve tokenURI for lab {}: {}", labId, LogSanitizer.sanitize(e.getMessage()));
            return getLabBaseUri(labId);
        }
    }

    private Optional<String> getLabBaseUri(BigInteger labId) {
        try {
            Web3j web3j = getWeb3jInstance();
            Diamond diamond = Diamond.load(
                contractAddress,
                web3j,
                new ReadonlyTransactionManager(web3j, contractAddress),
                new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO)
            );

            Diamond.Lab lab = diamond.getLab(labId).send();
            if (lab == null || lab.base == null) {
                return Optional.empty();
            }
            String uri = lab.base.uri;
            if (uri == null) {
                return Optional.empty();
            }
            String trimmed = uri.trim();
            return trimmed.isEmpty() ? Optional.empty() : Optional.of(trimmed);
        } catch (Exception e) {
            log.debug("Failed to resolve Lab.base.uri for lab {}: {}", labId, LogSanitizer.sanitize(e.getMessage()));
            return Optional.empty();
        }
    }

    /**
     * Returns lab IDs owned by a provider by paginating getLabsPaginated and
     * filtering via ownerOf. The Diamond contract does not implement
     * ERC721Enumerable (no tokenOfOwnerByIndex), so the correct approach is to
     * enumerate all listed labs and check ERC721 ownership for each.
     */
    private List<BigInteger> getDirectlyOwnedLabs(String providerAddress, Web3j web3j) {
        try {
            List<BigInteger> allLabIds = getAllLabIds(web3j);
            if (allLabIds.isEmpty()) {
                return List.of();
            }

            // Step 2: for each lab ID, check ERC721 owner
            List<BigInteger> owned = new ArrayList<>();
            for (BigInteger labId : allLabIds) {
                Optional<String> owner = getLabOwner(labId, web3j);
                if (owner.isPresent() && owner.get().equalsIgnoreCase(providerAddress)) {
                    owned.add(labId);
                }
            }

            owned.sort(Comparator.naturalOrder());
            return owned;
        } catch (Exception e) {
            log.warn("Failed to get directly owned labs for provider {}", LogSanitizer.maskIdentifier(providerAddress), e);
            return List.of();
        }
    }

    public List<BigInteger> getAllLabIds() {
        try {
            return getAllLabIds(getWeb3jInstance());
        } catch (Exception e) {
            log.warn("Failed to get all lab IDs", e);
            return List.of();
        }
    }

    private List<BigInteger> getAllLabIds(Web3j web3j) throws Exception {
        Function paginated = new Function(
            "getLabsPaginated",
            Arrays.asList(new Uint256(BigInteger.ZERO), new Uint256(BigInteger.valueOf(MAX_PROVIDER_LABS_QUERY))),
            Arrays.asList(
                new TypeReference<DynamicArray<Uint256>>() {},
                new TypeReference<Uint256>() {}
            )
        );
        String encodedPaginated = FunctionEncoder.encode(paginated);
        EthCall paginatedResponse = web3j.ethCall(
            Transaction.createEthCallTransaction(null, contractAddress, encodedPaginated),
            DefaultBlockParameterName.LATEST
        ).send();

        if (paginatedResponse.hasError()) {
            log.warn("Error calling getLabsPaginated()");
            return List.of();
        }

        @SuppressWarnings("rawtypes")
        List<Type> decodedPaginated = FunctionReturnDecoder.decode(
            paginatedResponse.getValue(),
            paginated.getOutputParameters()
        );
        if (decodedPaginated.isEmpty()) {
            return List.of();
        }

        @SuppressWarnings("unchecked")
        DynamicArray<Uint256> allIds = (DynamicArray<Uint256>) decodedPaginated.get(0);
        if (allIds.getValue() == null || allIds.getValue().isEmpty()) {
            return List.of();
        }

        List<BigInteger> labIds = new ArrayList<>();
        for (Uint256 idToken : allIds.getValue()) {
            labIds.add(idToken.getValue());
        }
        labIds.sort(Comparator.naturalOrder());
        return labIds;
    }

    private Optional<String> getLabOwner(BigInteger labId, Web3j web3j) {
        try {
            Function function = new Function(
                "ownerOf",
                Collections.singletonList(new Uint256(labId)),
                Collections.singletonList(new TypeReference<Address>() {})
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                return Optional.empty();
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return Optional.empty();
            }
            String owner = decoded.get(0).getValue().toString();
            return owner == null || owner.isBlank() ? Optional.empty() : Optional.of(owner);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private String normalizeUri(String uri) {
        if (uri == null) {
            return "";
        }
        String normalized = uri.trim();
        while (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    /**
     * Returns the provider receivable currently accrued or settleable for a specific lab.
     */
    public Optional<ProviderReceivableStatus> getProviderReceivableStatus(BigInteger labId) {
        if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
            return Optional.empty();
        }
        try {
            Web3j web3j = getWeb3jInstance();
            Function summaryFunction = new Function(
                "getLabProviderReceivable",
                Collections.singletonList(new Uint256(labId)),
                Arrays.asList(
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {}
                )
            );

            String encodedFunction = FunctionEncoder.encode(summaryFunction);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                log.warn("Error calling getLabProviderReceivable() for lab {}", labId);
                return Optional.empty();
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), summaryFunction.getOutputParameters());
            if (decoded.size() < 4) {
                return Optional.empty();
            }

            BigInteger accruedReceivable = BigInteger.ZERO;
            BigInteger settlementQueued = BigInteger.ZERO;
            BigInteger invoicedReceivable = BigInteger.ZERO;
            BigInteger approvedReceivable = BigInteger.ZERO;
            BigInteger paidReceivable = BigInteger.ZERO;
            BigInteger reversedReceivable = BigInteger.ZERO;
            BigInteger disputedReceivable = BigInteger.ZERO;
            BigInteger lastAccruedAt = BigInteger.ZERO;

            try {
                Function lifecycleFunction = new Function(
                    "getLabProviderReceivableLifecycle",
                    Collections.singletonList(new Uint256(labId)),
                    Arrays.asList(
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {},
                        new TypeReference<Uint256>() {}
                    )
                );

                String encodedLifecycleFunction = FunctionEncoder.encode(lifecycleFunction);
                EthCall lifecycleResponse = web3j.ethCall(
                    Transaction.createEthCallTransaction(null, contractAddress, encodedLifecycleFunction),
                    DefaultBlockParameterName.LATEST
                ).send();

                if (!lifecycleResponse.hasError()) {
                    @SuppressWarnings("rawtypes")
                    List<Type> decodedLifecycle =
                        FunctionReturnDecoder.decode(lifecycleResponse.getValue(), lifecycleFunction.getOutputParameters());
                    if (decodedLifecycle.size() >= 8) {
                        accruedReceivable = (BigInteger) decodedLifecycle.get(0).getValue();
                        settlementQueued = (BigInteger) decodedLifecycle.get(1).getValue();
                        invoicedReceivable = (BigInteger) decodedLifecycle.get(2).getValue();
                        approvedReceivable = (BigInteger) decodedLifecycle.get(3).getValue();
                        paidReceivable = (BigInteger) decodedLifecycle.get(4).getValue();
                        reversedReceivable = (BigInteger) decodedLifecycle.get(5).getValue();
                        disputedReceivable = (BigInteger) decodedLifecycle.get(6).getValue();
                        lastAccruedAt = (BigInteger) decodedLifecycle.get(7).getValue();
                    }
                }
            } catch (Exception lifecycleError) {
                log.warn("Error calling getLabProviderReceivableLifecycle() for lab {}", labId);
            }

            return Optional.of(new ProviderReceivableStatus(
                (BigInteger) decoded.get(0).getValue(),
                (BigInteger) decoded.get(1).getValue(),
                (BigInteger) decoded.get(2).getValue(),
                (BigInteger) decoded.get(3).getValue(),
                accruedReceivable,
                settlementQueued,
                invoicedReceivable,
                approvedReceivable,
                paidReceivable,
                reversedReceivable,
                disputedReceivable,
                lastAccruedAt
            ));
        } catch (Exception e) {
            log.error("Error getting provider receivable status for lab {}", labId, e);
            return Optional.empty();
        }
    }

    /**
     * Simulates requestProviderPayout() via eth_call to determine if payout can be requested now.
     */
    public PayoutRequestSimulationResult simulateProviderPayoutRequest(String callerAddress, BigInteger labId, BigInteger maxBatch) {
        if (callerAddress == null || callerAddress.isBlank()) {
            return new PayoutRequestSimulationResult(false, "Institutional wallet is not configured");
        }
        if (labId == null || labId.compareTo(BigInteger.ZERO) <= 0) {
            return new PayoutRequestSimulationResult(false, "Invalid lab ID");
        }
        if (maxBatch == null || maxBatch.compareTo(BigInteger.ONE) < 0 || maxBatch.compareTo(BigInteger.valueOf(100)) > 0) {
            return new PayoutRequestSimulationResult(false, "maxBatch must be between 1 and 100");
        }

        try {
            Web3j web3j = getWeb3jInstance();
            Function function = new Function(
                "requestProviderPayout",
                Arrays.asList(new Uint256(labId), new Uint256(maxBatch)),
                Collections.emptyList()
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(callerAddress, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                String message = response.getError() != null ? response.getError().getMessage() : "Payout request reverted";
                return new PayoutRequestSimulationResult(false, sanitizeRpcMessage(message));
            }

            String returnData = response.getValue();
            // requestProviderPayout(uint256,uint256) has no return values. Any non-empty return
            // payload indicates a revert payload encoded in the response body.
            if (returnData != null && !returnData.isBlank() && !"0x".equalsIgnoreCase(returnData)) {
                String decodedReason = decodeRevertReason(returnData);
                return new PayoutRequestSimulationResult(
                    false,
                    decodedReason != null ? decodedReason : "Payout request is not available"
                );
            }

            return new PayoutRequestSimulationResult(true, null);
        } catch (Exception e) {
            log.warn("Failed to simulate provider payout request for lab {}", labId, e);
            return new PayoutRequestSimulationResult(false, "Unable to simulate payout request right now");
        }
    }

    /**
     * Returns provider bond information.
     *
     * Staking-related selectors were removed from the current Diamond surface, so
     * the backend now returns an empty structure instead of attempting a failing call.
     */
    public StakeInfo getStakeInfo(String providerAddress) {
        if (providerAddress != null && !providerAddress.isBlank()) {
            log.debug(
                "Returning empty stake info for {} because staking selectors are not exposed by current Diamond ABI",
                LogSanitizer.maskIdentifier(providerAddress)
            );
        }
        return StakeInfo.empty();
    }

    /**
     * Returns per-user financial stats stored on-chain, if that user has interacted before.
     */
    public Optional<InstitutionalUserFinancialStats> getInstitutionalUserFinancialStats(String providerAddress, String puc) {
        if (providerAddress == null || providerAddress.isBlank() || puc == null || puc.isBlank()) {
            return Optional.empty();
        }
        try {
            Web3j web3j = getWeb3jInstance();

            Function function = new Function(
                "getInstitutionalUserFinancialStats",
                Arrays.asList(new Address(providerAddress), new Utf8String(puc)),
                Arrays.asList(
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {},
                    new TypeReference<Uint256>() {}
                )
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                log.warn("Error calling getInstitutionalUserFinancialStats()");
                log.debug("getInstitutionalUserFinancialStats() RPC error (details omitted)");
                return Optional.empty();
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.size() < 7) {
                return Optional.empty();
            }

            InstitutionalUserFinancialStats stats = InstitutionalUserFinancialStats.builder()
                .currentPeriodSpent((BigInteger) decoded.get(0).getValue())
                .totalHistoricalSpent((BigInteger) decoded.get(1).getValue())
                .spendingLimit((BigInteger) decoded.get(2).getValue())
                .remainingAllowance((BigInteger) decoded.get(3).getValue())
                .periodStart((BigInteger) decoded.get(4).getValue())
                .periodEnd((BigInteger) decoded.get(5).getValue())
                .periodDuration((BigInteger) decoded.get(6).getValue())
                .build();
            return Optional.of(stats);
        } catch (Exception e) {
            log.error("Error getting institutional user stats");
            log.debug("Institutional user stats error (context omitted)", e);
            return Optional.empty();
        }
    }

    /**
     * Returns the closed service credit balance tracked by the Diamond contract.
     */
    public BigInteger getServiceCreditBalance(String accountAddress) {
        return getServiceCreditBalance(accountAddress, activeNetwork);
    }

    public BigInteger getServiceCreditBalance(String accountAddress, String networkId) {
        if (accountAddress == null || accountAddress.isBlank()) {
            return BigInteger.ZERO;
        }

        try {
            String resolvedNetwork = resolveNetworkId(networkId);
            Web3j web3j = getWeb3jInstanceForNetwork(resolvedNetwork);
            Function function = new Function(
                "getServiceCreditBalance",
                Collections.singletonList(new Address(accountAddress)),
                Collections.singletonList(new TypeReference<Uint256>() {})
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                log.warn("Error calling getServiceCreditBalance()");
                log.debug("getServiceCreditBalance() RPC error (details omitted)");
                return BigInteger.ZERO;
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                return (BigInteger) decoded.get(0).getValue();
            }

            return BigInteger.ZERO;
        } catch (Exception e) {
            log.error("Error getting service credit balance");
            log.debug("Service credit balance lookup failed (context omitted)", e);
            return BigInteger.ZERO;
        }
    }
    
    /**
     * Gets the ERC20 token balance for an address
     * @param walletAddress The address to check balance for
     * @param tokenAddress The ERC20 token contract address
     * @return Token balance as BigInteger
     */
    private BigInteger getERC20Balance(String walletAddress, String tokenAddress) {
        return getERC20Balance(walletAddress, tokenAddress, activeNetwork);
    }

    private BigInteger getERC20Balance(String walletAddress, String tokenAddress, String networkId) {
        try {
            Web3j web3j = getWeb3jInstanceForNetwork(resolveNetworkId(networkId));
            
            // Call balanceOf(address) function on ERC20 token
            Function function = new Function(
                "balanceOf",
                Collections.singletonList(new Address(walletAddress)),
                Collections.singletonList(new TypeReference<Uint256>() {})
            );
            
            String encodedFunction = FunctionEncoder.encode(function);
            
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, tokenAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();
            
            if (response.hasError()) {
                log.warn("Error calling balanceOf()");
                log.debug("balanceOf() RPC error (details omitted)");
                return BigInteger.ZERO;
            }
            
            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                return (BigInteger) decoded.get(0).getValue();
            }
            
            return BigInteger.ZERO;
        } catch (Exception e) {
            log.error("Error getting ERC20 balance");
            log.debug("ERC20 balance lookup failed (context omitted)", e);
            return BigInteger.ZERO;
        }
    }

    private String decodeRevertReason(String returnData) {
        String clean = Numeric.cleanHexPrefix(returnData);
        if (clean == null || clean.length() < 8) {
            return null;
        }
        // Error(string)
        if (!clean.startsWith("08c379a0") || clean.length() <= 8) {
            return null;
        }
        String payload = "0x" + clean.substring(8);
        Function errorFunction = new Function(
            "Error",
            Collections.emptyList(),
            Collections.singletonList(new TypeReference<Utf8String>() {})
        );
        @SuppressWarnings("rawtypes")
        List<Type> decoded = FunctionReturnDecoder.decode(
            payload,
            errorFunction.getOutputParameters()
        );
        if (decoded.isEmpty()) {
            return null;
        }
        return decoded.get(0).getValue().toString();
    }

    private String sanitizeRpcMessage(String message) {
        if (message == null || message.isBlank()) {
            return "Payout request reverted";
        }
        String sanitized = message.replace("execution reverted:", "").trim();
        return sanitized.isEmpty() ? "Payout request reverted" : sanitized;
    }


    /**
     * Gets the transaction history (simplified)
     */
    public TransactionHistoryResponse getTransactionHistory(String address) {
        return getTransactionHistory(address, activeNetwork);
    }

    public TransactionHistoryResponse getTransactionHistory(String address, String networkId) {
        try {
            String resolvedNetwork = resolveNetworkId(networkId);
            Web3j web3j = getWeb3jInstanceForNetwork(resolvedNetwork);

            // Get the number of sent transactions
            EthGetTransactionCount txCount = web3j.ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).send();

            List<TransactionInfo> transactions = new ArrayList<>();
            // In a real implementation, we would query an indexer like Etherscan API
            // or use contract events for related transactions

            return TransactionHistoryResponse.builder()
                .success(true)
                .address(address)
                .transactionCount(txCount.getTransactionCount().toString())
                .transactions(transactions)
                .network(resolvedNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting transaction history");
            log.debug("Transaction history lookup failed (context omitted)", e);
            return TransactionHistoryResponse.error("Failed to get transaction history: " + e.getMessage());
        }
    }

    public Optional<String> getContractOwnerAddress() {
        try {
            Web3j web3j = getWeb3jInstance();
            Function function = new Function(
                "owner",
                Collections.emptyList(),
                Collections.singletonList(new TypeReference<Address>() {})
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                return Optional.empty();
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return Optional.empty();
            }

            String owner = Objects.toString(decoded.get(0).getValue(), "").trim();
            return owner.isEmpty() ? Optional.empty() : Optional.of(owner);
        } catch (Exception e) {
            log.debug("Failed to resolve contract owner", e);
            return Optional.empty();
        }
    }

    public Optional<String> getDefaultAdminRole() {
        try {
            Web3j web3j = getWeb3jInstance();
            Function function = new Function(
                "DEFAULT_ADMIN_ROLE",
                Collections.emptyList(),
                Collections.singletonList(new TypeReference<Bytes32>() {})
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                return Optional.of(DEFAULT_ADMIN_ROLE_HEX);
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return Optional.of(DEFAULT_ADMIN_ROLE_HEX);
            }

            byte[] roleBytes = ((Bytes32) decoded.get(0)).getValue();
            return Optional.of(Numeric.toHexString(roleBytes));
        } catch (Exception e) {
            log.debug("Failed to resolve DEFAULT_ADMIN_ROLE", e);
            return Optional.of(DEFAULT_ADMIN_ROLE_HEX);
        }
    }

    public boolean isDefaultAdmin(String accountAddress) {
        if (accountAddress == null || accountAddress.isBlank()) {
            return false;
        }
        return hasRole(getDefaultAdminRole().orElse(DEFAULT_ADMIN_ROLE_HEX), accountAddress);
    }

    public boolean isInstitution(String accountAddress) {
        if (accountAddress == null || accountAddress.isBlank()) {
            return false;
        }
        return hasRole(INSTITUTION_ROLE_HEX, accountAddress);
    }

    public boolean hasRole(String roleHex, String accountAddress) {
        if (accountAddress == null || accountAddress.isBlank()) {
            return false;
        }
        try {
            Web3j web3j = getWeb3jInstance();
            byte[] roleBytes = Numeric.hexStringToByteArray(
                roleHex == null || roleHex.isBlank() ? DEFAULT_ADMIN_ROLE_HEX : roleHex
            );
            if (roleBytes.length != 32) {
                roleBytes = Arrays.copyOf(roleBytes, 32);
            }

            Function function = new Function(
                "hasRole",
                Arrays.asList(new Bytes32(roleBytes), new Address(accountAddress)),
                Collections.singletonList(new TypeReference<Bool>() {})
            );

            String encodedFunction = FunctionEncoder.encode(function);
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();

            if (response.hasError()) {
                return false;
            }

            @SuppressWarnings("rawtypes")
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (decoded.isEmpty()) {
                return false;
            }

            return Boolean.TRUE.equals(decoded.get(0).getValue());
        } catch (Exception e) {
            log.debug("Failed to check role {} for {}", roleHex, accountAddress, e);
            return false;
        }
    }

    /**
     * Gets the status of configured contract event listeners
     */
    public EventListenerResponse getEventListenerStatus() {
        return getEventListenerStatus(activeNetwork);
    }

    public EventListenerResponse getEventListenerStatus(String networkId) {
        try {
            String resolvedNetwork = resolveNetworkId(networkId);
            return EventListenerResponse.builder()
                .success(true)
                .contractAddress(contractAddress)
                .network(resolvedNetwork)
                .message("Event listeners are configured automatically on startup from application.properties")
                .build();

        } catch (Exception e) {
            log.error("Error getting event listener status", e);
            return EventListenerResponse.error("Failed to get event listener status: " + e.getMessage());
        }
    }

    /**
     * Lists available networks
     */
    public NetworkResponse getAvailableNetworks() {
        List<NetworkInfo> networks = Arrays.asList(
            new NetworkInfo("mainnet", "Ethereum Mainnet", 
                          String.join(",", networkRpcUrls.getOrDefault("mainnet", List.of(mainnetRpcUrl))), 1),
            new NetworkInfo("sepolia", "Sepolia Testnet", 
                          String.join(",", networkRpcUrls.getOrDefault("sepolia", List.of(sepoliaRpcUrl))), 11155111)
        );

        return NetworkResponse.builder()
            .success(true)
            .networks(networks)
            .activeNetwork(activeNetwork)
            .build();
    }

    /**
     * Switches the active network
     */
    public NetworkResponse switchNetwork(String networkId) {
        if (!networkRpcUrls.containsKey(networkId)) {
            return NetworkResponse.error("Invalid network: " + networkId);
        }

        String oldNetwork = activeNetwork;
        activeNetwork = networkId;
        log.info("Switched network from {} to {}", oldNetwork, networkId);
        
        // Publish event to notify other components
        eventPublisher.publishEvent(new NetworkSwitchEvent(this, oldNetwork, networkId));

        return getAvailableNetworks();
    }

    // Helper methods

    public Web3j getWeb3jInstance() {
        return getWeb3jInstanceWithFallback(activeNetwork);
    }

    public Web3j getWeb3jInstanceForNetwork(String network) {
        return getWeb3jInstanceWithFallback(resolveNetworkId(network));
    }
    
    /**
     * Gets Web3j instance with automatic RPC fallback
     * Tries the current RPC endpoint, and if it fails, tries the next one
     */
    private Web3j getWeb3jInstanceWithFallback(String network) {
        List<String> rpcUrls = networkRpcUrls.getOrDefault(network, List.of(sepoliaRpcUrl));
        int startIndex = currentRpcIndex.getOrDefault(network, 0);
        
        // Try all available RPC endpoints starting from current index
        for (int i = 0; i < rpcUrls.size(); i++) {
            int index = (startIndex + i) % rpcUrls.size();
            String rpcUrl = rpcUrls.get(index);
            
            try {
                // Create or get existing Web3j instance for this specific URL
                String cacheKey = network + ":" + index;
                Web3j web3j = web3jInstances.computeIfAbsent(cacheKey, k -> {
                    log.info("Creating Web3j instance for {} using RPC endpoint [{}]: {}", 
                             network, index, rpcUrl);
                    HttpService httpService = new HttpService(rpcUrl, httpClient);
                    return Web3j.build(httpService);
                });
                
                // Test the connection with a simple call (with short timeout)
                try {
                    web3j.ethBlockNumber().send();
                    
                    // Success! Update current index for this network
                    if (index != startIndex) {
                        log.info("Successfully switched to fallback RPC endpoint [{}]: {}", index, rpcUrl);
                        currentRpcIndex.put(network, index);
                    }
                    
                    return web3j;
                } catch (Exception e) {
                    log.warn("RPC endpoint [{}] failed ({}): {} - trying next...", 
                             index, rpcUrl, e.getMessage());
                    
                    // Remove failed instance from cache
                    web3jInstances.remove(cacheKey);
                    
                    // Continue to next RPC endpoint
                }
            } catch (Exception e) {
                log.warn("Error creating Web3j instance for endpoint [{}]: {} - trying next...", 
                         index, e.getMessage());
            }
        }
        
        // All RPC endpoints failed, throw exception
        throw new RuntimeException("All RPC endpoints failed for network: " + network + 
                                   ". Tried: " + String.join(", ", rpcUrls));
    }

    /**
     * Encrypts a private key using AES-256-GCM with PBKDF2 key derivation
     * This provides strong encryption suitable for production use
     * 
     * @param privateKey The private key to encrypt
     * @param password The password used for encryption
     * @return Base64 encoded string containing: salt + iv + encrypted data
     */
    private String encryptPrivateKey(String privateKey, String password) {
        try {
            // Validate private key size to prevent resource exhaustion
            // Ethereum private keys are 64 hex chars, with some margin for format variations
            final int MAX_PRIVATE_KEY_LENGTH = 256;
            if (privateKey == null || privateKey.isEmpty()) {
                throw new IllegalArgumentException("Private key cannot be null or empty");
            }
            if (privateKey.length() > MAX_PRIVATE_KEY_LENGTH) {
                throw new IllegalArgumentException("Private key exceeds maximum allowed length");
            }

            // Generate random salt for this encryption
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);

            // Derive key from password using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_SIZE);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Initialize cipher with AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            // Encrypt the private key
            byte[] encryptedData = cipher.doFinal(privateKey.getBytes(StandardCharsets.UTF_8));

            // Combine salt + iv + encrypted data
            // Use fixed buffer size to avoid user-controlled arithmetic
            // Max: 16 (salt) + 12 (iv) + 256 (key) + 16 (GCM tag) = 300, round to 512
            final int FIXED_BUFFER_SIZE = 512;
            final int MAX_ENCRYPTED_SIZE = FIXED_BUFFER_SIZE - 16 - GCM_IV_LENGTH; // 484 bytes max
            if (encryptedData.length > MAX_ENCRYPTED_SIZE) {
                throw new RuntimeException("Encrypted data exceeds expected size");
            }
            ByteBuffer byteBuffer = ByteBuffer.allocate(FIXED_BUFFER_SIZE);
            byteBuffer.put(salt);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedData);
            // Trim to actual size for output
            byte[] result = new byte[16 + GCM_IV_LENGTH + encryptedData.length];
            byteBuffer.flip();
            byteBuffer.get(result);

            // Return as Base64 encoded string
            return Base64.getEncoder().encodeToString(result);

        } catch (Exception e) {
            log.error("Error encrypting private key", e);
            throw new RuntimeException("Failed to encrypt private key: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a private key that was encrypted with encryptPrivateKey
     * Used by InstitutionalWalletService to decrypt wallet for transaction signing
     * 
     * @param encryptedData Base64 encoded string containing: salt + iv + encrypted data
     * @param password The password used for decryption
     * @return The decrypted private key
     * @throws RuntimeException if decryption fails (wrong password or corrupted data)
     */
    public String decryptPrivateKey(String encryptedData, String password) {
        try {
            // Decode Base64
            byte[] decodedData = Base64.getDecoder().decode(encryptedData);

            // Extract salt, IV, and encrypted data
            ByteBuffer byteBuffer = ByteBuffer.wrap(decodedData);
            byte[] salt = new byte[16];
            byteBuffer.get(salt);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);
            byte[] encryptedBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedBytes);

            // Derive key from password using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, AES_KEY_SIZE);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Initialize cipher for decryption
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            // Decrypt
            byte[] decryptedData = cipher.doFinal(encryptedBytes);
            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("Error decrypting private key", e);
            throw new RuntimeException("Failed to decrypt private key: " + e.getMessage(), e);
        }
    }
}

