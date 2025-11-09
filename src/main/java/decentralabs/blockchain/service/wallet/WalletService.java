package decentralabs.blockchain.service.wallet;

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
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.wallet.*;
import decentralabs.blockchain.service.persistence.WalletPersistenceService;

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

    @Value("${base.domain:http://localhost}")
    private String baseDomain;

    // Network-specific RPC configurations (comma-separated for fallback)
    @Value("${ethereum.mainnet.rpc.url:https://eth.public-rpc.com}")
    private String mainnetRpcUrl;

    @Value("${ethereum.sepolia.rpc.url:https://rpc.sepolia.org}")
    private String sepoliaRpcUrl;
    
    @Value("${blockchain.network.active:sepolia}")
    private String defaultNetwork;

    @Value("${wallet.encryption.salt:DecentraLabsTestSalt}")
    private String encryptionSalt;

    // AES-GCM parameters
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 128 bits
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int AES_KEY_SIZE = 256;

    // Cache of Web3j connections per network (with fallback URLs)
    private final Map<String, Web3j> web3jInstances = new ConcurrentHashMap<>();
    private final Map<String, List<String>> networkRpcUrls = new ConcurrentHashMap<>();
    private final Map<String, Integer> currentRpcIndex = new ConcurrentHashMap<>();
    private String activeNetwork;
    
    // Cache for LAB token address (queried from Diamond contract)
    private volatile String cachedLabTokenAddress = null;
    
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
        this.activeNetwork = defaultNetwork;
        List<String> activeUrls = networkRpcUrls.get(activeNetwork);
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

    // Cache of encrypted wallets (use Redis/database in production)
    private final Map<String, String> encryptedWallets = new ConcurrentHashMap<>();

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

            if (request.getPrivateKey() != null) {
                // Import from private key
                ECKeyPair keyPair = ECKeyPair.create(Numeric.toBigInt(request.getPrivateKey()));
                address = Keys.getAddress(keyPair.getPublicKey());
                encryptedPrivateKey = encryptPrivateKey(request.getPrivateKey(), request.getPassword());
            } else if (request.getMnemonic() != null) {
                // Import from mnemonic (BIP39)
                Credentials credentials = WalletUtils.loadBip39Credentials(
                    request.getPassword(), request.getMnemonic());
                address = credentials.getAddress();
                encryptedPrivateKey = encryptPrivateKey(
                    Numeric.toHexStringWithPrefix(credentials.getEcKeyPair().getPrivateKey()),
                    request.getPassword());
            } else {
                return WalletResponse.error("Either privateKey or mnemonic must be provided");
            }

            // Save to cache
            encryptedWallets.put(address, encryptedPrivateKey);

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
     * Gets the balance of an address
     */
    public BalanceResponse getBalance(String address) {
        try {
            Web3j web3j = getWeb3jInstance();
            EthGetBalance balance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send();

            BigDecimal ethBalance = Convert.fromWei(balance.getBalance().toString(), Convert.Unit.ETHER);

            // Get LAB token balance
            String labTokenAddress = getLabTokenAddress();
            BigInteger labTokenBalance = BigInteger.ZERO;
            if (labTokenAddress != null && !labTokenAddress.equals("0x0000000000000000000000000000000000000000")) {
                labTokenBalance = getERC20Balance(address, labTokenAddress);
            }
            
            // LAB token has 6 decimals
            BigDecimal labBalance = new BigDecimal(labTokenBalance).divide(BigDecimal.valueOf(1_000_000));

            return BalanceResponse.builder()
                .success(true)
                .address(address)
                .balanceWei(balance.getBalance().toString())
                .balanceEth(ethBalance.toString())
                .labTokenAddress(labTokenAddress)
                .labBalanceRaw(labTokenBalance.toString())
                .labBalance(labBalance.toString())
                .network(activeNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting balance for address: {}", address, e);
            return BalanceResponse.error("Failed to get balance: " + e.getMessage());
        }
    }

    /**
     * Gets the LAB token address from the Diamond contract
     * Caches the result to avoid repeated contract calls
     */
    private String getLabTokenAddress() {
        if (cachedLabTokenAddress != null) {
            return cachedLabTokenAddress;
        }
        
        try {
            Web3j web3j = getWeb3jInstance();
            
            // Call getLabTokenAddress() function on Diamond contract
            // function getLabTokenAddress() public view returns (address)
            Function function = new Function(
                "getLabTokenAddress",
                Collections.emptyList(),
                Collections.singletonList(new TypeReference<Address>() {})
            );
            
            String encodedFunction = FunctionEncoder.encode(function);
            
            EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send();
            
            if (response.hasError()) {
                log.warn("Error calling getLabTokenAddress(): {}", response.getError().getMessage());
                return null;
            }
            
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                cachedLabTokenAddress = decoded.get(0).getValue().toString();
                log.info("LAB token address retrieved from Diamond contract: {}", cachedLabTokenAddress);
                return cachedLabTokenAddress;
            }
            
            return null;
        } catch (Exception e) {
            log.error("Error getting LAB token address from Diamond contract", e);
            return null;
        }
    }
    
    /**
     * Gets the ERC20 token balance for an address
     * @param walletAddress The address to check balance for
     * @param tokenAddress The ERC20 token contract address
     * @return Token balance as BigInteger
     */
    private BigInteger getERC20Balance(String walletAddress, String tokenAddress) {
        try {
            Web3j web3j = getWeb3jInstance();
            
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
                log.warn("Error calling balanceOf() on token {}: {}", tokenAddress, response.getError().getMessage());
                return BigInteger.ZERO;
            }
            
            List<Type> decoded = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            if (!decoded.isEmpty()) {
                return (BigInteger) decoded.get(0).getValue();
            }
            
            return BigInteger.ZERO;
        } catch (Exception e) {
            log.error("Error getting ERC20 balance for token {}", tokenAddress, e);
            return BigInteger.ZERO;
        }
    }


    /**
     * Gets the transaction history (simplified)
     */
    public TransactionHistoryResponse getTransactionHistory(String address) {
        try {
            Web3j web3j = getWeb3jInstance();

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
                .network(activeNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting transaction history for address: {}", address, e);
            return TransactionHistoryResponse.error("Failed to get transaction history: " + e.getMessage());
        }
    }

    /**
     * Gets the status of configured contract event listeners
     */
    public EventListenerResponse getEventListenerStatus() {
        try {
            return EventListenerResponse.builder()
                .success(true)
                .contractAddress(contractAddress)
                .network(activeNetwork)
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
        if (!Arrays.asList("mainnet", "sepolia", "goerli").contains(networkId)) {
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
            ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + iv.length + encryptedData.length);
            byteBuffer.put(salt);
            byteBuffer.put(iv);
            byteBuffer.put(encryptedData);

            // Return as Base64 encoded string
            return Base64.getEncoder().encodeToString(byteBuffer.array());

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

