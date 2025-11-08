package decentralabs.blockchain.service.wallet;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import decentralabs.blockchain.dto.wallet.*;
import decentralabs.blockchain.service.persistence.WalletPersistenceService;

import java.math.BigDecimal;
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

    @Value("${rpc.url}")
    private String defaultRpcUrl;

    @Value("${contract.address}")
    private String contractAddress;

    @Value("${wallet.address}")
    private String defaultWalletAddress;

    @Value("${base.domain:http://localhost}")
    private String baseDomain;

    // Optional network-specific RPC configurations (with default values)
    @Value("${ethereum.mainnet.rpc.url:https://mainnet.infura.io/v3/YOUR_PROJECT_ID}")
    private String mainnetRpcUrl;

    @Value("${ethereum.sepolia.rpc.url:https://sepolia.infura.io/v3/YOUR_PROJECT_ID}")
    private String sepoliaRpcUrl;

    @Value("${wallet.encryption.salt:DecentraLabsTestSalt}")
    private String encryptionSalt;

    // AES-GCM parameters
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 128 bits
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int AES_KEY_SIZE = 256;

    // Cache of Web3j connections per network
    private final Map<String, Web3j> web3jInstances = new ConcurrentHashMap<>();
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
            
        // Use sepolia by default since rpc.url points to sepolia
        this.activeNetwork = "sepolia";
        log.info("WalletService initialized with active network: {} using RPC: {}", activeNetwork, defaultRpcUrl);
    }

    // Cache of encrypted wallets (use Redis/database in production)
    private final Map<String, String> encryptedWallets = new ConcurrentHashMap<>();

    /**
     * Creates a new Ethereum wallet
     */
    public WalletResponse createWallet(String password) {
        try {
            // Generate random private key
            ECKeyPair keyPair = Keys.createEcKeyPair();
            String privateKey = Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
            String address = Keys.getAddress(keyPair.getPublicKey());

            // Encrypt the private key
            String encryptedPrivateKey = encryptPrivateKey(privateKey, password);

            // Save using persistence service (with fallback to in-memory)
            walletPersistenceService.saveWallet(address, encryptedPrivateKey);

            log.info("Created new wallet: {}", address);

            return WalletResponse.builder()
                .success(true)
                .address(address)
                .encryptedPrivateKey(encryptedPrivateKey)
                .message("Wallet created successfully")
                .build();

        } catch (Exception e) {
            log.error("Error creating wallet", e);
            return WalletResponse.error("Failed to create wallet: " + e.getMessage());
        }
    }

    /**
     * Imports a wallet from private key or mnemonic
     */
    public WalletResponse importWallet(WalletImportRequest request) {
        try {
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

            log.info("Imported wallet: {}", address);

            return WalletResponse.builder()
                .success(true)
                .address(address)
                .encryptedPrivateKey(encryptedPrivateKey)
                .message("Wallet imported successfully")
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

            return BalanceResponse.builder()
                .success(true)
                .address(address)
                .balanceWei(balance.getBalance().toString())
                .balanceEth(ethBalance.toString())
                .network(activeNetwork)
                .build();

        } catch (Exception e) {
            log.error("Error getting balance for address: {}", address, e);
            return BalanceResponse.error("Failed to get balance: " + e.getMessage());
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
            new NetworkInfo("mainnet", "Ethereum Mainnet", mainnetRpcUrl, 1),
            new NetworkInfo("sepolia", "Sepolia Testnet", sepoliaRpcUrl, 11155111)
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

        activeNetwork = networkId;
        log.info("Switched to network: {}", networkId);

        return getAvailableNetworks();
    }

    // Helper methods

    public Web3j getWeb3jInstance() {
        return web3jInstances.computeIfAbsent(activeNetwork, this::createWeb3jInstance);
    }

    private Web3j createWeb3jInstance(String network) {
        String rpcUrl = switch (network) {
            case "mainnet" -> mainnetRpcUrl; // Use specific configuration if available
            case "sepolia" -> sepoliaRpcUrl; // Use specific configuration if available
            default -> defaultRpcUrl;        // Fallback to existing rpc.url
        };

        // Use HttpService with OkHttpClient for connection pooling
        HttpService httpService = new HttpService(rpcUrl, httpClient);
        return Web3j.build(httpService);
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

