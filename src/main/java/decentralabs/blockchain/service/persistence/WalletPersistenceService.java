package decentralabs.blockchain.service.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Persistence service for wallet storage
 * 
 * Three storage modes:
 * 
 * MODE 1 - In-Memory (Default, wallet.persistence.enabled=false):
 *   - Fast, no I/O overhead
 *   - Lost on restart
 *   - Good for: development, testing, stateless auth
 * 
 * MODE 2 - File-Based (wallet.persistence.enabled=true, wallet.persistence.file.enabled=true):
 *   - Wallets stored in JSON file on disk
 *   - Survives restarts
 *   - File protected with 0600 permissions (Linux/Mac)
 *   - Good for: single instance, simple deployment
 *   - Configure: wallet.persistence.file.path (default: ./data/wallets.json)
 * 
 * MODE 3 - Redis/DB (wallet.persistence.enabled=true, wallet.persistence.file.enabled=false):
 *   - Requires implementing Redis/DB code
 *   - Good for: multiple instances, high availability
 * 
 * Security notes:
 * - Wallets are already AES-256-GCM encrypted BEFORE storage
 * - File contains encrypted data only (double protection)
 * - File permissions set to 0600 (owner read/write only)
 * - Consider encrypting the entire filesystem for extra security
 * - Backup the wallet file regularly
 */
@Service
@Slf4j
public class WalletPersistenceService {

    @Value("${wallet.persistence.enabled:false}")
    private boolean persistenceEnabled;

    @Value("${wallet.persistence.file.enabled:true}")
    private boolean filePersistenceEnabled;

    @Value("${wallet.persistence.file.path:./data/wallets.json}")
    private String walletFilePath;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // In-memory storage (always used for fast access)
    private final Map<String, String> inMemoryStorage = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        if (persistenceEnabled && filePersistenceEnabled) {
            loadWalletsFromFile();
        }
    }

    /**
     * Stores an encrypted wallet
     * 
     * @param walletAddress The wallet address (used as key)
     * @param encryptedData The encrypted wallet data (already AES-256-GCM encrypted)
     */
    public void saveWallet(String walletAddress, String encryptedData) {
        // Always save to in-memory for fast access
        inMemoryStorage.put(walletAddress, encryptedData);
        
        // Additionally persist to file if enabled
        if (persistenceEnabled && filePersistenceEnabled) {
            saveWalletsToFile();
        }
        
        log.debug("Wallet stored for address: {} (persistence: {})", 
            walletAddress, persistenceEnabled && filePersistenceEnabled ? "file" : "memory-only");
    }

    /**
     * Retrieves an encrypted wallet
     * 
     * @param walletAddress The wallet address
     * @return The encrypted wallet data, or null if not found
     */
    public String getWallet(String walletAddress) {
        return inMemoryStorage.get(walletAddress);
    }

    /**
     * Checks if a wallet exists
     * 
     * @param walletAddress The wallet address
     * @return true if wallet exists, false otherwise
     */
    public boolean walletExists(String walletAddress) {
        return inMemoryStorage.containsKey(walletAddress);
    }

    /**
     * Deletes a wallet
     * 
     * @param walletAddress The wallet address
     */
    public void deleteWallet(String walletAddress) {
        inMemoryStorage.remove(walletAddress);
        
        // Persist deletion to file if enabled
        if (persistenceEnabled && filePersistenceEnabled) {
            saveWalletsToFile();
        }
        
        log.debug("Wallet deleted for address: {}", walletAddress);
    }

    /**
     * Gets the count of stored wallets
     */
    public int getWalletCount() {
        return inMemoryStorage.size();
    }

    /**
     * Loads wallets from JSON file on startup
     */
    private void loadWalletsFromFile() {
        try {
            Path path = Paths.get(walletFilePath);
            File file = path.toFile();
            
            if (!file.exists()) {
                log.info("Wallet file does not exist yet: {}", walletFilePath);
                return;
            }
            
            // Read and parse JSON file
            @SuppressWarnings("unchecked")
            Map<String, String> loadedWallets = objectMapper.readValue(file, Map.class);
            
            inMemoryStorage.putAll(loadedWallets);
            
            log.info("Loaded {} wallets from file: {}", loadedWallets.size(), walletFilePath);
            
        } catch (IOException e) {
            log.error("Failed to load wallets from file: {}", walletFilePath, e);
            log.warn("Starting with empty wallet storage");
        }
    }

    /**
     * Saves all wallets to JSON file
     */
    private void saveWalletsToFile() {
        try {
            Path path = Paths.get(walletFilePath);
            
            // Create parent directories if they don't exist
            File parentDir = path.getParent().toFile();
            if (!parentDir.exists()) {
                if (!parentDir.mkdirs()) {
                    log.error("Failed to create directory: {}", parentDir.getAbsolutePath());
                    return;
                }
            }
            
            // Write wallets to JSON file (pretty print for readability)
            objectMapper.writerWithDefaultPrettyPrinter()
                .writeValue(path.toFile(), inMemoryStorage);
            
            // Set file permissions to 0600 (owner read/write only) on Unix systems
            try {
                if (Files.exists(path) && !System.getProperty("os.name").toLowerCase().contains("win")) {
                    Set<PosixFilePermission> perms = Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                    );
                    Files.setPosixFilePermissions(path, perms);
                }
            } catch (UnsupportedOperationException e) {
                // Windows doesn't support POSIX permissions, ignore
                log.debug("POSIX permissions not supported on this system");
            }
            
            log.debug("Saved {} wallets to file: {}", inMemoryStorage.size(), walletFilePath);
            
        } catch (IOException e) {
            log.error("Failed to save wallets to file: {}", walletFilePath, e);
        }
    }
}
