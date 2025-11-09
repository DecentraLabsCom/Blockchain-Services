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
 * Persistence service for institutional wallet storage
 * 
 * IMPORTANT: This service stores ONLY ONE institutional wallet at a time.
 * Creating or importing a new wallet will REPLACE the existing one.
 * 
 * Storage modes:
 * 
 * MODE 1 - In-Memory (Default, wallet.persistence.enabled=false):
 *   - Fast, no I/O overhead
 *   - Lost on restart
 *   - Good for: development, testing
 * 
 * MODE 2 - File-Based (wallet.persistence.enabled=true, wallet.persistence.file.enabled=true):
 *   - Single wallet stored in JSON file on disk
 *   - Survives restarts
 *   - File protected with 0600 permissions (Linux/Mac)
 *   - Good for: production, single instance
 *   - Configure: wallet.persistence.file.path (default: ./data/wallets.json)
 * 
 * Security notes:
 * - Wallet is already AES-256-GCM encrypted BEFORE storage
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

    // In-memory storage for the single institutional wallet
    // Key: wallet address, Value: encrypted private key
    private final Map<String, String> inMemoryStorage = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        if (persistenceEnabled && filePersistenceEnabled) {
            loadWalletsFromFile();
        }
    }

    /**
     * Stores the institutional wallet (REPLACES any existing wallet)
     * 
     * @param walletAddress The wallet address (used as key)
     * @param encryptedData The encrypted wallet data (already AES-256-GCM encrypted)
     */
    public void saveWallet(String walletAddress, String encryptedData) {
        // Clear any existing wallet (only ONE wallet allowed)
        inMemoryStorage.clear();
        
        // Save the new wallet
        inMemoryStorage.put(walletAddress, encryptedData);
        
        // Additionally persist to file if enabled
        if (persistenceEnabled && filePersistenceEnabled) {
            saveWalletsToFile();
        }
        
        log.info("Institutional wallet stored for address: {} (persistence: {})", 
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
     * Deletes the institutional wallet
     * 
     * @param walletAddress The wallet address
     */
    public void deleteWallet(String walletAddress) {
        inMemoryStorage.remove(walletAddress);
        
        // Persist deletion to file if enabled
        if (persistenceEnabled && filePersistenceEnabled) {
            saveWalletsToFile();
        }
        
        log.info("Institutional wallet deleted for address: {}", walletAddress);
    }

    /**
     * Gets the count of stored wallets (should always be 0 or 1)
     */
    public int getWalletCount() {
        return inMemoryStorage.size();
    }
    
    /**
     * Gets the current institutional wallet address (if any)
     * 
     * @return The wallet address, or null if no wallet is stored
     */
    public String getCurrentWalletAddress() {
        return inMemoryStorage.isEmpty() ? null : inMemoryStorage.keySet().iterator().next();
    }

    /**
     * Loads wallet from JSON file on startup
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
            
            if (loadedWallets.isEmpty()) {
                log.info("No institutional wallet found in file: {}", walletFilePath);
                return;
            }
            
            // Only load the wallet (should be just one)
            inMemoryStorage.putAll(loadedWallets);
            
            if (loadedWallets.size() > 1) {
                log.warn("Multiple wallets found in file (expected 1). Using the first one and clearing others.");
                // Keep only the first wallet
                String firstAddress = loadedWallets.keySet().iterator().next();
                String firstEncrypted = loadedWallets.get(firstAddress);
                inMemoryStorage.clear();
                inMemoryStorage.put(firstAddress, firstEncrypted);
                saveWalletsToFile(); // Persist the cleanup
            }
            
            log.info("Loaded institutional wallet from file: {} (address: {})", 
                walletFilePath, getCurrentWalletAddress());
            
        } catch (IOException e) {
            log.error("Failed to load wallet from file: {}", walletFilePath, e);
            log.warn("Starting with empty wallet storage");
        }
    }

    /**
     * Saves the institutional wallet to JSON file
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
            
            // Write wallet to JSON file (pretty print for readability)
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
            
            log.info("Saved institutional wallet to file: {} (address: {})", 
                walletFilePath, getCurrentWalletAddress());
            
        } catch (IOException e) {
            log.error("Failed to save wallet to file: {}", walletFilePath, e);
        }
    }
}
