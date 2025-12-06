package decentralabs.blockchain.service.wallet;

import decentralabs.blockchain.service.persistence.WalletPersistenceService;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Credentials;

/**
 * Service for managing the institutional wallet used for automated transactions.
 * 
 * This service manages a SINGLE wallet that is used for:
 * - Automatic reservation confirmations/denials (event listeners)
 * - Institutional reservations (treasury operations)
 * - Administrative operations (treasury admin)
 * 
 * The institutional wallet is:
 * - Created once via POST /wallet/create with a password
 * - Stored encrypted in the persistence layer (/app/data/wallets.json)
 * - Loaded on service startup and cached in memory
 * - Decrypted only when needed to sign transactions
 * 
 * Security model:
 * - Private key: AES-256-GCM encrypted in /app/data/wallets.json (never in plain text)
 * - Password: AES-256-GCM encrypted inside wallet-config.properties
 *            (`institutional.wallet.password.encrypted`) using the
 *            `wallet.config.encryption-key` provided via env/secret manager.
 *            INSTITUTIONAL_WALLET_PASSWORD env var still overrides when present.
 * - Credentials: Cached in memory after first decryption (ephemeral)
 * - Access: Protected by localhost-only endpoints and CORS
 * 
 * Setup flow:
 * 1. Create/import wallet via dashboard or POST /wallet/create {"password": "..."}
 * 2. Service encrypts it into persistence and writes wallet-config.properties
 *    (address + encrypted password, requires wallet.config.encryption-key)
 * 3. Institutional wallet auto-loads (env vars can override if provided)
 * 4. Auto-sign: Service decrypts wallet when needed to sign transactions
 * 
 * @see WalletService for wallet creation and encryption
 * @see WalletPersistenceService for encrypted storage
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class InstitutionalWalletService {
    
    private final WalletService walletService;
    private final WalletPersistenceService persistenceService;

    private static final String ADDRESS_PROPERTY = "institutional.wallet.address";
    private static final String ENCRYPTED_PASSWORD_PROPERTY = "institutional.wallet.password.encrypted";
    private static final int CONFIG_GCM_TAG_LENGTH = 128;
    private static final int CONFIG_IV_LENGTH = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    /**
     * Address of the institutional wallet (configured in application.properties)
     * This wallet must be created first using POST /wallet/create
     */
    @Value("${institutional.wallet.address:}")
    private String institutionalWalletAddress;
    
    /**
     * Password to decrypt the institutional wallet's private key
     * SECURITY: Store this in AWS Secrets Manager, Azure Key Vault, or similar
     * Never commit this password to version control
     */
    @Value("${institutional.wallet.password:}")
    private String institutionalWalletPassword;
    
    /**
     * Path to wallet configuration file (address + password)
     * Used as fallback if environment variables are not set
     */
    @Value("${wallet.config.file:./data/wallet-config.properties}")
    private String walletConfigFile;

    @Value("${wallet.config.encryption-key:}")
    private String walletConfigEncryptionKey;

    @Value("${wallet.config.encryption-key-file:/app/data/.wallet-encryption-key}")
    private String walletEncryptionKeyFile;
    
    /**
     * Cached credentials to avoid decrypting on every transaction
     * Only initialized when first needed (lazy loading)
     */
    private volatile Credentials cachedCredentials;
    
    /**
     * Validates that the institutional wallet exists in persistence on startup.
     * Does NOT decrypt the wallet yet (lazy initialization for better startup time).
     * 
     * Loads configuration from:
     * 1. Environment variables (institutional.wallet.address, institutional.wallet.password)
     * 2. Wallet config file (./data/wallet-config.properties) as fallback
     * 3. Persistence service (auto-detect single wallet)
     * 
     * @throws IllegalStateException if wallet address or password not configured
     * @throws IllegalStateException if wallet not found in persistence
     */
    @PostConstruct
    public void initializeInstitutionalWallet() {
        loadEncryptionKeyFromFileIfMissing();

        // Try to load from config file if environment variables not set
        if ((institutionalWalletAddress == null || institutionalWalletAddress.isBlank()) ||
            (institutionalWalletPassword == null || institutionalWalletPassword.isBlank())) {
            
            log.info("Environment variables not set, trying to load from config file: {}", walletConfigFile);
            loadFromConfigFile();
        }
        
        // If still not configured, try to auto-detect from persistence
        if (institutionalWalletAddress == null || institutionalWalletAddress.isBlank()) {
            String detectedAddress = persistenceService.getCurrentWalletAddress();
            if (detectedAddress != null) {
                log.info("Auto-detected wallet from persistence: {}", detectedAddress);
                institutionalWalletAddress = detectedAddress;
            }
        }
        
        // Check if institutional wallet is configured
        if (institutionalWalletAddress == null || institutionalWalletAddress.isBlank()) {
            log.warn("Institutional wallet address not configured. " +
                    "Create a wallet using the dashboard or POST /wallet/create. " +
                    "Automated transaction signing will not be available.");
            return;
        }
        
        if (institutionalWalletPassword == null || institutionalWalletPassword.isBlank()) {
            log.warn("Institutional wallet password not configured. " +
                    "Cannot decrypt wallet. Automated transaction signing will not be available.");
            return;
        }
        
        // Verify wallet exists in persistence (but don't decrypt yet)
        String encryptedKey = persistenceService.getWallet(institutionalWalletAddress);
        
        if (encryptedKey == null) {
            log.warn("Institutional wallet not found at address: {}. " +
                    "Please create it first using POST /wallet/create or the dashboard.", 
                    institutionalWalletAddress);
            return;
        }
        
        log.info("Institutional wallet verified in persistence: {}", institutionalWalletAddress);
        log.info("Institutional wallet ready for automated transaction signing");
    }
    
    /**
     * Loads wallet configuration from file
     */
    private void loadFromConfigFile() {
        try {
            java.nio.file.Path path = java.nio.file.Paths.get(walletConfigFile);
            if (!java.nio.file.Files.exists(path)) {
                log.debug("Wallet config file does not exist: {}", walletConfigFile);
                return;
            }
            
            java.util.Properties props = new java.util.Properties();
            try (java.io.FileInputStream fis = new java.io.FileInputStream(path.toFile())) {
                props.load(fis);
            }
            
            String address = props.getProperty(ADDRESS_PROPERTY);
            String encryptedPassword = props.getProperty(ENCRYPTED_PASSWORD_PROPERTY);
            
            if (address != null && !address.isBlank()) {
                institutionalWalletAddress = address;
                log.info("Loaded wallet address from config file");
            }
            
            if (encryptedPassword != null && !encryptedPassword.isBlank()) {
                if (!hasEncryptionKey()) {
                    log.warn("Encrypted institutional wallet password present but wallet.config.encryption-key is not configured; skipping");
                } else {
                    institutionalWalletPassword = decryptPassword(encryptedPassword.trim());
                    log.info("Loaded wallet password from encrypted config file");
                }
            }
            
        } catch (Exception e) {
            log.error("Failed to load wallet config from file: {}", walletConfigFile, e);
        }
    }
    
    /**
     * Generates a secure encryption key and writes it to the configured key file.
     * This key is used to encrypt the wallet password in wallet-config.properties.
     * 
     * @return the generated encryption key
     */
    private String generateAndSaveEncryptionKey() {
        try {
            // Generate a secure 256-bit key
            byte[] keyBytes = new byte[32];
            SECURE_RANDOM.nextBytes(keyBytes);
            String encryptionKey = Base64.getEncoder().encodeToString(keyBytes);
            
            Path keyPath = Paths.get(walletEncryptionKeyFile);
            if (keyPath.getParent() != null) {
                Files.createDirectories(keyPath.getParent());
            }

            Files.writeString(
                keyPath,
                encryptionKey,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
            );

            try {
                if (!System.getProperty("os.name").toLowerCase().contains("win")) {
                    java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = java.util.Set.of(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE
                    );
                    Files.setPosixFilePermissions(keyPath, perms);
                }
            } catch (UnsupportedOperationException e) {
                // Windows - ignore
            }

            walletConfigEncryptionKey = encryptionKey;
            log.info("Persisted wallet encryption key to {}", walletEncryptionKeyFile);
            return encryptionKey;

        } catch (IOException e) {
            log.error("Failed to persist encryption key to {}: {}", walletEncryptionKeyFile, e.getMessage(), e);
            throw new IllegalStateException("Unable to persist encryption key to file", e);
        }
    }

    private void loadEncryptionKeyFromFileIfMissing() {
        if (hasEncryptionKey()) {
            return;
        }
        try {
            Path keyPath = Paths.get(walletEncryptionKeyFile);
            if (!Files.exists(keyPath)) {
                log.debug("Encryption key file does not exist: {}", walletEncryptionKeyFile);
                return;
            }
            String key = Files.readString(keyPath, StandardCharsets.UTF_8).trim();
            if (key.isBlank()) {
                log.warn("Encryption key file {} is empty; ignoring", walletEncryptionKeyFile);
                return;
            }
            walletConfigEncryptionKey = key;
            log.info("Loaded wallet encryption key from {}", walletEncryptionKeyFile);
        } catch (IOException e) {
            log.error("Failed to read wallet encryption key file {}: {}", walletEncryptionKeyFile, e.getMessage(), e);
        }
    }

    /**
     * Saves wallet configuration to file for persistence across restarts
     * 
     * @param address Wallet address
     * @param password Wallet password
     */
    public void saveConfigToFile(String address, String password) {
        try {
            // Auto-generate encryption key if not configured
            if (!hasEncryptionKey()) {
                log.info("Encryption key not found, generating and saving to .env file");
                generateAndSaveEncryptionKey();
            }

            java.nio.file.Path path = java.nio.file.Paths.get(walletConfigFile);
            
            // Create parent directories if needed
            if (path.getParent() != null) {
                java.nio.file.Files.createDirectories(path.getParent());
            }
            
            java.util.Properties props = new java.util.Properties();
            props.setProperty(ADDRESS_PROPERTY, address);
            props.setProperty(ENCRYPTED_PASSWORD_PROPERTY, encryptPassword(password));
            
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(path.toFile())) {
                props.store(fos, "Institutional Wallet Configuration - Auto-generated");
            }
            
            // Set restrictive permissions (600) on Unix systems
            try {
                if (!System.getProperty("os.name").toLowerCase().contains("win")) {
                    java.util.Set<java.nio.file.attribute.PosixFilePermission> perms = java.util.Set.of(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE
                    );
                    java.nio.file.Files.setPosixFilePermissions(path, perms);
                }
            } catch (UnsupportedOperationException e) {
                // Windows - ignore
            }
            
            log.info("Saved wallet configuration to file: {}", walletConfigFile);
            
        } catch (Exception e) {
            log.error("Failed to save wallet config to file: {}", walletConfigFile, e);
        }
    }
    
    /**
     * Gets the credentials for the institutional wallet, decrypting if necessary.
     * Uses double-checked locking for thread-safe lazy initialization.
     * Credentials are cached after first decryption to avoid repeated decryption overhead.
     * 
     * @return Credentials object that can sign transactions
     * @throws IllegalStateException if wallet not configured or not found
     * @throws RuntimeException if decryption fails (wrong password or corrupted data)
     */
    public Credentials getInstitutionalCredentials() {
        // Fast path: return cached credentials if available
        Credentials local = cachedCredentials;
        if (local != null) {
            return local;
        }
        
        // Slow path: decrypt and cache
        synchronized (this) {
            local = cachedCredentials;
            if (local != null) {
                return local;
            }
            
            // Validate configuration
            if (institutionalWalletAddress == null || institutionalWalletAddress.isBlank()) {
                throw new IllegalStateException(
                    "Institutional wallet address not configured. " +
                    "Set institutional.wallet.address in application.properties."
                );
            }
            if (institutionalWalletPassword == null || institutionalWalletPassword.isBlank()) {
                throw new IllegalStateException(
                    "Institutional wallet password not available. " +
                    "Ensure wallet.config.encryption-key is set and wallet-config.properties contains the encrypted password."
                );
            }
            
            // Load encrypted wallet from persistence
            String encryptedKey = persistenceService.getWallet(institutionalWalletAddress);
            if (encryptedKey == null) {
                throw new IllegalStateException(
                    "Institutional wallet not found in persistence: " + institutionalWalletAddress + ". " +
                    "Create it with POST /wallet/create first."
                );
            }
            
            // Decrypt private key with password (throws RuntimeException if wrong password)
            String privateKey = walletService.decryptPrivateKey(
                encryptedKey, 
                institutionalWalletPassword
            );
            
            // Create credentials from decrypted private key
            local = Credentials.create(privateKey);
            
            // Clear private key from memory immediately (security best practice)
            privateKey = null;
            
            // Verify decrypted address matches configured address
            if (!local.getAddress().equalsIgnoreCase(institutionalWalletAddress)) {
                throw new IllegalStateException(
                    "Decrypted wallet address (" + local.getAddress() + ") " +
                    "does not match configured address (" + institutionalWalletAddress + "). " +
                    "Check your institutional.wallet.address and institutional.wallet.password configuration."
                );
            }
            
            cachedCredentials = local;
            log.info("Institutional wallet credentials initialized and cached for address: {}", 
                     local.getAddress());
            
            return local;
        }
    }

    private boolean hasEncryptionKey() {
        return walletConfigEncryptionKey != null && !walletConfigEncryptionKey.isBlank();
    }

    private String encryptPassword(String password) {
        try {
            // Validate password size to prevent resource exhaustion
            // Reasonable max password length is 256 characters
            final int MAX_PASSWORD_LENGTH = 256;
            if (password == null || password.isEmpty()) {
                throw new IllegalArgumentException("Password cannot be null or empty");
            }
            if (password.length() > MAX_PASSWORD_LENGTH) {
                throw new IllegalArgumentException("Password exceeds maximum allowed length");
            }

            byte[] iv = new byte[CONFIG_IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, buildSecretKey(), new GCMParameterSpec(CONFIG_GCM_TAG_LENGTH, iv));
            byte[] cipherText = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

            // Validate ciphertext size to prevent resource exhaustion
            // With AES-GCM, ciphertext size = plaintext size + 16 bytes (GCM tag)
            // Max expected: 256 (password) + 16 (tag) = 272 bytes
            final int MAX_CIPHERTEXT_SIZE = 512;
            if (cipherText.length > MAX_CIPHERTEXT_SIZE) {
                throw new IllegalStateException("Encrypted data exceeds expected size");
            }
            int totalLength = iv.length + cipherText.length;
            ByteBuffer buffer = ByteBuffer.allocate(totalLength);
            buffer.put(iv);
            buffer.put(cipherText);
            return Base64.getEncoder().encodeToString(buffer.array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to encrypt institutional wallet password", e);
        }
    }

    private String decryptPassword(String encoded) {
        try {
            byte[] payload = Base64.getDecoder().decode(encoded);
            if (payload.length <= CONFIG_IV_LENGTH) {
                throw new IllegalStateException("Encrypted password payload is malformed");
            }
            ByteBuffer buffer = ByteBuffer.wrap(payload);
            byte[] iv = new byte[CONFIG_IV_LENGTH];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, buildSecretKey(), new GCMParameterSpec(CONFIG_GCM_TAG_LENGTH, iv));
            byte[] plaintext = cipher.doFinal(cipherText);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Unable to decrypt institutional wallet password", e);
        }
    }

    private SecretKeySpec buildSecretKey() throws GeneralSecurityException {
        if (!hasEncryptionKey()) {
            throw new GeneralSecurityException("wallet.config.encryption-key is not configured");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(walletConfigEncryptionKey.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, "AES");
    }
    
    /**
     * Clears the cached credentials, forcing re-decryption on next use.
     * Useful if the wallet password is rotated or credentials need to be refreshed.
     * 
     * This is a security-sensitive operation and should only be called when necessary.
     */
    public synchronized void clearCredentialsCache() {
        if (cachedCredentials != null) {
            log.info("Clearing institutional wallet credentials cache for address: {}", 
                     cachedCredentials.getAddress());
            cachedCredentials = null;
        }
    }
    
    /**
     * Checks if the institutional wallet is properly configured and available.
     * 
     * @return true if wallet address and password are configured, false otherwise
     */
    public boolean isConfigured() {
        return institutionalWalletAddress != null && !institutionalWalletAddress.isBlank()
            && institutionalWalletPassword != null && !institutionalWalletPassword.isBlank()
            && persistenceService.getWallet(institutionalWalletAddress) != null;
    }
    
    /**
     * Gets the configured institutional wallet address.
     * 
     * @return wallet address or null if not configured
     */
    public String getInstitutionalWalletAddress() {
        return institutionalWalletAddress;
    }
}
